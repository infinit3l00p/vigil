package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/vigil/edr/internal/alert"
	"github.com/vigil/edr/internal/baseline"
	"github.com/vigil/edr/internal/bpfintegrity"
	"github.com/vigil/edr/internal/clustering"
	"github.com/vigil/edr/internal/config"
	"github.com/vigil/edr/internal/containerguard"
	"github.com/vigil/edr/internal/crossview"
	"github.com/vigil/edr/internal/dashboard"
	"github.com/vigil/edr/internal/detector"
	"github.com/vigil/edr/internal/dnsguard"
	ebpfpkg "github.com/vigil/edr/internal/ebpf"
	"github.com/vigil/edr/internal/fleet"
	"github.com/vigil/edr/internal/flowguard"
	"github.com/vigil/edr/internal/integrity"
	"github.com/vigil/edr/internal/lineage"
	"github.com/vigil/edr/internal/models"
	"github.com/vigil/edr/internal/response"
	"github.com/vigil/edr/internal/syscallarg"
	"github.com/vigil/edr/internal/ttyguard"
)

func main() {
	cfgPath := flag.String("config", "", "Path to vigil.toml config file")
	testAnomaly := flag.Bool("test-anomaly", false, "Inject test anomalies for verification")
	printVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *printVersion {
		fmt.Printf("VIGIL v%s\n", models.VigilVersion)
		return
	}

	logger := setupLogger()
	defer logger.Sync()

	startTime := time.Now()
	logger.Info("=== VIGIL STARTING ===", zap.String("version", models.VigilVersion))

	// Load config
	cfg := config.DefaultConfig()
	if *cfgPath != "" {
		loaded, err := config.LoadFromFile(*cfgPath)
		if err != nil {
			logger.Warn("config: failed to load, using defaults", zap.Error(err))
		} else {
			cfg = config.Merge(cfg, loaded)
			logger.Info("config: loaded", zap.String("path", *cfgPath))
		}
	}

	// Alert manager (v0.8.0: log path from config — was hardcoded)
	alertMgr := alert.New("info", cfg.LogPath)

	// Self-integrity check
	selfCheck, _ := integrity.NewSelfCheck(func(level, category, msg string, args ...interface{}) {
		alertMgr.Critical(category, msg, args...)
	}, 30*time.Minute)

	// ── v0.1: Temporal Anomaly Detection ───────────────────────────
	var ebpfMgr *ebpfpkg.Manager
	if cfg.Modules.TemporalAnomaly {
		var err error
		ebpfMgr, err = ebpfpkg.Load(cfg)
		if err != nil {
			logger.Error("eBPF: temporal anomaly load failed, using stub", zap.Error(err))
			ebpfMgr = ebpfpkg.NewStubManager(cfg)
		} else {
			logger.Info("eBPF: temporal anomaly module loaded")
		}
	} else {
		ebpfMgr = ebpfpkg.NewStubManager(cfg)
	}

	// ── v0.2: Baseline + Detection ────────────────────────────────
	ctx := context.Background()
	base := baseline.New(filepath.Join(cfg.DataDir, "baseline.json"), cfg)
	if cfg.Modules.TemporalAnomaly {
		// Run baseline learning in a goroutine so the dashboard starts immediately
		go func() {
			learnCtx, learnCancel := context.WithTimeout(ctx, cfg.LearnDuration)
			base.Learn(learnCtx, ebpfMgr)
			learnCancel()
			logger.Info("baseline: learned")
		}()
	}

	det := detector.New(ebpfMgr, alertMgr, cfg)

	// ── v0.3: Syscall Argument Filter ──────────────────────────────
	var saf *syscallarg.SyscallArgFilter
	if cfg.Modules.SyscallArgFilter {
		saf = syscallarg.NewSyscallArgFilter(cfg, alertMgr)
		if err := saf.Load(); err != nil {
			logger.Error("syscall-filter: failed to load", zap.Error(err))
			saf = syscallarg.NewStubFilter(cfg, alertMgr)
		} else {
			logger.Info("syscall-filter: loaded")
		}
	}

	// ── v0.4: Cross-View Integrity ─────────────────────────────────
	var cvChecker *crossview.CrossViewChecker
	if cfg.Modules.CrossView {
		cv := crossview.NewCrossViewChecker(cfg, alertMgr)
		if err := cv.Load(); err != nil {
			logger.Error("cross-view: failed to load", zap.Error(err))
		} else {
			cvChecker = cv
			logger.Info("cross-view: loaded")
		}
	}

	// ── v0.5: Process Lineage ──────────────────────────────────────
	var lineageChecker *lineage.LineageChecker
	if cfg.Modules.ProcessLineage {
		objPath := findBPFObject("vigil_lineage.o")
		lc, err := lineage.NewLineageChecker(alertMgr, logger)
		if err != nil {
			logger.Error("lineage: failed to create", zap.Error(err))
		} else if err := lc.Load(objPath); err != nil {
			logger.Error("lineage: failed to load", zap.Error(err))
		} else {
			lineageChecker = lc
			logger.Info("lineage: loaded")
		}
	}

	// ── v0.5a: BPF Self-Integrity Watchdog ──────────────────────────
	var bpfInt *bpfintegrity.BPFIntegrityChecker
	if cfg.Modules.SelfIntegrity {
		objPath := findBPFObject("vigil_integrity.o")
		bi, err := bpfintegrity.NewBPFIntegrityChecker(alertMgr, logger)
		if err != nil {
			logger.Error("bpf-integrity: failed to create", zap.Error(err))
		} else if err := bi.Load(objPath); err != nil {
			logger.Error("bpf-integrity: failed to load", zap.Error(err))
		} else {
			bpfInt = bi
			logger.Info("bpf-integrity: loaded")
		}
	}

	// ── v0.5c: DNS Exfiltration Detection ───────────────────────────
	var dns *dnsguard.DNSGuard
	if cfg.Modules.DNSExfiltration {
		objPath := findBPFObject("vigil_dns.o")
		dg, err := dnsguard.NewDNSGuard(alertMgr, logger)
		if err != nil {
			logger.Error("dns: failed to create", zap.Error(err))
		} else if err := dg.Load(objPath); err != nil {
			logger.Error("dns: failed to load", zap.Error(err))
		} else {
			dns = dg
			logger.Info("dns: loaded")
		}
	}

	// ── v0.5e: TTY Surveillance Detection ────────────────────────────
	var tty *ttyguard.TTYGuard
	if cfg.Modules.TTYSurveillance {
		objPath := findBPFObject("vigil_tty.o")
		tg, err := ttyguard.NewTTYGuard(alertMgr, logger)
		if err != nil {
			logger.Error("tty: failed to create", zap.Error(err))
		} else if err := tg.Load(objPath); err != nil {
			logger.Error("tty: failed to load", zap.Error(err))
		} else {
			tty = tg
			logger.Info("tty: loaded")
		}
	}

	// ── v0.5d: Container Runtime Detection ──────────────────────────
	var contGuard *containerguard.ContainerGuard
	if cfg.Modules.ContainerEscape {
		objPath := findBPFObject("vigil_container.o")
		cg, err := containerguard.NewContainerGuard(alertMgr, logger)
		if err != nil {
			logger.Error("container: failed to create", zap.Error(err))
		} else if err := cg.Load(objPath); err != nil {
			logger.Error("container: failed to load", zap.Error(err))
		} else {
			contGuard = cg
			logger.Info("container: loaded")
		}
	}

	// ── v0.5f: Network Flow Baseline ─────────────────────────────────
	var flow *flowguard.FlowGuard
	if cfg.Modules.NetworkFlow {
		objPath := findBPFObject("vigil_flow.o")
		fg, err := flowguard.NewFlowGuard(alertMgr, logger)
		if err != nil {
			logger.Error("flow: failed to create", zap.Error(err))
		} else if err := fg.Load(objPath); err != nil {
			logger.Error("flow: failed to load", zap.Error(err))
		} else {
			flow = fg
			logger.Info("flow: loaded")
		}
	}

	// ── v0.5b: Behavioral Process Clustering ────────────────────────
	var clusterer *clustering.BehaviorClusterer
	if cfg.Modules.BehavioralClustering {
		clusterer = clustering.NewBehaviorClusterer(alertMgr, logger)
		logger.Info("clustering: initialized")
	}

	// ── v0.7: Response Engine ───────────────────────────────────────────
	responsePolicy := response.DefaultPolicy("/var/lib/vigil/evidence")
	// ENABLED: graduated auto-response (evidence capture, freeze, network isolate).
	// Destructive actions (SIGKILL) require manual approval via dashboard API.
	// Non-destructive responses run automatically on CRITICAL alerts.
	responsePolicy.SetEnabled(false)
	responseEngine := response.NewResponseEngine(responsePolicy, alertMgr, logger)

	// Initialize cgroup freezer and network isolator
	if err := responseEngine.Freezer().Init(); err != nil {
		logger.Warn("response: cgroup freezer init failed", zap.Error(err))
	}
	if err := responseEngine.Isolator().Init(); err != nil {
		logger.Warn("response: network isolator init failed", zap.Error(err))
	}
	logger.Info("response: engine initialized")

	// ── Signal handling ─────────────────────────────────────────────
	sigCtx, sigCancel := context.WithCancel(context.Background())
	defer sigCancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// ── Start all modules ──────────────────────────────────────────
	go det.RunDetection(sigCtx, base)
	if saf != nil {
		go saf.Run(sigCtx)
	}
	if cvChecker != nil {
		go cvChecker.Run(sigCtx)
	}
	if lineageChecker != nil {
		go lineageChecker.Run(sigCtx)
	}
	if bpfInt != nil {
		go bpfInt.Run(sigCtx)
	}
	if dns != nil {
		go dns.Run(sigCtx)
	}
	if tty != nil {
		go tty.Run(sigCtx)
	}
	if contGuard != nil {
		go contGuard.Run(sigCtx)
	}
	if flow != nil {
		go flow.Run(sigCtx)
	}
	if clusterer != nil {
		go clusterer.Run(sigCtx)
	}

	// Wire alert callback → response engine
	alertMgr.SetCallback(func(a alert.Alert) {
		go responseEngine.HandleAlert(a, a.PID)
	})

	// ── v0.6.0: Alert routing (webhook/Slack/Discord/Telegram/JSONL) ──
	var alertRouter *alert.Router
	if cfg.Alert.Routing != (alert.RoutingConfig{}) {
		alertRouter = alert.NewRouter(cfg.Alert.Routing)
		if alertRouter != nil {
			alertMgr.SetCallback(alertRouter.Route)
			logger.Info("alert routing configured",
				zap.String("webhook", boolStr(cfg.Alert.Routing.WebhookURL != "")),
				zap.String("slack", boolStr(cfg.Alert.Routing.SlackURL != "")),
				zap.String("discord", boolStr(cfg.Alert.Routing.DiscordURL != "")),
				zap.String("telegram", boolStr(cfg.Alert.Routing.TelegramToken != "")),
				zap.String("jsonl", cfg.Alert.Routing.JSONLPath),
				zap.String("email", boolStr(cfg.Alert.Routing.SMTPServer != "")),
			)
			defer alertRouter.Close()
		}
	}

	// ── v0.8.0: Fleet mode ─────────────────────────────────────────────
	// Collector role: accept reports from other VIGIL agents.
	var fleetCollector *fleet.Collector
	if cfg.Fleet.CollectorEnabled {
		fleetCollector = fleet.NewCollector(cfg.Fleet, logger)
		logger.Info("fleet: collector enabled",
			zap.Int("max_agents", cfg.Fleet.MaxAgents),
			zap.String("token", boolStr(cfg.Fleet.Token != "")))
	}

	// Agent role: report status + alerts to a central collector.
	if cfg.Fleet.CollectorURL != "" {
		agentID := fleet.LoadOrCreateAgentID(cfg.DataDir)
		fleetStatusFn := func() fleet.AgentStatus {
			counts := alertMgr.AlertCount()
			levels := make(map[string]int, len(counts))
			for lvl, n := range counts {
				levels[lvl.String()] = n
			}
			status := fleet.AgentStatus{
				AlertCounts: levels,
				UptimeSec:   int64(time.Since(startTime).Seconds()),
			}
			if base != nil {
				status.BaselineReady = base.IsReady()
			}
			if ebpfMgr != nil {
				status.EBPFEnabled = ebpfMgr.IsEnabled()
				status.FunctionsMonitored = len(ebpfMgr.Functions())
			}
			type enabler interface{ IsEnabled() bool }
			active := 0
			for _, m := range []enabler{cvChecker, bpfInt, dns, tty, contGuard, flow} {
				if m != nil && m.IsEnabled() {
					active++
				}
			}
			if lineageChecker != nil && lineageChecker.IsEnabled() {
				active++
			}
			if clusterer != nil {
				active++
			}
			status.ActiveModules = active
			return status
		}
		reporter := fleet.NewReporter(cfg.Fleet, agentID, models.VigilVersion, fleetStatusFn, logger)
		alertMgr.SetCallback(reporter.HandleAlert)
		go reporter.Start(sigCtx)
		interval := 30
		if cfg.Fleet.IntervalSec > 0 {
			interval = cfg.Fleet.IntervalSec
		}
		logger.Info("fleet: reporter started",
			zap.String("collector", cfg.Fleet.CollectorURL),
			zap.String("agent_id", agentID),
			zap.Int("interval_sec", interval))
	}

	go responseEngine.Start(sigCtx)

	// Self-integrity periodic check
	go func() {
		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-sigCtx.Done():
				return
			case <-ticker.C:
				result := selfCheck.RunCheck()
				if !result.Passed {
					alertMgr.Critical(string(models.CatSelfIntegrity), "Self-integrity check FAILED: %v", result)
				}
			}
		}
	}()

	if *testAnomaly {
		logger.Info("test-anomaly: mode enabled")
	}

	// ── Dashboard ──────────────────────────────────────────────────
	dash := dashboard.NewDashboard(dashboard.DashboardConfig{
		Addr:              cfg.DashboardAddr,
		AuthToken:         cfg.AuthToken,
		DetectionInterval: cfg.DetectionInterval,
		TLSCertFile:       cfg.TLSCertFile, // v0.7
		TLSKeyFile:        cfg.TLSKeyFile,  // v0.7
		FleetToken:        cfg.Fleet.Token, // v0.8.0
	}, alertMgr, logger)

	dash.SetIntegrity(selfCheck)
	dash.SetEbpfManager(ebpfMgr)
	dash.SetBaseline(base)
	if cvChecker != nil {
		dash.SetCrossViewChecker(cvChecker)
	}
	if saf != nil {
		dash.SetSyscallFilter(saf)
	}
	dash.SetLineageChecker(lineageChecker)
	dash.SetBPFIntegrity(bpfInt)
	dash.SetDNSGuard(dns)
	dash.SetTTYGuard(tty)
	dash.SetContainerGuard(contGuard)
	dash.SetFlowGuard(flow)
	dash.SetClusterer(clusterer)
	dash.SetResponseEngine(responseEngine)
	dash.SetFleetCollector(fleetCollector) // v0.8.0 — nil when collector disabled

	if err := dash.Start(sigCtx); err != nil {
		logger.Error("dashboard: failed to start", zap.Error(err))
	}

	activeModules := 0
	type enabled interface{ IsEnabled() bool }
	for _, m := range []enabled{ebpfMgr, cvChecker, bpfInt, dns, tty, contGuard, flow} {
		if m != nil && m.IsEnabled() {
			activeModules++
		}
	}
	if lineageChecker != nil && lineageChecker.IsEnabled() {
		activeModules++
	}
	if clusterer != nil {
		activeModules++
	}
	logger.Info("=== VIGIL READY ===",
		zap.String("version", models.VigilVersion),
		zap.Int("active_modules", activeModules),
		zap.String("dashboard", cfg.DashboardAddr),
	)

	select {
	case sig := <-sigCh:
		logger.Info("signal received, shutting down", zap.String("signal", sig.String()))
	case <-sigCtx.Done():
	}

	sigCancel()
	dash.Stop()

	// Cleanup
	if ebpfMgr != nil {
		ebpfMgr.Close()
	}
	if cvChecker != nil {
		cvChecker.Close()
	}
	if saf != nil {
		saf.Close()
	}
	if lineageChecker != nil {
		lineageChecker.Close()
	}
	if bpfInt != nil {
		bpfInt.Close()
	}
	if dns != nil {
		dns.Close()
	}
	if tty != nil {
		tty.Close()
	}
	if contGuard != nil {
		contGuard.Close()
	}
	if flow != nil {
		flow.Close()
	}
	if clusterer != nil {
		clusterer.Close()
	}
	if responseEngine != nil {
		responseEngine.Isolator().Cleanup()
	}
	alertMgr.Close()
	logger.Info("=== VIGIL SHUTDOWN ===")
}

func setupLogger() *zap.Logger {
	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()),
		zapcore.AddSync(os.Stderr),
		zapcore.InfoLevel,
	)
	return zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
}

func findBPFObject(name string) string {
	searchPaths := []string{
		filepath.Join(projDir(), "build", "bpf", name),
		"/usr/local/lib/vigil/" + name,
	}
	for _, p := range searchPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return searchPaths[len(searchPaths)-1]
}

func projDir() string {
	if dir := os.Getenv("VIGIL_DIR"); dir != "" {
		return dir
	}
	wd, _ := os.Getwd()
	if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
		return wd
	}
	return "."
}

func boolStr(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
