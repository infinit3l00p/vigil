// Package dashboard implements the VIGIL web dashboard and REST API.
package dashboard

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/vigil/edr/internal/alert"
	"github.com/vigil/edr/internal/baseline"
	"github.com/vigil/edr/internal/bpfintegrity"
	"github.com/vigil/edr/internal/response"
	"github.com/vigil/edr/internal/clustering"
	"github.com/vigil/edr/internal/containerguard"
	"github.com/vigil/edr/internal/crossview"
	"github.com/vigil/edr/internal/dnsguard"
	"github.com/vigil/edr/internal/ebpf"
	"github.com/vigil/edr/internal/flowguard"
	"github.com/vigil/edr/internal/integrity"
	"github.com/vigil/edr/internal/lineage"
	"github.com/vigil/edr/internal/syscallarg"
	"github.com/vigil/edr/internal/ttyguard"
)

// Embed the static dashboard HTML
//go:embed static/*
var staticFS embed.FS

// EbpfStatus provides eBPF status for the dashboard.
type EbpfStatus interface {
	IsEnabled() bool
}

// Dashboard serves the VIGIL web dashboard.
type Dashboard struct {
	mu         sync.Mutex
	addr       string
	authToken  string
	alert      *alert.AlertManager
	logger     *zap.Logger
	server     *http.Server
	integrity  *integrity.SelfCheck

	// Module references for API endpoints
	ebpfMgr      *ebpf.Manager
	baseline     *baseline.Baseline
	crossView    *crossview.CrossViewChecker
	syscallFilter *syscallarg.SyscallArgFilter
	lineage      *lineage.LineageChecker
	bpfIntegrity *bpfintegrity.BPFIntegrityChecker
	dnsGuard     *dnsguard.DNSGuard
	ttyGuard     *ttyguard.TTYGuard
	containerGuard *containerguard.ContainerGuard
	flowGuard    *flowguard.FlowGuard
	clusterer    *clustering.BehaviorClusterer
	response      *response.ResponseEngine

	detectionInterval time.Duration

	// Rate limiter: per-IP request tracking
	rateMu     sync.Mutex
	rateLimits map[string]time.Time // IP → last request time (1-minute window)
	rateCount  map[string]int       // IP → request count in current window

	// SSE connection limiter
	sseMu        sync.Mutex
	sseConns     int // current active SSE connections
	sseMaxConns  int // maximum concurrent SSE connections
}

type DashboardConfig struct {
	Addr              string
	DetectionInterval time.Duration
	AuthToken         string // Bearer token for API auth; if empty, bind to localhost only
}

func NewDashboard(cfg DashboardConfig, alertMgr *alert.AlertManager, logger *zap.Logger) *Dashboard {
	if cfg.Addr == "" {
		cfg.Addr = ":8443"
	}
	// If no auth token is set, bind to localhost only for security
	if cfg.AuthToken == "" {
		// Force localhost binding if no auth token configured
		if cfg.Addr == ":8443" || cfg.Addr == "0.0.0.0:8443" || cfg.Addr == ":80" || cfg.Addr == "0.0.0.0:80" {
			cfg.Addr = "127.0.0.1:8443"
		}
	}
	return &Dashboard{
		addr:              cfg.Addr,
		authToken:         cfg.AuthToken,
		alert:             alertMgr,
		logger:            logger,
		detectionInterval: cfg.DetectionInterval,
		rateLimits:        make(map[string]time.Time),
		rateCount:         make(map[string]int),
		sseMaxConns:       10,
	}
}

// Set* methods for wiring modules into the dashboard
func (d *Dashboard) SetEbpfManager(m *ebpf.Manager)            { d.ebpfMgr = m }
func (d *Dashboard) SetBaseline(b *baseline.Baseline)             { d.baseline = b }
func (d *Dashboard) SetCrossViewChecker(cv *crossview.CrossViewChecker) { d.crossView = cv }
func (d *Dashboard) SetSyscallFilter(sf *syscallarg.SyscallArgFilter)    { d.syscallFilter = sf }
func (d *Dashboard) SetLineageChecker(lc *lineage.LineageChecker)      { d.lineage = lc }
func (d *Dashboard) SetBPFIntegrity(bi *bpfintegrity.BPFIntegrityChecker) { d.bpfIntegrity = bi }
func (d *Dashboard) SetDNSGuard(dg *dnsguard.DNSGuard)         { d.dnsGuard = dg }
func (d *Dashboard) SetTTYGuard(tg *ttyguard.TTYGuard)         { d.ttyGuard = tg }
func (d *Dashboard) SetContainerGuard(cg *containerguard.ContainerGuard) { d.containerGuard = cg }
func (d *Dashboard) SetFlowGuard(fg *flowguard.FlowGuard)      { d.flowGuard = fg }
func (d *Dashboard) SetClusterer(c *clustering.BehaviorClusterer)     { d.clusterer = c }
func (d *Dashboard) SetResponseEngine(r *response.ResponseEngine)   { d.response = r }
func (d *Dashboard) SetIntegrity(ic *integrity.SelfCheck)     { d.integrity = ic }

func (d *Dashboard) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// Static files — only use embedded FS if index.html exists
	staticContent, err := fs.Sub(staticFS, "static")
	if err != nil {
		mux.HandleFunc("/", d.handleIndex)
	} else if _, err := fs.Stat(staticContent, "index.html"); err != nil {
		// No index.html in embedded FS, use inline dashboard
		mux.HandleFunc("/", d.handleIndex)
	} else {
		mux.Handle("/", http.FileServer(http.FS(staticContent)))
	}

	// API endpoints
	mux.HandleFunc("/api/status", d.handleStatus)
	mux.HandleFunc("/metrics", d.handleMetrics) // v0.6.0: Prometheus
	mux.HandleFunc("/api/rules", d.handleRules)  // v0.6.0: rules list/toggle API
	mux.HandleFunc("/api/baseline", d.handleBaseline)
	mux.HandleFunc("/api/alerts", d.handleAlerts)
	mux.HandleFunc("/api/integrity", d.handleIntegrity)
	mux.HandleFunc("/api/functions", d.handleFunctions)
	mux.HandleFunc("/api/events", d.handleEvents) // SSE
	mux.HandleFunc("/api/cross-view", d.handleCrossView)
	mux.HandleFunc("/api/syscall-filter", d.handleSyscallFilter)
	mux.HandleFunc("/api/lineage", d.handleLineage)
	mux.HandleFunc("/api/bpf-integrity", d.handleBPFIntegrity)
	mux.HandleFunc("/api/dns", d.handleDNS)
	mux.HandleFunc("/api/tty", d.handleTTY)
	mux.HandleFunc("/api/container", d.handleContainer)
	mux.HandleFunc("/api/flow", d.handleFlow)
	mux.HandleFunc("/api/clustering", d.handleClustering)
	mux.HandleFunc("/api/response", d.handleResponse)
	mux.HandleFunc("/api/response/approve", d.handleResponseApprove)
	mux.HandleFunc("/api/response/reject", d.handleResponseReject)

	// Wrap with auth middleware (rate limiting removed — local-only dashboard on 127.0.0.1)
	handler := d.authMiddleware(mux)

	d.server = &http.Server{
		Addr:    d.addr,
		Handler: handler,
	}

	go func() {
		d.logger.Info("dashboard: starting", zap.String("addr", d.addr))
		if err := d.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			d.logger.Error("dashboard: server error", zap.Error(err))
		}
	}()

	return nil
}

func (d *Dashboard) Stop() {
	if d.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		d.server.Shutdown(ctx)
	}
}

// ── API Handlers ─────────────────────────────────────────────────────

// authMiddleware enforces bearer token auth on /api/ routes when AuthToken is set.
// If AuthToken is empty, the dashboard is bound to localhost only (enforced in NewDashboard).
func (d *Dashboard) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only protect /api/ routes (except SSE which uses its own auth via query param or header)
		if strings.HasPrefix(r.URL.Path, "/api/") && d.authToken != "" {
			authHeader := r.Header.Get("Authorization")
			expected := "Bearer " + d.authToken
			if authHeader != expected {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimitMiddleware enforces a per-IP rate limit of 120 requests/minute.
func (d *Dashboard) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)

		d.rateMu.Lock()
		now := time.Now()

		// Reset window if last request from this IP was > 1 minute ago
		if last, ok := d.rateLimits[ip]; ok {
			if now.Sub(last) >= time.Minute {
				d.rateCount[ip] = 0
			}
		}

		d.rateCount[ip]++
		d.rateLimits[ip] = now

		// Cleanup stale entries periodically (every ~100 requests)
		if len(d.rateLimits) > 1000 {
			for ip2, last := range d.rateLimits {
				if now.Sub(last) >= time.Minute {
					delete(d.rateLimits, ip2)
					delete(d.rateCount, ip2)
				}
			}
		}

		count := d.rateCount[ip]
		d.rateMu.Unlock()

		if count > 120 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{"error": "rate limit exceeded"})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// getClientIP extracts the client IP from the request, handling X-Forwarded-For.
func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the list
		if idx := strings.Index(xff, ","); idx > 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	// Strip port from RemoteAddr
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx > 0 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}

func (d *Dashboard) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>VIGIL v0.5</title>
<style>body{background:#0a0a0f;color:#e0e0e0;font-family:monospace;margin:0;padding:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px}
.card{background:#1a1a2e;border:1px solid #333;border-radius:8px;padding:16px}
.card h3{margin:0 0 8px;color:#00d4ff}.ok{color:#0f0}.err{color:#f00}.warn{color:#ff0}
.critical{color:#ff4444;font-weight:bold}.status{display:flex;gap:8px;align-items:center}
.dot{width:10px;height:10px;border-radius:50%%}.dot-ok{background:#0f0}.dot-err{background:#f00}
</style></head><body><h1>🔥 VIGIL v0.5 EDR Dashboard</h1>
<div class="grid">
<div class="card"><h3>System Status</h3><div id="status">Loading...</div></div>
<div class="card"><h3>Detection Modules</h3><div id="modules">Loading...</div></div>
<div class="card"><h3>Process Lineage</h3><div id="lineage">Loading...</div></div>
<div class="card"><h3>Network Flows</h3><div id="flow">Loading...</div></div>
<div class="card"><h3>DNS Monitor</h3><div id="dns">Loading...</div></div>
<div class="card"><h3>TTY Surveillance</h3><div id="tty">Loading...</div></div>
<div class="card"><h3>Container Guard</h3><div id="container">Loading...</div></div>
<div class="card"><h3>BPF Integrity</h3><div id="bpf">Loading...</div></div>
<div class="card"><h3>Behavioral Clustering</h3><div id="cluster">Loading...</div></div>
<div class="card" style="grid-column:1/-1"><h3>Response Engine</h3><div id="response">Loading...</div></div>
<div class="card" style="grid-column:1/-1"><div style="display:flex;justify-content:space-between;align-items:center"><h3 style="margin:0">Recent Alerts</h3><button onclick="saveAlerts()" style="background:#1a1a2e;color:#00d4ff;border:1px solid #00d4ff;border-radius:4px;padding:4px 12px;cursor:pointer;font-family:monospace;font-size:12px">💾 Save</button></div><div id="alerts" style="max-height:300px;overflow-y:auto;margin-top:8px">Loading...</div></div>
</div>
<script>
function load(){fetch('/api/status').then(r=>r.json()).then(d=>{let modHtml='<div class="status"><div class="dot '+(d.ebpf_enabled?'dot-ok':'dot-err')+'"></div>Temporal eBPF: '+(d.ebpf_enabled?'Active':'Off')+'</div>';
if(d.lineage_enabled)modHtml+='<div class="status"><div class="dot dot-ok"></div>Lineage</div>';
if(d.bpf_integrity_enabled)modHtml+='<div class="status"><div class="dot dot-ok"></div>BPF Integrity</div>';
if(d.dns_guard_enabled)modHtml+='<div class="status"><div class="dot dot-ok"></div>DNS Guard</div>';
if(d.tty_guard_enabled)modHtml+='<div class="status"><div class="dot dot-ok"></div>TTY Guard</div>';
if(d.container_guard_enabled)modHtml+='<div class="status"><div class="dot dot-ok"></div>Container Guard</div>';
if(d.flow_guard_enabled)modHtml+='<div class="status"><div class="dot dot-ok"></div>Flow Guard</div>';
if(d.clustering_enabled)modHtml+='<div class="status"><div class="dot dot-ok"></div>Clustering</div>';
if(d.response_enabled)modHtml+='<div class="status"><div class="dot dot-ok"></div>Response Engine</div>';
modHtml+='<div>Probes: '+d.total_probes+' | Modules: '+d.total_modules+'</div>';
document.getElementById('modules').innerHTML=modHtml;
document.getElementById('status').innerHTML=
'<div class="status"><div class="dot '+(d.ebpf_enabled?'dot-ok':'dot-err')+'"></div>eBPF: '+(d.ebpf_enabled?'Active':'Off')+'</div>'+
'<div class="status"><div class="dot '+(d.baseline_ready?'dot-ok':'dot-err')+'"></div>Baseline: '+(d.baseline_ready?'Ready':'Learning')+'</div>'+
'<div class="status"><div class="dot '+(d.self_check_ok?'dot-ok':'dot-err')+'"></div>Integrity: '+(d.self_check_ok?'OK':'FAIL')+'</div>'+
'<div>Probes: '+d.functions_monitored+' | Detections: '+d.detection_interval+'</div>'
}).catch(()=>{});fetch('/api/alerts').then(r=>r.json()).then(d=>{let h='';(d.alerts||[]).slice(-10).forEach(a=>{let cls=(a.severity||'').toLowerCase();if(cls==='critical')cls='critical';h+='<div class="'+cls+'">'+a.time+' '+a.category+': '+String(a.message).slice(0,100)+'</div>'});document.getElementById('alerts').innerHTML=h||'No alerts'}).catch(()=>{});
fetch('/api/clustering').then(r=>r.json()).then(d=>{document.getElementById('cluster').innerHTML='Profiles: '+d.profiles_tracked+' | Critical: '+d.critical_procs+' | Rules: '+d.rule_matches}).catch(()=>{});
fetch('/api/response').then(r=>r.json()).then(d=>{let h='';if(!d.enabled){h='Disabled'}else{h='<div class="status"><div class="dot '+(d.total_responses>0?'dot-ok':'dot-warn')+'"></div>Responses: '+d.total_responses+' | Pending: '+d.pending_actions+'</div>';if(d.frozen_pids&&d.frozen_pids.length)h+='<div>Frozen PIDs: '+d.frozen_pids.join(', ')+'</div>';if(d.isolated_pids&&d.isolated_pids.length)h+='<div>Isolated PIDs: '+d.isolated_pids.join(', ')+'</div>';if(d.recent&&d.recent.length){d.recent.slice(-5).forEach(r=>{h+='<div class="'+(r.status==='FAILED'?'critical':'')+'">'+r.action+' → '+r.status+' (pid '+r.pid+', '+r.attack_type+')</div>'})}}document.getElementById('response').innerHTML=h||'No responses'}).catch(()=>{});
fetch('/api/lineage').then(r=>r.json()).then(d=>{document.getElementById('lineage').innerHTML='Processes: '+d.process_count+' | Alive: '+d.alive_count+' | Cred changes: '+d.cred_changes+' | SUID: '+d.suid_execs}).catch(()=>{});
fetch('/api/dns').then(r=>r.json()).then(d=>{document.getElementById('dns').innerHTML='Queries: '+d.total_queries+' | Responses: '+d.total_responses+' | Suspicious: '+d.suspicious_rate}).catch(()=>{});
fetch('/api/flow').then(r=>r.json()).then(d=>{document.getElementById('flow').innerHTML='Connects: '+d.connect_events+' | Accepts: '+d.accept_events+' | Unusual ports: '+d.unusual_ports}).catch(()=>{});
fetch('/api/tty').then(r=>r.json()).then(d=>{document.getElementById('tty').innerHTML='Reads: '+d.tty_read_events+' | Suspicious: '+d.suspicious_reads}).catch(()=>{});
fetch('/api/container').then(r=>r.json()).then(d=>{document.getElementById('container').innerHTML='SetNS: '+d.setns_events+' | Unshare: '+d.unshare_events+' | Escapes: '+d.ns_escapes}).catch(()=>{});
fetch('/api/bpf-integrity').then(r=>r.json()).then(d=>{document.getElementById('bpf').innerHTML='BPF Checks: '+d.bpf_check_events+' | Procs Exits: '+d.process_exits}).catch(()=>{});}
load();setInterval(load,5000);
function saveAlerts(){fetch('/api/alerts').then(r=>r.json()).then(d=>{let txt='VIGIL Alert Log — '+new Date().toISOString()+'\n\n';(d.alerts||[]).forEach(a=>{txt+='['+a.time+'] '+a.severity+' '+a.category+': '+a.message+'\n'});if(!(d.alerts||[]).length)txt+='No alerts.';let b=document.createElement('a');b.href=URL.createObjectURL(new Blob([txt],{type:'text/plain'}));b.download='vigil-alerts-'+Date.now()+'.txt';b.click()}).catch(()=>alert('Failed to fetch alerts'))}
</script></body></html>`)
}

func (d *Dashboard) handleStatus(w http.ResponseWriter, r *http.Request) {
	stats := d.getDashboardStats()
	writeJSON(w, stats)
}

type DashboardStats struct {
	EBPFEnabled        bool   `json:"ebpf_enabled"`
	BaselineReady      bool   `json:"baseline_ready"`
	SelfCheckOK        bool   `json:"self_check_ok"`
	SelfCheckDetails   []string `json:"self_check_details,omitempty"`
	FunctionsMonitored int    `json:"functions_monitored"`
	DetectionInterval  string `json:"detection_interval"`

	// v0.5 module statuses
	LineageEnabled    bool `json:"lineage_enabled"`
	BPFIntegrityEnabled bool `json:"bpf_integrity_enabled"`
	DNSGuardEnabled   bool `json:"dns_guard_enabled"`
	TTYGuardEnabled   bool `json:"tty_guard_enabled"`
	ContainerGuardEnabled bool `json:"container_guard_enabled"`
	FlowGuardEnabled  bool `json:"flow_guard_enabled"`
	ClusteringEnabled bool `json:"clustering_enabled"`
	ResponseEnabled   bool `json:"response_enabled"`

	// Aggregate counts
	TotalProbes  int `json:"total_probes"`
	TotalModules int `json:"total_modules"`
}

func (d *Dashboard) getDashboardStats() DashboardStats {
	stats := DashboardStats{
		DetectionInterval: d.detectionInterval.String(),
	}

	// eBPF temporal module
	if d.ebpfMgr != nil {
		stats.EBPFEnabled = d.ebpfMgr.IsEnabled()
		stats.FunctionsMonitored = len(d.ebpfMgr.Functions())
	}

	// Baseline
	if d.baseline != nil {
		stats.BaselineReady = d.baseline.IsReady()
	}

	// Self-integrity
	if d.integrity != nil {
		result := d.integrity.RunCheck()
		stats.SelfCheckOK = result.Passed
		stats.SelfCheckDetails = result.Details
	}

	// v0.5 modules
	stats.LineageEnabled = d.lineage != nil && d.lineage.IsEnabled()
	stats.BPFIntegrityEnabled = d.bpfIntegrity != nil && d.bpfIntegrity.IsEnabled()
	stats.DNSGuardEnabled = d.dnsGuard != nil && d.dnsGuard.IsEnabled()
	stats.TTYGuardEnabled = d.ttyGuard != nil && d.ttyGuard.IsEnabled()
	stats.ContainerGuardEnabled = d.containerGuard != nil && d.containerGuard.IsEnabled()
	stats.FlowGuardEnabled = d.flowGuard != nil && d.flowGuard.IsEnabled()
	stats.ClusteringEnabled = d.clusterer != nil
	stats.ResponseEnabled = d.response != nil && d.response.IsEnabled()

	// Count total active modules
	activeModules := 0
	totalProbes := stats.FunctionsMonitored
	for _, enabled := range []bool{
		stats.EBPFEnabled, stats.LineageEnabled, stats.BPFIntegrityEnabled,
		stats.DNSGuardEnabled, stats.TTYGuardEnabled,
		stats.ContainerGuardEnabled, stats.FlowGuardEnabled,
	} {
		if enabled {
			activeModules++
		}
	}
	stats.TotalModules = activeModules
	stats.TotalProbes = totalProbes

	return stats
}

func (d *Dashboard) handleBaseline(w http.ResponseWriter, r *http.Request) {
	if d.ebpfMgr == nil {
		writeJSON(w, map[string]string{"error": "eBPF not loaded"})
		return
	}
	functions := d.ebpfMgr.Functions()
	writeJSON(w, functions)
}

func (d *Dashboard) handleAlerts(w http.ResponseWriter, r *http.Request) {
	alerts := d.alert.GetAlerts(alert.WARN)
	writeJSON(w, map[string]interface{}{"alerts": alerts})
}

func (d *Dashboard) handleIntegrity(w http.ResponseWriter, r *http.Request) {
	if d.integrity == nil {
		writeJSON(w, map[string]interface{}{"ok": false, "details": "not initialized"})
		return
	}
	result := d.integrity.RunCheck()
	writeJSON(w, result)
}

func (d *Dashboard) handleFunctions(w http.ResponseWriter, r *http.Request) {
	if d.ebpfMgr == nil {
		writeJSON(w, []string{})
		return
	}
	functions := d.ebpfMgr.Functions()
	names := make([]string, 0, len(functions))
	for _, f := range functions {
		names = append(names, fmt.Sprintf("%s (mean=%d p95=%d)", f.Name, f.ID, f.ID))
	}
	writeJSON(w, names)
}

func (d *Dashboard) handleEvents(w http.ResponseWriter, r *http.Request) {
	// Limit concurrent SSE connections to prevent resource exhaustion
	d.sseMu.Lock()
	if d.sseConns >= d.sseMaxConns {
		d.sseMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "maximum SSE connections reached"})
		return
	}
	d.sseConns++
	d.sseMu.Unlock()

	// Decrement on exit
	defer func() {
		d.sseMu.Lock()
		d.sseConns--
		d.sseMu.Unlock()
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			stats := d.getDashboardStats()
			data, _ := json.Marshal(stats)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (d *Dashboard) handleCrossView(w http.ResponseWriter, r *http.Request) {
	if d.crossView == nil {
		writeJSON(w, map[string]interface{}{"error": "not loaded"})
		return
	}
	stats := d.crossView.GetStats()
	writeJSON(w, stats)
}

func (d *Dashboard) handleSyscallFilter(w http.ResponseWriter, r *http.Request) {
	if d.syscallFilter == nil {
		writeJSON(w, map[string]interface{}{"error": "not loaded"})
		return
	}
	writeJSON(w, map[string]interface{}{
		"enabled":      true,
		"stats":        d.syscallFilter.GetStats(),
		"rules_count":  len(d.syscallFilter.GetRules()),
	})
}

func (d *Dashboard) handleLineage(w http.ResponseWriter, r *http.Request) {
	if d.lineage == nil {
		writeJSON(w, map[string]interface{}{"error": "not loaded"})
		return
	}
	stats := d.lineage.Stats()
	writeJSON(w, map[string]interface{}{
		"enabled":         d.lineage.IsEnabled(),
		"process_count":   stats.ProcessCount,
		"alive_count":     stats.AliveCount,
		"cred_changes":    stats.CredChanges,
		"ptrace_events":   stats.PtraceEvents,
		"namespace_events": stats.NamespaceEvents,
		"suid_execs":      stats.SUIDExecs,
		"rule_matches":    stats.RuleMatches,
		"suspicious_procs": stats.SuspiciousProcs,
	})
}

func (d *Dashboard) handleBPFIntegrity(w http.ResponseWriter, r *http.Request) {
	if d.bpfIntegrity == nil {
		writeJSON(w, map[string]interface{}{"error": "not loaded"})
		return
	}
	stats := d.bpfIntegrity.Stats()
	writeJSON(w, map[string]interface{}{
		"enabled":          d.bpfIntegrity.IsEnabled(),
		"bpf_programs":     stats.BPFPrograms,
		"bpf_check_events": stats.BPFCheckEvents,
		"process_exits":    stats.ProcessExits,
		"unexpected_load":  stats.UnexpectedLoad,
		"missing_progs":   stats.MissingProgs,
	})
}

func (d *Dashboard) handleDNS(w http.ResponseWriter, r *http.Request) {
	if d.dnsGuard == nil {
		writeJSON(w, map[string]interface{}{"error": "not loaded"})
		return
	}
	stats := d.dnsGuard.Stats()
	writeJSON(w, map[string]interface{}{
		"enabled":          d.dnsGuard.IsEnabled(),
		"total_queries":    stats.TotalQueries,
		"total_responses":  stats.TotalResponses,
		"query_bytes":      stats.QueryBytes,
		"response_bytes":   stats.ResponseBytes,
		"suspicious_rate":  stats.SuspiciousRate,
		"large_responses":  stats.LargeResponses,
		"events_processed": stats.EventsProcessed,
	})
}

func (d *Dashboard) handleTTY(w http.ResponseWriter, r *http.Request) {
	if d.ttyGuard == nil {
		writeJSON(w, map[string]interface{}{"error": "not loaded"})
		return
	}
	stats := d.ttyGuard.Stats()
	writeJSON(w, map[string]interface{}{
		"enabled":           d.ttyGuard.IsEnabled(),
		"tty_read_events":   stats.TTYReadEvents,
		"tty_write_events":  stats.TTYWriteEvents,
		"pty_write_events":  stats.PTYWriteEvents,
		"suspicious_reads":  stats.SuspiciousReads,
		"events_processed":  stats.EventsProcessed,
	})
}

func (d *Dashboard) handleContainer(w http.ResponseWriter, r *http.Request) {
	if d.containerGuard == nil {
		writeJSON(w, map[string]interface{}{"error": "not loaded"})
		return
	}
	stats := d.containerGuard.Stats()
	writeJSON(w, map[string]interface{}{
		"enabled":           d.containerGuard.IsEnabled(),
		"setns_events":      stats.SetNSEvents,
		"unshare_events":    stats.UnshareEvents,
		"ns_escapes":        stats.NSEscapes,
		"priv_esc_attempts": stats.PrivEscAttempts,
		"events_processed":  stats.EventsProcessed,
	})
}

func (d *Dashboard) handleFlow(w http.ResponseWriter, r *http.Request) {
	if d.flowGuard == nil {
		writeJSON(w, map[string]interface{}{"error": "not loaded"})
		return
	}
	stats := d.flowGuard.Stats()
	writeJSON(w, map[string]interface{}{
		"enabled":          d.flowGuard.IsEnabled(),
		"connect_events":   stats.ConnectEvents,
		"accept_events":    stats.AcceptEvents,
		"unique_dests":     stats.UniqueDests,
		"high_rate_procs":  stats.HighRateProcs,
		"unusual_ports":    stats.UnusualPorts,
		"events_processed": stats.EventsProcessed,
	})
}

func (d *Dashboard) handleClustering(w http.ResponseWriter, r *http.Request) {
	if d.clusterer == nil {
		writeJSON(w, map[string]interface{}{"error": "not loaded"})
		return
	}
	stats := d.clusterer.Stats()
	topRisks := d.clusterer.TopRisks(10)

	type profileJSON struct {
		PID       uint32 `json:"pid"`
		Comm      string `json:"comm"`
		RiskScore int    `json:"risk_score"`
		Category  string `json:"category"`
		Summary   string `json:"summary"`
	}

	var top []profileJSON
	for _, p := range topRisks {
		top = append(top, profileJSON{
			PID:       p.PID,
			Comm:      p.Comm,
			RiskScore: p.RiskScore,
			Category:  p.RiskCategory,
			Summary:   p.String(),
		})
	}

	writeJSON(w, map[string]interface{}{
		"enabled":         true,
		"profiles_tracked": stats.ProfilesTracked,
		"critical_procs":  stats.CriticalProcs,
		"suspicious_procs": stats.SuspiciousProcs,
		"rule_matches":    stats.RuleMatches,
		"alerts_fired":    stats.AlertsFired,
		"top_risks":       top,
	})
}

// ── Response Engine API ─────────────────────────────────────────────

func (d *Dashboard) handleResponse(w http.ResponseWriter, r *http.Request) {
	if d.response == nil {
		writeJSON(w, map[string]interface{}{"enabled": false})
		return
	}
	stats := d.response.Stats()
	recent := d.response.RecentResults(20)
	writeJSON(w, map[string]interface{}{
		"enabled":          stats.Enabled,
		"total_responses":  stats.TotalResponses,
		"pending_actions":  stats.PendingActions,
		"action_breakdown":  stats.ActionBreakdown,
		"status_breakdown":  stats.StatusBreakdown,
		"recent":          recent,
		"frozen_pids":      d.response.Freezer().FrozenPIDs(),
		"isolated_pids":     d.response.Isolator().IsolatedPIDs(),
	})
}

func (d *Dashboard) handleResponseApprove(w http.ResponseWriter, r *http.Request) {
	if d.response == nil {
		writeJSON(w, map[string]interface{}{"error": "response engine not available"})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, map[string]interface{}{"error": "POST required"})
		return
	}
	var req struct{ PID uint32 `json:"pid"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"error": err.Error()})
		return
	}
	approved := d.response.ApproveDestructive(req.PID)
	writeJSON(w, map[string]interface{}{"approved": approved, "pid": req.PID})
}

func (d *Dashboard) handleResponseReject(w http.ResponseWriter, r *http.Request) {
	if d.response == nil {
		writeJSON(w, map[string]interface{}{"error": "response engine not available"})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, map[string]interface{}{"error": "POST required"})
		return
	}
	var req struct{ PID uint32 `json:"pid"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"error": err.Error()})
		return
	}
	rejected := d.response.RejectDestructive(req.PID)
	writeJSON(w, map[string]interface{}{"rejected": rejected, "pid": req.PID})
}

// ── Helpers ──────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		// Client disconnected or similar
		_ = err
	}
}

// AlertJSON converts an alert to JSON format.
type AlertJSON struct {
	Time     string `json:"time"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Message  string `json:"message"`
}

// FormatAlerts converts alert entries to JSON.
func FormatAlerts(alerts []alert.Alert) []AlertJSON {
	result := make([]AlertJSON, 0, len(alerts))
	for _, a := range alerts {
		result = append(result, AlertJSON{
			Time:     a.Timestamp.Format("15:04:05"),
			Severity: a.Level.String(),
			Category: a.Category,
			Message:  a.Message,
		})
	}
	return result
}

// Ensure alert package has the right structure
var _ = strings.Builder{}
// ────────────────────────────────────────────────────────────────────────
// v0.6.0: Prometheus /metrics + Rules API
// ────────────────────────────────────────────────────────────────────────

// handleMetrics serves Prometheus-format metrics at /metrics.
// Every alert counter, detection module status, and process count —
// ingestible by Prometheus/Grafana with zero glue.
func (d *Dashboard) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	var b strings.Builder
	writeMetric := func(name, help, mtype string, value interface{}) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n%s %v\n",
			name, help, name, mtype, name, value)
	}

	// Alert counters by level
	counts := d.alert.AlertCount()
	writeMetric("vigil_alerts_total_critical",
		"Total CRITICAL alerts in the alert buffer", "counter",
		counts[alert.CRITICAL])
	writeMetric("vigil_alerts_total_warn",
		"Total WARN alerts in the alert buffer", "counter", counts[alert.WARN])
	writeMetric("vigil_alerts_total_info",
		"Total INFO alerts in the alert buffer", "counter", counts[alert.INFO])

	// Detection module status (1 = active, 0 = inactive)
	moduleStatus := func(name string, ok bool) {
		v := 0
		if ok {
			v = 1
		}
		writeMetric("vigil_module_"+name, "Detection module active (1) or inactive (0)", "gauge", v)
	}
	if d.ebpfMgr != nil {
		moduleStatus("ebpf", true)
	}
	if d.baseline != nil {
		moduleStatus("baseline", true)
	}
	if d.crossView != nil {
		moduleStatus("cross_view", true)
	}
	if d.syscallFilter != nil {
		moduleStatus("syscall_filter", true)
	}
	if d.lineage != nil {
		moduleStatus("lineage", true)
	}
	if d.bpfIntegrity != nil {
		moduleStatus("bpf_integrity", true)
	}
	if d.dnsGuard != nil {
		moduleStatus("dns_guard", true)
	}
	if d.ttyGuard != nil {
		moduleStatus("tty_guard", true)
	}
	if d.containerGuard != nil {
		moduleStatus("container_guard", true)
	}
	if d.flowGuard != nil {
		moduleStatus("flow_guard", true)
	}

	// Uptime not tracked here yet — reserved for v0.6.1
	_, _ = w.Write([]byte(b.String()))
}

// handleRules serves the syscall-arg rule set with runtime enable/disable.
// GET /api/rules — list all rules (with enabled state)
// POST /api/rules { "id": "...", "enabled": false } — toggle (persists to overrides)
func (d *Dashboard) handleRules(w http.ResponseWriter, r *http.Request) {
	if d.syscallFilter == nil {
		http.Error(w, `{"error": "syscall filter not active"}`, http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		rules := d.syscallFilter.GetRules()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rules)
	case http.MethodPost:
		var req struct {
			ID      string `json:"id"`
			Enabled *bool  `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error": "bad request"}`, http.StatusBadRequest)
			return
		}
		if req.ID == "" || req.Enabled == nil {
			http.Error(w, `{"error": "id and enabled required"}`, http.StatusBadRequest)
			return
		}
		if err := d.syscallFilter.SetRuleEnabled(req.ID, *req.Enabled); err != nil {
			http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": true, "id": req.ID, "enabled": *req.Enabled,
		})
	default:
		http.Error(w, `{"error": "method not allowed"}`, http.StatusMethodNotAllowed)
	}
}
