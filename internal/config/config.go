package config

import (
	"github.com/vigil/edr/internal/alert"
	"github.com/vigil/edr/internal/fleet"
	"time"

	"github.com/BurntSushi/toml"
)

// Config holds all VIGIL configuration.
type Config struct {
	Modules           ModulesConfig
	LearnDuration     time.Duration     `toml:"learn_duration"`
	DetectionInterval time.Duration     `toml:"detection_interval"`
	SampleRate        int               `toml:"sample_rate"`
	ConsecutiveHits   int               `toml:"consecutive_hits"`
	MinShiftPercent   float64           `toml:"min_shift_percent"` // Minimum timing shift (%) for CRITICAL alerts
	DashboardAddr     string            `toml:"dashboard_addr"`
	AuthToken         string            `toml:"auth_token"`
	TLSCertFile       string            `toml:"tls_cert_file"` // v0.7: PEM path (empty = HTTP)
	TLSKeyFile        string            `toml:"tls_key_file"`  // v0.7: PEM path (empty = HTTP)
	Alert             AlertConfig       `toml:"alert"`
	DataDir           string            `toml:"data_dir"` // v0.8.0: baselines, agent_id, state
	LogPath           string            `toml:"log_path"` // v0.8.0: alert log file
	Fleet             fleet.FleetConfig `toml:"fleet"`    // v0.8.0: multi-host aggregation
}

// AlertConfig configures the alert manager + routing (v0.6.0).
type AlertConfig struct {
	MaxEntries int                 `toml:"max_entries"` // in-memory alert buffer
	Routing    alert.RoutingConfig `toml:"routing"`     // external destinations
}

// ModulesConfig controls which VIGIL modules are enabled.
type ModulesConfig struct {
	TemporalAnomaly      bool `toml:"temporal_anomaly"`
	SyscallArgFilter     bool `toml:"syscall_arg_filter"`
	CrossView            bool `toml:"cross_view"`
	ProcessLineage       bool `toml:"process_lineage"`
	SelfIntegrity        bool `toml:"self_integrity"`
	BehavioralClustering bool `toml:"behavioral_clustering"`
	DNSExfiltration      bool `toml:"dns_exfiltration"`
	ContainerEscape      bool `toml:"container_escape"`
	TTYSurveillance      bool `toml:"tty_surveillance"`
	NetworkFlow          bool `toml:"network_flow"`
}

// DefaultConfig returns the default VIGIL configuration.
func DefaultConfig() *Config {
	return &Config{
		Modules: ModulesConfig{
			TemporalAnomaly:      true,
			SyscallArgFilter:     true,
			CrossView:            true,
			ProcessLineage:       true,
			SelfIntegrity:        true,
			BehavioralClustering: true,
			DNSExfiltration:      true,
			ContainerEscape:      true,
			TTYSurveillance:      true,
			NetworkFlow:          true,
		},
		LearnDuration:     120 * time.Second, // 2min baseline to capture normal load variation
		DetectionInterval: 5 * time.Second,
		SampleRate:        100,
		ConsecutiveHits:   3,
		MinShiftPercent:   50.0, // Require ≥50% shift for CRITICAL — rootkit hooks add 500μs+, not 2-3μs
		DashboardAddr:     ":8443",
		DataDir:           "/var/lib/vigil",
		LogPath:           "/var/log/vigil/alerts.log",
		Alert: AlertConfig{
			MaxEntries: 1000,
		},
	}
}

// LoadFromFile reads configuration from a TOML file.
func LoadFromFile(path string) (*Config, error) {
	cfg := DefaultConfig()
	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Merge overlays non-zero values from overlay onto base.
func Merge(base, overlay *Config) *Config {
	result := *base
	if overlay.Modules != (ModulesConfig{}) {
		result.Modules = overlay.Modules
	}
	if overlay.LearnDuration != 0 {
		result.LearnDuration = overlay.LearnDuration
	}
	if overlay.DetectionInterval != 0 {
		result.DetectionInterval = overlay.DetectionInterval
	}
	if overlay.SampleRate != 0 {
		result.SampleRate = overlay.SampleRate
	}
	if overlay.ConsecutiveHits != 0 {
		result.ConsecutiveHits = overlay.ConsecutiveHits
	}
	if overlay.DashboardAddr != "" {
		result.DashboardAddr = overlay.DashboardAddr
	}
	if overlay.AuthToken != "" {
		result.AuthToken = overlay.AuthToken
	}
	if overlay.TLSCertFile != "" {
		result.TLSCertFile = overlay.TLSCertFile
	}
	if overlay.TLSKeyFile != "" {
		result.TLSKeyFile = overlay.TLSKeyFile
	}
	if overlay.Alert.MaxEntries != 0 {
		result.Alert.MaxEntries = overlay.Alert.MaxEntries
	}
	// v0.6.0 fix (2026-09-07): routing config was silently dropped by Merge —
	// the router never saw [alert.routing] from the config file.
	if overlay.Alert.Routing != (alert.RoutingConfig{}) {
		result.Alert.Routing = overlay.Alert.Routing
	}
	// v0.8.0: new config sections — same merge-audit rule (f2f0601):
	// every new field needs its Merge branch or it is silently dropped.
	if overlay.DataDir != "" {
		result.DataDir = overlay.DataDir
	}
	if overlay.LogPath != "" {
		result.LogPath = overlay.LogPath
	}
	if overlay.Fleet != (fleet.FleetConfig{}) {
		result.Fleet = overlay.Fleet
	}
	return &result
}
