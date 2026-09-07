// © 2026 Dan Vladoiu. All rights reserved.
package fleet

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/vigil/edr/internal/alert"
	"go.uber.org/zap"
)

func testLogger() *zap.Logger { return zap.NewNop() }

// TestCollectorAcceptAndList covers report storage, counters, and listing.
func TestCollectorAcceptAndList(t *testing.T) {
	c := NewCollector(FleetConfig{}, testLogger())
	rep := Report{
		AgentID:  "a1",
		Hostname: "host-a",
		Version:  "0.8.0",
		SentAt:   time.Now(),
		Status:   AgentStatus{BaselineReady: true, EBPFEnabled: true, ActiveModules: 5},
		Alerts: []alert.Alert{
			{Level: alert.CRITICAL, Category: "X", Message: "crit"},
			{Level: alert.WARN, Category: "Y", Message: "warn"},
		},
	}
	if err := c.AcceptReport(rep, "10.0.0.5"); err != nil {
		t.Fatalf("AcceptReport: %v", err)
	}

	agents := c.ListAgents()
	if len(agents) != 1 {
		t.Fatalf("agents = %d, want 1", len(agents))
	}
	a := agents[0]
	if a.AgentID != "a1" || a.Hostname != "host-a" || a.IP != "10.0.0.5" {
		t.Errorf("agent identity wrong: %+v", a)
	}
	if a.TotalAlerts != 2 || a.CriticalAlerts != 1 {
		t.Errorf("counters wrong: total=%d critical=%d", a.TotalAlerts, a.CriticalAlerts)
	}
	if !a.Online || !a.Status.BaselineReady || a.Reports != 1 {
		t.Errorf("status wrong: online=%v baseline=%v reports=%d", a.Online, a.Status.BaselineReady, a.Reports)
	}

	alerts := c.AgentAlerts("a1", 0)
	if len(alerts) != 2 || alerts[0].Message != "crit" {
		t.Errorf("AgentAlerts = %+v", alerts)
	}
	if c.AgentCount() != 1 {
		t.Errorf("AgentCount = %d, want 1", c.AgentCount())
	}
}

// TestCollectorRingBound verifies the per-agent alert ring: oldest dropped,
// total counter keeps the true sum.
func TestCollectorRingBound(t *testing.T) {
	c := NewCollector(FleetConfig{AlertsPerAgent: 3}, testLogger())
	for i := 0; i < 5; i++ {
		rep := Report{AgentID: "a", Alerts: []alert.Alert{{Message: fmt.Sprintf("m%d", i)}}}
		if err := c.AcceptReport(rep, "ip"); err != nil {
			t.Fatalf("AcceptReport %d: %v", i, err)
		}
	}
	alerts := c.AgentAlerts("a", 0)
	if len(alerts) != 3 || alerts[0].Message != "m2" || alerts[2].Message != "m4" {
		t.Errorf("ring bound broken: %+v", alerts)
	}
	agents := c.ListAgents()
	if agents[0].TotalAlerts != 5 {
		t.Errorf("total counter = %d, want 5 (must count evicted too)", agents[0].TotalAlerts)
	}
}

// TestCollectorStalePrune verifies agents older than retention disappear.
func TestCollectorStalePrune(t *testing.T) {
	c := NewCollector(FleetConfig{RetentionMin: 1}, testLogger())
	if err := c.AcceptReport(Report{AgentID: "old"}, "ip"); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.agents["old"].info.LastSeen = time.Now().Add(-2 * time.Minute)
	c.mu.Unlock()
	if got := c.ListAgents(); len(got) != 0 {
		t.Errorf("stale agent not pruned: %+v", got)
	}
}

// TestCollectorMaxAgents verifies the fleet capacity cap.
func TestCollectorMaxAgents(t *testing.T) {
	c := NewCollector(FleetConfig{MaxAgents: 1}, testLogger())
	if err := c.AcceptReport(Report{AgentID: "a1"}, "ip"); err != nil {
		t.Fatal(err)
	}
	if err := c.AcceptReport(Report{AgentID: "a2"}, "ip"); err == nil {
		t.Error("expected fleet-full error for second agent")
	}
	// Existing agent still updates when at capacity
	if err := c.AcceptReport(Report{AgentID: "a1", Hostname: "updated"}, "ip"); err != nil {
		t.Errorf("existing agent rejected at capacity: %v", err)
	}
}

// TestCollectorRejectsEmptyAgentID validates the basic payload contract.
func TestCollectorRejectsEmptyAgentID(t *testing.T) {
	c := NewCollector(FleetConfig{}, testLogger())
	if err := c.AcceptReport(Report{}, "ip"); err == nil {
		t.Error("expected error for empty agent_id")
	}
}

// TestReporterDeliversAlerts exercises the full agent→collector HTTP path:
// gzip encoding, bearer token, payload contents, and pending-buffer cleanup.
func TestReporterDeliversAlerts(t *testing.T) {
	var mu sync.Mutex
	var gotAuth, gotEnc string
	var gotReport Report
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotAuth = r.Header.Get("Authorization")
		gotEnc = r.Header.Get("Content-Encoding")
		var body []byte
		if gotEnc == "gzip" {
			gz, _ := gzip.NewReader(r.Body)
			body, _ = io.ReadAll(gz)
		} else {
			body, _ = io.ReadAll(r.Body)
		}
		_ = json.Unmarshal(body, &gotReport)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := NewReporter(FleetConfig{CollectorURL: srv.URL, Token: "tok"}, "agent-1", "0.8.0",
		func() AgentStatus { return AgentStatus{BaselineReady: true} }, testLogger())
	r.HandleAlert(alert.Alert{Level: alert.WARN, Category: "C", Message: "hello"})
	r.HandleAlert(alert.Alert{Level: alert.CRITICAL, Category: "C", Message: "world"})

	if !r.sendOnce() {
		t.Fatal("sendOnce returned false")
	}

	mu.Lock()
	defer mu.Unlock()
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer tok")
	}
	if gotEnc != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip", gotEnc)
	}
	if gotReport.AgentID != "agent-1" || gotReport.Version != "0.8.0" {
		t.Errorf("report identity wrong: %+v", gotReport)
	}
	if !gotReport.Status.BaselineReady {
		t.Errorf("status snapshot missing")
	}
	if len(gotReport.Alerts) != 2 || gotReport.Alerts[0].Message != "hello" {
		t.Errorf("alerts wrong: %+v", gotReport.Alerts)
	}
	pending, sentOK, _, _ := r.Stats()
	if pending != 0 || sentOK != 1 {
		t.Errorf("after success: pending=%d sentOK=%d, want 0/1", pending, sentOK)
	}
}

// TestReporterRetainsOnFailure verifies failed reports keep their alerts
// buffered for retry.
func TestReporterRetainsOnFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	r := NewReporter(FleetConfig{CollectorURL: srv.URL}, "a", "0.8.0",
		func() AgentStatus { return AgentStatus{} }, testLogger())
	r.HandleAlert(alert.Alert{Message: "keepme"})

	if r.sendOnce() {
		t.Fatal("sendOnce should report failure on HTTP 500")
	}
	pending, _, sendFail, _ := r.Stats()
	if pending != 1 || sendFail != 1 {
		t.Errorf("pending=%d sendFail=%d, want 1/1", pending, sendFail)
	}
}

// TestReporterBatchesAndEvicts verifies the pending-buffer bound.
func TestReporterBatchesAndEvicts(t *testing.T) {
	r := NewReporter(FleetConfig{CollectorURL: "http://127.0.0.1:1"}, "a", "0.8.0",
		func() AgentStatus { return AgentStatus{} }, testLogger())
	for i := 0; i < r.maxPending+50; i++ {
		r.HandleAlert(alert.Alert{Message: fmt.Sprintf("m%d", i)})
	}
	if pending, _, _, _ := r.Stats(); pending > r.maxPending {
		t.Errorf("pending=%d exceeds bound %d", pending, r.maxPending)
	}
}

// TestLoadOrCreateAgentID verifies the agent ID is created once and stable.
func TestLoadOrCreateAgentID(t *testing.T) {
	dir := t.TempDir()
	id1 := LoadOrCreateAgentID(dir)
	id2 := LoadOrCreateAgentID(dir)
	if id1 == "" || id1 != id2 {
		t.Errorf("agent ID not stable: %q vs %q", id1, id2)
	}
	if _, err := os.Stat(dir + "/agent_id"); err != nil {
		t.Errorf("agent_id file not persisted: %v", err)
	}
}

// TestFleetConfigDefaults verifies all defaults apply from zero values.
func TestFleetConfigDefaults(t *testing.T) {
	c := FleetConfig{}
	if c.interval() != 30*time.Second {
		t.Errorf("default interval = %v", c.interval())
	}
	if c.maxAgents() != 100 || c.retention() != 15*time.Minute || c.alertsPerAgent() != 500 {
		t.Errorf("defaults wrong: maxAgents=%d retention=%v alerts=%d", c.maxAgents(), c.retention(), c.alertsPerAgent())
	}
}
