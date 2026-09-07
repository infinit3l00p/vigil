// © 2026 Dan Vladoiu. All rights reserved.
package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// RoutingConfig configures alert routing destinations.
// Every destination is optional — empty values disable the route.
// Each route has its own minimum level, so you can send e.g. everything
// to a webhook but only CRITICAL to Discord.
//
// v0.6.0: closes the biggest gap vs. platform EDRs (OpenEDR et al) —
// VIGIL stays kernel-native but now routes alerts anywhere.
type RoutingConfig struct {
	WebhookURL        string `toml:"webhook_url" json:"webhook_url"`                 // Generic POST JSON
	WebhookMinLevel  string `toml:"webhook_min_level" json:"webhook_min_level"`     // default: warn
	SlackURL          string `toml:"slack_webhook_url" json:"slack_webhook_url"`    // Slack-compatible incoming webhook
	SlackMinLevel     string `toml:"slack_min_level" json:"slack_min_level"`       // default: critical
	DiscordURL        string `toml:"discord_webhook_url" json:"discord_webhook_url"` // Discord webhook
	DiscordMinLevel   string `toml:"discord_min_level" json:"discord_min_level"`   // default: critical
	TelegramToken     string `toml:"telegram_bot_token" json:"telegram_bot_token"`  // Telegram bot token
	TelegramChatID    string `toml:"telegram_chat_id" json:"telegram_chat_id"`      // Telegram chat ID
	TelegramMinLevel  string `toml:"telegram_min_level" json:"telegram_min_level"` // default: critical
	JSONLPath         string `toml:"jsonl_path" json:"jsonl_path"`                  // Structured event log (eve.json-style)
	SendTimeoutSec    int    `toml:"send_timeout_sec" json:"send_timeout_sec"`      // default: 5
}

// Router fans alerts out to configured destinations.
// Non-blocking: sends happen in goroutines; slow/unreachable destinations
// can never stall detection. Failed sends are logged, never crash the EDR.
type Router struct {
	mu       sync.Mutex
	cfg      RoutingConfig
	client   *http.Client
	jsonlFile *os.File

	// per-route minimum levels (parsed once)
	webhookLevel, slackLevel, discordLevel, telegramLevel Level

	// error throttling: log send failures at most once per minute per route
	lastErrLog map[string]time.Time
}

// NewRouter creates an alert router. Returns nil if no destinations configured.
func NewRouter(cfg RoutingConfig) *Router {
	hasAny := cfg.WebhookURL != "" || cfg.SlackURL != "" || cfg.DiscordURL != "" ||
		(cfg.TelegramToken != "" && cfg.TelegramChatID != "") || cfg.JSONLPath != ""
	if !hasAny {
		return nil
	}

	timeout := cfg.SendTimeoutSec
	if timeout <= 0 {
		timeout = 5
	}

	r := &Router{
		cfg: cfg,
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
		lastErrLog: make(map[string]time.Time),
	}

	// Parse per-route levels (defaults: webhook=warn, chat apps=critical)
	r.webhookLevel = ParseLevel(cfg.WebhookMinLevel)
	if cfg.WebhookMinLevel == "" {
		r.webhookLevel = WARN
	}
	r.slackLevel = ParseLevel(cfg.SlackMinLevel)
	if cfg.SlackMinLevel == "" {
		r.slackLevel = CRITICAL
	}
	r.discordLevel = ParseLevel(cfg.DiscordMinLevel)
	if cfg.DiscordMinLevel == "" {
		r.discordLevel = CRITICAL
	}
	r.telegramLevel = ParseLevel(cfg.TelegramMinLevel)
	if cfg.TelegramMinLevel == "" {
		r.telegramLevel = CRITICAL
	}

	// JSONL structured event log
	if cfg.JSONLPath != "" {
		if err := os.MkdirAll(dirOf(cfg.JSONLPath), 0755); err == nil {
			f, err := os.OpenFile(cfg.JSONLPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
			if err == nil {
				r.jsonlFile = f
			} else {
				log.Printf("[VIGIL] routing: cannot open jsonl %s: %v", cfg.JSONLPath, err)
			}
		}
	}

	return r
}

// Close releases router resources.
func (r *Router) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.jsonlFile != nil {
		r.jsonlFile.Close()
	}
}

// Route dispatches an alert to all configured destinations (non-blocking).
func (r *Router) Route(a Alert) {
	// JSONL: synchronous-ish write (local file, fast) — guarded
	if r.jsonlFile != nil && a.Level >= INFO {
		if data, err := json.Marshal(a); err == nil {
			r.mu.Lock()
			r.jsonlFile.Write(append(data, '\n'))
			r.mu.Unlock()
		}
	}

	if r.cfg.WebhookURL != "" && a.Level >= r.webhookLevel {
		go r.sendWebhook("webhook", r.cfg.WebhookURL, a)
	}
	if r.cfg.SlackURL != "" && a.Level >= r.slackLevel {
		go r.sendSlack(r.cfg.SlackURL, a)
	}
	if r.cfg.DiscordURL != "" && a.Level >= r.discordLevel {
		go r.sendDiscord(r.cfg.DiscordURL, a)
	}
	if r.cfg.TelegramToken != "" && r.cfg.TelegramChatID != "" && a.Level >= r.telegramLevel {
		go r.sendTelegram(r.cfg.TelegramToken, r.cfg.TelegramChatID, a)
	}
}

// ─── senders ────────────────────────────────────────────────────────────

func (r *Router) sendWebhook(route, url string, a Alert) {
	body, _ := json.Marshal(a)
	r.postJSON(route, url, "application/json", body)
}

func (r *Router) sendSlack(url string, a Alert) {
	color := map[Level]string{
		DEBUG: "#777777", INFO: "#36a64f", WARN: "#ffcc00", CRITICAL: "#cc0000",
	}[a.Level]
	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{{
			"color":    color,
			"pretext":  fmt.Sprintf("VIGIL [%s]", a.Level),
			"fields": []map[string]interface{}{
				{"title": a.Category, "value": a.Message, "short": false},
			},
			"footer": fmt.Sprintf("pid=%d @ %s", a.PID, a.Timestamp.Format("15:04:05")),
		}},
	}
	body, _ := json.Marshal(payload)
	r.postJSON("slack", url, "application/json", body)
}

func (r *Router) sendDiscord(url string, a Alert) {
	payload := map[string]interface{}{
		"content": fmt.Sprintf("**[%s]** `%s` — %s", a.Level, a.Category, a.Message),
	}
	body, _ := json.Marshal(payload)
	r.postJSON("discord", url, "application/json", body)
}

func (r *Router) sendTelegram(token, chatID string, a Alert) {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	payload := map[string]interface{}{
		"chat_id": chatID,
		"text": fmt.Sprintf("🛡️ *VIGIL [%s]* `%s`\n%s",
			a.Level, a.Category, a.Message),
		"parse_mode": "Markdown",
	}
	body, _ := json.Marshal(payload)
	r.postJSON("telegram", url, "application/json", body)
}

// postJSON posts a JSON body, with error throttling: a failing destination
// logs at most once per minute so a dead webhook can't flood the console.
func (r *Router) postJSON(route, url, contentType string, body []byte) {
	resp, err := r.client.Post(url, contentType, bytes.NewReader(body))
	if err != nil {
		r.logErrThrottled(route, fmt.Sprintf("send failed: %v", err))
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		r.logErrThrottled(route, fmt.Sprintf("HTTP %d", resp.StatusCode))
	}
}

func (r *Router) logErrThrottled(route, msg string) {
	r.mu.Lock()
	if time.Since(r.lastErrLog[route]) < time.Minute {
		r.mu.Unlock()
		return
	}
	r.lastErrLog[route] = time.Now()
	r.mu.Unlock()
	log.Printf("[VIGIL] routing: %s: %s", route, msg)
}

func dirOf(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i]
	}
	return "."
}