package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	alertInterval  = 15 * time.Second
	alertRetention = 30 * 86400
)

type webhook struct {
	URL    string `json:"url"`
	Format string `json:"format"`
}

type alertSettings struct {
	Webhooks            []webhook `json:"webhooks"`
	ConsecutiveFailures float64   `json:"consecutive_failures"`
	AgentStale          float64   `json:"agent_stale_seconds"`
	OutOfSync           float64   `json:"out_of_sync_seconds"`
	Repeat              float64   `json:"repeat_seconds"`
	Interval            float64   `json:"eval_interval"`
}

func parseAlertSettings(raw json.RawMessage) (alertSettings, error) {
	cfg := alertSettings{ConsecutiveFailures: 3, AgentStale: 120, OutOfSync: 300, Interval: 15}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("invalid alerts settings: %w", err)
	}
	formats := []string{"generic", "slack", "feishu", "dingtalk", "wecom"}
	for _, hook := range cfg.Webhooks {
		target, err := url.Parse(hook.URL)
		if err != nil || target.Hostname() == "" || (target.Scheme != "http" && target.Scheme != "https") {
			return cfg, errors.New("each webhook needs an http(s) url")
		}
		if hook.Format != "" && !slices.Contains(formats, hook.Format) {
			return cfg, fmt.Errorf("webhook format must be one of %s", strings.Join(formats, ", "))
		}
	}
	if cfg.ConsecutiveFailures < 1 {
		return cfg, errors.New("alerts.consecutive_failures must be at least 1")
	}
	if cfg.AgentStale < 0 || cfg.OutOfSync < 0 || cfg.Repeat < 0 || cfg.Interval < 0 {
		return cfg, errors.New("alert thresholds and intervals must be non-negative")
	}
	return cfg, nil
}

type alertView struct {
	ID         int64    `json:"id"`
	Key        string   `json:"key"`
	Rule       string   `json:"rule"`
	Subject    string   `json:"subject"`
	Severity   string   `json:"severity"`
	Summary    string   `json:"summary"`
	State      string   `json:"state"`
	StartedAt  float64  `json:"started_at"`
	FiredAt    *float64 `json:"fired_at"`
	ResolvedAt *float64 `json:"resolved_at"`
	Notify     *string  `json:"notify"`
	NotifiedAt *float64 `json:"notified_at"`
	Error      *string  `db:"notify_error" json:"notify_error"`
}

func listAlerts(ctx context.Context, db database, all bool) ([]alertView, error) {
	return rowsOf[alertView](ctx, db, `SELECT * FROM alerts WHERE $1 OR state = 'firing'
		ORDER BY CASE state WHEN 'firing' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END,
			CASE severity WHEN 'critical' THEN 0 ELSE 1 END, started_at DESC, id DESC LIMIT 200`, all)
}

type alertCondition struct {
	Rule, Subject, Severity, Summary string
	Grace                            float64
}

func failing(p probeSeries, count int) bool {
	if len(p.History) < count {
		return false
	}
	return !slices.Contains(p.History[len(p.History)-count:], true)
}

func withDetail(detail string) string {
	if detail == "" {
		return ""
	}
	return ": " + detail
}

func alertConditions(topo topologyView, cfg alertSettings) map[string]alertCondition {
	out := make(map[string]alertCondition)
	k := int(min(cfg.ConsecutiveFailures, probeHistory+1))
	for _, ip := range topo.IPs {
		if ip.Status == "banned" {
			continue
		}
		for _, p := range ip.Probes {
			if !failing(p, k) {
				continue
			}
			severity, who := "warning", " (unassigned)"
			if len(ip.Users) != 0 {
				severity, who = "critical", " (affected users: "+strings.Join(ip.Users, ", ")+")"
			}
			summary := fmt.Sprintf("Egress IP %s failed to reach %s %d times in a row%s%s. If the target confirmed a ban, run cpctl ban %s.",
				ip.IP, p.Target, k, withDetail(p.Detail), who, ip.IP)
			out["egress_probe_failing/"+ip.IP+"/"+p.Target] = alertCondition{"egress_probe_failing", ip.IP, severity, summary, 0}
		}
	}
	for _, e := range topo.Entries {
		severity, more := "warning", ""
		if !slices.ContainsFunc(e.Probes, func(p probeSeries) bool { return !failing(p, k) }) {
			severity, more = "critical", ". All probe locations failed"
		}
		for _, p := range e.Probes {
			if failing(p, k) {
				summary := fmt.Sprintf("Entry %s (%s:%d) was unreachable from %s %d times in a row%s%s.",
					e.Name, e.Host, e.Port, p.Source, k, withDetail(p.Detail), more)
				out["entry_unreachable/"+e.Name+"/"+p.Source] = alertCondition{"entry_unreachable", e.Name, severity, summary, 0}
			}
		}
	}
	for _, a := range topo.Agents {
		if a.Age > cfg.AgentStale {
			summary := fmt.Sprintf("Egress host %s has missed heartbeats for %d seconds.", a.Name, int(a.Age))
			out["agent_stale/"+a.Name] = alertCondition{"agent_stale", a.Name, "critical", summary, 0}
			continue
		}
		if a.SingboxRunning != nil && !*a.SingboxRunning {
			summary := fmt.Sprintf("sing-box is stopped on egress host %s.", a.Name)
			out["singbox_down/"+a.Name] = alertCondition{"singbox_down", a.Name, "critical", summary, 0}
		}
		if !a.InSync && topo.ServerConfigETags[a.Name] != "" {
			summary := fmt.Sprintf("The configuration on egress host %s is out of sync.", a.Name)
			out["agent_out_of_sync/"+a.Name] = alertCondition{"agent_out_of_sync", a.Name, "warning", summary, cfg.OutOfSync}
		}
	}
	return out
}

func updateAlerts(ctx context.Context, db database, now float64, cfg alertSettings, conditions map[string]alertCondition) ([]alertView, error) {
	active, err := rowsOf[alertView](ctx, db, "SELECT * FROM alerts WHERE state != 'resolved'")
	if err != nil {
		return nil, err
	}
	keyed := make(map[string]alertView, len(active))
	for _, alert := range active {
		if _, ok := conditions[alert.Key]; ok {
			keyed[alert.Key] = alert
			continue
		}
		if alert.State == "pending" {
			_, err = db.Exec(ctx, "DELETE FROM alerts WHERE id = $1", alert.ID)
		} else {
			_, err = db.Exec(ctx, "UPDATE alerts SET state = 'resolved', resolved_at = $2, notify = 'resolved' WHERE id = $1", alert.ID, now)
		}
		if err != nil {
			return nil, err
		}
	}

	keys := make([]string, 0, len(conditions))
	for key := range conditions {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		c := conditions[key]
		a, exists := keyed[key]
		if !exists {
			state := "pending"
			var fired *float64
			var notify *string
			if c.Grace <= 0 {
				state, fired = "firing", &now
				notify = &state
			}
			_, err := db.Exec(ctx, `INSERT INTO alerts(key, rule, subject, severity, summary, state, started_at, fired_at, notify)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, key, c.Rule, c.Subject, c.Severity, c.Summary, state, now, fired, notify)
			if err != nil {
				return nil, err
			}
			continue
		}
		firing := "firing"
		if a.State == "pending" && now-a.StartedAt >= c.Grace {
			a.State, a.FiredAt, a.Notify = firing, &now, &firing
		} else if a.State == "firing" && cfg.Repeat > 0 && a.NotifiedAt != nil && a.Notify == nil && now-*a.NotifiedAt >= cfg.Repeat {
			a.Notify = &firing
		}
		if _, err := db.Exec(ctx, "UPDATE alerts SET severity=$2, summary=$3, state=$4, fired_at=$5, notify=$6 WHERE id=$1",
			a.ID, c.Severity, c.Summary, a.State, a.FiredAt, a.Notify); err != nil {
			return nil, err
		}
	}
	if _, err := db.Exec(ctx, "DELETE FROM alerts WHERE state = 'resolved' AND resolved_at < $1", now-alertRetention); err != nil {
		return nil, err
	}
	return rowsOf[alertView](ctx, db, "SELECT * FROM alerts WHERE notify IS NOT NULL ORDER BY id")
}

func alertPayload(format string, a alertView, status string) object {
	level := "Warning"
	switch {
	case status == "resolved":
		level = "Resolved"
	case a.Severity == "critical":
		level = "Critical"
	}
	text := "[" + level + "] " + a.Summary
	switch format {
	case "slack":
		return object{"text": text}
	case "feishu":
		return object{"msg_type": "text", "content": object{"text": text}}
	case "dingtalk", "wecom":
		return object{"msgtype": "text", "text": object{"content": text}}
	}
	var started *float64
	if a.Rule != "test" {
		started = &a.StartedAt
	}
	return object{"status": status, "rule": a.Rule, "subject": a.Subject, "severity": a.Severity, "summary": a.Summary,
		"text": text, "started_at": started, "fired_at": a.FiredAt, "resolved_at": a.ResolvedAt}
}

var webhookClient = &http.Client{Timeout: 5 * time.Second}

func sendWebhook(ctx context.Context, target string, body object) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(data))
	if err != nil {
		return errors.New("invalid webhook URL")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := webhookClient.Do(req)
	if err != nil {
		var requestError *url.Error
		if errors.As(err, &requestError) {
			return requestError.Err
		}
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func (s *store) runAlerts(ctx context.Context) {
	for ctx.Err() == nil {
		interval, err := s.evaluateAlerts(ctx, sendWebhook)
		if err != nil && ctx.Err() == nil {
			log.Printf("alert evaluation failed: %v", err)
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (s *store) evaluateAlerts(ctx context.Context, send func(context.Context, string, object) error) (time.Duration, error) {
	// One worker updates and delivers the queue for a schema. Committing the queue before delivery keeps retries durable.
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return alertInterval, err
	}
	defer conn.Release()
	var locked bool
	err = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(67143002, hashtext(current_schema()))").Scan(&locked)
	if err != nil || !locked {
		return alertInterval, err
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := conn.Exec(unlockCtx, "SELECT pg_advisory_unlock(67143002, hashtext(current_schema()))"); err != nil {
			conn.Hijack().Close(unlockCtx)
		}
	}()

	var cfg alertSettings
	var queued []alertView
	err = pgx.BeginTxFunc(ctx, conn, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		settings, err := loadSettings(ctx, tx)
		if err != nil {
			return err
		}
		cfg, err = parseAlertSettings(settings.Alerts)
		if err != nil {
			return err
		}
		monitor, err := decodeMonitor(settings)
		if err != nil {
			return err
		}
		topo, err := s.topology(ctx, tx, monitor)
		if err != nil {
			return err
		}
		queued, err = updateAlerts(ctx, tx, topo.Now, cfg, alertConditions(topo, cfg))
		return err
	})
	if err != nil {
		return alertInterval, err
	}
	interval := alertInterval
	if cfg.Interval > 0 && cfg.Interval < float64((1<<63-1)/time.Second) {
		interval = max(time.Millisecond, time.Duration(cfg.Interval*float64(time.Second)))
	}
	for _, alert := range queued {
		if err := ctx.Err(); err != nil {
			return interval, err
		}
		var failures []string
		for i, hook := range cfg.Webhooks {
			if err := send(ctx, hook.URL, alertPayload(hook.Format, alert, *alert.Notify)); err != nil {
				failures = append(failures, fmt.Sprintf("webhook %d: %s", i+1, err))
			}
		}
		if len(failures) != 0 {
			_, err = conn.Exec(ctx, "UPDATE alerts SET notify_error = $2 WHERE id = $1", alert.ID, truncate(strings.Join(failures, "; "), 500))
		} else {
			_, err = conn.Exec(ctx, "UPDATE alerts SET notify = NULL, notified_at = $2, notify_error = NULL WHERE id = $1", alert.ID, s.now())
		}
		if err != nil {
			return interval, err
		}
	}
	return interval, nil
}
