package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// publishFakeRelease writes CP_AGENT_RELEASES/<version>/ as the exit-agent workflow leaves it (linux-amd64 only).
func publishFakeRelease(t *testing.T, dir, version string, sequence int64, signed bool) []byte {
	t.Helper()
	base := filepath.Join(dir, version)
	require(t, os.MkdirAll(base, 0o755))
	bin := []byte("agent binary " + version)
	require(t, os.WriteFile(filepath.Join(base, agentFileName("linux-amd64")), bin, 0o755))
	sum := sha256.Sum256(bin)
	record := fmt.Sprintf(`{"schema":1,"product":"ccproxy-exit-agent","version":%q,"sequence":%d,"binaries":{"linux-amd64":{"file":%q,"sha256":%q,"size":%d}}}`+"\n",
		version, sequence, agentFileName("linux-amd64"), hex.EncodeToString(sum[:]), len(bin))
	require(t, os.WriteFile(filepath.Join(base, "release.json"), []byte(record), 0o644))
	if signed {
		require(t, os.WriteFile(filepath.Join(base, "release.json.sig"), []byte("ed25519:c2lnbmF0dXJl\n"), 0o644))
	}
	return bin
}

type rolloutHarness struct {
	*syncHarness
	tokens map[string]string
	dir    string
}

func newRolloutHarness(t *testing.T) *rolloutHarness {
	s := testStore(t)
	h := &rolloutHarness{syncHarness: &syncHarness{t: t, s: s,
		handler: newAPI(s, testAdminToken, "", []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})},
		tokens: map[string]string{}, dir: t.TempDir()}
	for i, name := range []string{"pilot", "second", "third"} {
		h.tokens[name] = testHost(t, s, name, fmt.Sprintf("192.0.%d", 10+i), 21000+10*i)
	}
	t.Setenv("CP_AGENT_RELEASES", h.dir)
	return h
}

func (h *rolloutHarness) json(rec *httptest.ResponseRecorder, want int) map[string]any {
	h.t.Helper()
	if rec.Code != want {
		h.t.Fatalf("HTTP %d, want %d: %s", rec.Code, want, rec.Body)
	}
	var out map[string]any
	if rec.Body.Len() > 0 {
		require(h.t, json.Unmarshal(rec.Body.Bytes(), &out))
	}
	return out
}

func (h *rolloutHarness) report(host, agentVersion, update string) {
	h.t.Helper()
	body := `{"probes":[],"config_etag":"x","apply_state":"confirmed"`
	if agentVersion != "" {
		body += fmt.Sprintf(`,"agent_version":%q`, agentVersion)
	}
	if update != "" {
		body += `,"update":` + update
	}
	h.json(h.do("POST", "/agent/report", h.tokens[host], body+"}"), 200)
}

func (h *rolloutHarness) hosts() map[string]map[string]any {
	h.t.Helper()
	out := h.json(h.do("GET", "/admin/agent-rollout", testAdminToken, ""), 200)
	byName := map[string]map[string]any{}
	for _, raw := range out["hosts"].([]any) {
		row := raw.(map[string]any)
		byName[row["host"].(string)] = row
	}
	return byName
}

func TestAgentRolloutTargetsPausesAndReports(t *testing.T) {
	h := newRolloutHarness(t)
	bin := publishFakeRelease(t, h.dir, "agent-new", 12, true)
	publishFakeRelease(t, h.dir, "agent-unsigned", 13, false)

	// No rollout: nothing to do, for every host.
	if rec := h.do("GET", "/agent/update", h.tokens["pilot"], ""); rec.Code != 204 {
		t.Fatalf("no rollout: HTTP %d", rec.Code)
	}
	list := h.json(h.do("GET", "/admin/agent-releases", testAdminToken, ""), 200)
	if releases := list["releases"].([]any); len(releases) != 1 || releases[0].(map[string]any)["version"] != "agent-new" {
		t.Fatalf("published releases: %v", list)
	}
	if problems := list["problems"].([]any); len(problems) != 1 || !strings.Contains(fmt.Sprint(problems), "not signed") {
		t.Fatalf("an unsigned directory must be listed as a problem: %v", problems)
	}

	// Refusals: unsigned release, unknown version, unknown host, bad hosts value.
	for body, want := range map[string]int{
		`{"version":"agent-unsigned","hosts":["pilot"]}`: 409,
		`{"version":"agent-missing","hosts":["pilot"]}`:  404,
		`{"version":"../agent-new","hosts":["pilot"]}`:   400,
		`{"version":"agent-new","hosts":["nobody"]}`:     404,
		`{"version":"agent-new","hosts":[]}`:             400,
		`{"version":"agent-new","hosts":"some"}`:         400,
		`{"version":"agent-new"}`:                        400,
	} {
		if rec := h.do("PUT", "/admin/agent-rollout", testAdminToken, body); rec.Code != want {
			t.Errorf("%s: HTTP %d, want %d: %s", body, rec.Code, want, rec.Body)
		}
	}

	// Pilot: only the pilot host is offered the release.
	set := h.json(h.do("PUT", "/admin/agent-rollout", testAdminToken, `{"version":"agent-new","hosts":["pilot"]}`), 200)
	rollout := set["rollout"].(map[string]any)
	firstID := rollout["rollout_id"].(float64)
	if rollout["sequence"] != float64(12) || rollout["paused"] != false {
		t.Fatalf("rollout: %v", rollout)
	}
	offer := h.json(h.do("GET", "/agent/update", h.tokens["pilot"], ""), 200)
	record, _ := os.ReadFile(filepath.Join(h.dir, "agent-new", "release.json"))
	if offer["release"] != string(record) || offer["signature"] != "ed25519:c2lnbmF0dXJl" || offer["rollout_id"] != firstID {
		t.Fatalf("offer must carry release.json byte for byte: %v", offer)
	}
	if rec := h.do("GET", "/agent/update", h.tokens["second"], ""); rec.Code != 204 {
		t.Fatalf("non-targeted host: HTTP %d", rec.Code)
	}
	if rec := h.do("GET", "/agent/update", "", ""); rec.Code != 401 {
		t.Fatalf("no token: HTTP %d", rec.Code)
	}

	// The binary: only with a host token, only while it matches release.json.
	rec := h.do("GET", "/agent/update/agent-new/linux-amd64", h.tokens["pilot"], "")
	if rec.Code != 200 || rec.Body.String() != string(bin) {
		t.Fatalf("binary: HTTP %d", rec.Code)
	}
	if rec := h.do("GET", "/agent/update/agent-new/linux-amd64", "", ""); rec.Code != 401 {
		t.Fatalf("binary without token: HTTP %d", rec.Code)
	}
	if rec := h.do("GET", "/agent/update/agent-new/windows-arm64", h.tokens["pilot"], ""); rec.Code != 404 {
		t.Fatalf("missing platform: HTTP %d", rec.Code)
	}
	require(t, os.WriteFile(filepath.Join(h.dir, "agent-new", agentFileName("linux-amd64")), []byte("replaced on disk"), 0o755))
	if rec := h.do("GET", "/agent/update/agent-new/linux-amd64", h.tokens["pilot"], ""); rec.Code != 503 {
		t.Fatalf("changed binary must not be served: HTTP %d", rec.Code)
	}

	// Heartbeats: an old agent (no fields), the pilot confirming, then updated.
	h.report("second", "", "")
	h.report("third", "agent-old", `{"state":"idle","running_sequence":11}`)
	h.report("pilot", "agent-new", fmt.Sprintf(`{"state":"confirming","target_version":"agent-new","target_sequence":12,"rollout_id":%d,"previous_version":"agent-old"}`, int(firstID)))
	rows := h.hosts()
	if rows["pilot"]["outcome"] != outcomeInProgress || rows["second"]["outcome"] != outcomeNotTargeted || rows["third"]["outcome"] != outcomeNotTargeted {
		t.Fatalf("while the pilot confirms: %v", rows)
	}
	h.report("pilot", "agent-new", fmt.Sprintf(`{"state":"updated","target_version":"agent-new","target_sequence":12,"rollout_id":%d,"running_sequence":12,"previous_version":"agent-old"}`, int(firstID)))
	rows = h.hosts()
	if rows["pilot"]["outcome"] != outcomeOnTarget || rows["pilot"]["agent_version"] != "agent-new" || rows["pilot"]["previous_version"] != "agent-old" {
		t.Fatalf("pilot after update: %v", rows["pilot"])
	}
	if rows["third"]["agent_version"] != "agent-old" {
		t.Fatalf("another host's record changed: %v", rows["third"])
	}

	// Widen to every host, paused: no host is offered anything; the old agent needs the installer.
	set = h.json(h.do("PUT", "/admin/agent-rollout", testAdminToken, `{"version":"agent-new","hosts":"all","paused":true}`), 200)
	secondID := set["rollout"].(map[string]any)["rollout_id"].(float64)
	if secondID <= firstID || set["rollout"].(map[string]any)["hosts"] != nil {
		t.Fatalf("a new PUT must start a new rollout id for every host: %v", set)
	}
	for _, host := range []string{"pilot", "second", "third"} {
		if rec := h.do("GET", "/agent/update", h.tokens[host], ""); rec.Code != 204 {
			t.Fatalf("paused rollout offered to %s: HTTP %d", host, rec.Code)
		}
	}
	rows = h.hosts()
	if rows["second"]["outcome"] != outcomeUpgradeNeeded || rows["third"]["outcome"] != outcomeWaiting || rows["pilot"]["outcome"] != outcomeOnTarget {
		t.Fatalf("paused, all hosts: %v", rows)
	}
	h.json(h.do("POST", "/admin/agent-rollout/resume", testAdminToken, ""), 200)
	if rec := h.do("GET", "/agent/update", h.tokens["third"], ""); rec.Code != 200 {
		t.Fatalf("resumed rollout not offered: HTTP %d", rec.Code)
	}
	paused := h.json(h.do("POST", "/admin/agent-rollout/pause", testAdminToken, ""), 200)
	if paused["rollout"].(map[string]any)["rollout_id"] != secondID {
		t.Fatal("pause must keep the rollout id")
	}
	h.json(h.do("POST", "/admin/agent-rollout/resume", testAdminToken, ""), 200)

	// A host that rolled back shows as failed with the reason.
	h.report("third", "agent-old", fmt.Sprintf(`{"state":"rolled_back","target_version":"agent-new","target_sequence":12,"rollout_id":%d,"error":"not healthy within 10m0s: heartbeat failed","previous_version":"agent-old"}`, int(secondID)))
	rows = h.hosts()
	if rows["third"]["outcome"] != outcomeFailed || !strings.Contains(rows["third"]["error"].(string), "heartbeat failed") {
		t.Fatalf("rolled back: %v", rows["third"])
	}

	// Garbage in the update object never fails a heartbeat.
	h.report("third", "agent-old", `{"state":"exploded","target_version":"../../x","rollout_id":-4}`)
	rows = h.hosts()
	if rows["third"]["state"] != "unknown" || rows["third"]["agent_version"] != "agent-old" || rows["third"]["rollout_id"] != float64(0) {
		t.Fatalf("malformed report: %v", rows["third"])
	}

	// Stop the rollout: nothing is offered and every host keeps its release.
	h.json(h.do("DELETE", "/admin/agent-rollout", testAdminToken, ""), 200)
	if rec := h.do("GET", "/agent/update", h.tokens["pilot"], ""); rec.Code != 204 {
		t.Fatalf("cleared rollout: HTTP %d", rec.Code)
	}
	if rec := h.do("POST", "/admin/agent-rollout/pause", testAdminToken, ""); rec.Code != 404 {
		t.Fatalf("pause without rollout: HTTP %d", rec.Code)
	}
	// Deleting a host removes its status row.
	require(t, h.s.deleteHost(t.Context(), "third"))
	if _, found := h.hosts()["third"]; found {
		t.Fatal("deleted host still listed")
	}
}

func TestAgentRolloutNeedsReleaseDirectory(t *testing.T) {
	h := newRolloutHarness(t)
	t.Setenv("CP_AGENT_RELEASES", "")
	if rec := h.do("GET", "/admin/agent-releases", testAdminToken, ""); rec.Code != 503 {
		t.Fatalf("HTTP %d", rec.Code)
	}
	if rec := h.do("PUT", "/admin/agent-rollout", testAdminToken, `{"version":"agent-new","hosts":"all"}`); rec.Code != 503 {
		t.Fatalf("HTTP %d", rec.Code)
	}
	if rec := h.do("GET", "/admin/agent-rollout", "", ""); rec.Code != 401 {
		t.Fatalf("admin route without a token: HTTP %d", rec.Code)
	}
}
