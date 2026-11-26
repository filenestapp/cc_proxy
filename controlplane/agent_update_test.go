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
	bin := publishFakeRelease(t, h.dir, "v0.1.0", 12, true)
	publishFakeRelease(t, h.dir, "agent-unsigned", 13, false)

	// No rollout: nothing to do, for every host.
	if rec := h.do("GET", "/agent/update", h.tokens["pilot"], ""); rec.Code != 204 {
		t.Fatalf("no rollout: HTTP %d", rec.Code)
	}
	list := h.json(h.do("GET", "/admin/agent-releases", testAdminToken, ""), 200)
	if releases := list["releases"].([]any); len(releases) != 1 || releases[0].(map[string]any)["version"] != "v0.1.0" {
		t.Fatalf("published releases: %v", list)
	}
	if problems := list["problems"].([]any); len(problems) != 1 || !strings.Contains(fmt.Sprint(problems), "not signed") {
		t.Fatalf("an unsigned directory must be listed as a problem: %v", problems)
	}

	// Refusals: unsigned release, unknown version, unknown host, bad hosts value.
	for body, want := range map[string]int{
		`{"version":"agent-unsigned","hosts":["pilot"]}`: 409,
		`{"version":"agent-missing","hosts":["pilot"]}`:  404,
		`{"version":"../v0.1.0","hosts":["pilot"]}`:      400,
		`{"version":"v0.1.0","hosts":["nobody"]}`:        404,
		`{"version":"v0.1.0","hosts":[]}`:                400,
		`{"version":"v0.1.0","hosts":"some"}`:            400,
		`{"version":"v0.1.0"}`:                           400,
	} {
		if rec := h.do("PUT", "/admin/agent-rollout", testAdminToken, body); rec.Code != want {
			t.Errorf("%s: HTTP %d, want %d: %s", body, rec.Code, want, rec.Body)
		}
	}

	// Pilot: only the pilot host is offered the release.
	set := h.json(h.do("PUT", "/admin/agent-rollout", testAdminToken, `{"version":"v0.1.0","hosts":["pilot"]}`), 200)
	rollout := set["rollout"].(map[string]any)
	firstID := rollout["rollout_id"].(float64)
	if rollout["sequence"] != float64(12) || rollout["paused"] != false {
		t.Fatalf("rollout: %v", rollout)
	}
	offer := h.json(h.do("GET", "/agent/update", h.tokens["pilot"], ""), 200)
	record, _ := os.ReadFile(filepath.Join(h.dir, "v0.1.0", "release.json"))
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
	rec := h.do("GET", "/agent/update/v0.1.0/linux-amd64", h.tokens["pilot"], "")
	if rec.Code != 200 || rec.Body.String() != string(bin) {
		t.Fatalf("binary: HTTP %d", rec.Code)
	}
	if rec := h.do("GET", "/agent/update/v0.1.0/linux-amd64", "", ""); rec.Code != 401 {
		t.Fatalf("binary without token: HTTP %d", rec.Code)
	}
	if rec := h.do("GET", "/agent/update/v0.1.0/windows-arm64", h.tokens["pilot"], ""); rec.Code != 404 {
		t.Fatalf("missing platform: HTTP %d", rec.Code)
	}
	require(t, os.WriteFile(filepath.Join(h.dir, "v0.1.0", agentFileName("linux-amd64")), []byte("replaced on disk"), 0o755))
	if rec := h.do("GET", "/agent/update/v0.1.0/linux-amd64", h.tokens["pilot"], ""); rec.Code != 503 {
		t.Fatalf("changed binary must not be served: HTTP %d", rec.Code)
	}

	// Heartbeats: an old agent (no fields), the pilot confirming, then updated.
	h.report("second", "", "")
	h.report("third", "agent-0a37adb7da36", `{"state":"idle","running_sequence":11}`)
	h.report("pilot", "v0.1.0", fmt.Sprintf(`{"state":"confirming","target_version":"v0.1.0","target_sequence":12,"rollout_id":%d,"previous_version":"agent-0a37adb7da36"}`, int(firstID)))
	rows := h.hosts()
	if rows["pilot"]["outcome"] != outcomeInProgress || rows["second"]["outcome"] != outcomeNotTargeted || rows["third"]["outcome"] != outcomeNotTargeted {
		t.Fatalf("while the pilot confirms: %v", rows)
	}
	h.report("pilot", "v0.1.0", fmt.Sprintf(`{"state":"updated","target_version":"v0.1.0","target_sequence":12,"rollout_id":%d,"running_sequence":12,"previous_version":"agent-0a37adb7da36"}`, int(firstID)))
	rows = h.hosts()
	if rows["pilot"]["outcome"] != outcomeOnTarget || rows["pilot"]["agent_version"] != "v0.1.0" || rows["pilot"]["previous_version"] != "agent-0a37adb7da36" {
		t.Fatalf("pilot after update: %v", rows["pilot"])
	}
	if rows["third"]["agent_version"] != "agent-0a37adb7da36" {
		t.Fatalf("another host's record changed: %v", rows["third"])
	}

	// Widen to every host, paused: no host is offered anything; the old agent needs the installer.
	set = h.json(h.do("PUT", "/admin/agent-rollout", testAdminToken, `{"version":"v0.1.0","hosts":"all","paused":true}`), 200)
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
	h.report("third", "agent-0a37adb7da36", fmt.Sprintf(`{"state":"rolled_back","target_version":"v0.1.0","target_sequence":12,"rollout_id":%d,"error":"not healthy within 10m0s: heartbeat failed","previous_version":"agent-0a37adb7da36"}`, int(secondID)))
	rows = h.hosts()
	if rows["third"]["outcome"] != outcomeFailed || !strings.Contains(rows["third"]["error"].(string), "heartbeat failed") {
		t.Fatalf("rolled back: %v", rows["third"])
	}

	// Garbage in the update object never fails a heartbeat.
	h.report("third", "agent-0a37adb7da36", `{"state":"exploded","target_version":"../../x","rollout_id":-4}`)
	rows = h.hosts()
	if rows["third"]["state"] != "unknown" || rows["third"]["agent_version"] != "agent-0a37adb7da36" || rows["third"]["rollout_id"] != float64(0) {
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

func TestFailedOrLegacyHeartbeatDoesNotLookUpdated(t *testing.T) {
	h := newRolloutHarness(t)
	publishFakeRelease(t, h.dir, "agent-new", 12, true)
	result := h.json(h.do("PUT", "/admin/agent-rollout", testAdminToken,
		`{"version":"agent-new","hosts":["pilot"]}`), 200)
	rolloutID := int(result["rollout"].(map[string]any)["rollout_id"].(float64))
	h.report("pilot", "agent-new", fmt.Sprintf(`{"state":"failed","target_version":"agent-new","rollout_id":%d}`, rolloutID))
	if got := h.hosts()["pilot"]["outcome"]; got != outcomeFailed {
		t.Fatalf("unhealthy target was treated as updated: %v", got)
	}
	h.report("pilot", "", "")
	if row := h.hosts()["pilot"]; row["outcome"] != outcomeUpgradeNeeded || row["state"] != "" {
		t.Fatalf("legacy heartbeat retained old updater state: %v", row)
	}
}

func TestAgentCanReadItsSignedReleaseBeforeAnyRollout(t *testing.T) {
	h := newRolloutHarness(t)
	publishFakeRelease(t, h.dir, "agent-installed", 11, true)
	publishFakeRelease(t, h.dir, "agent-unsigned", 12, false)

	endpoint := "/agent/release/agent-installed"
	if rec := h.do("GET", endpoint, "", ""); rec.Code != 401 {
		t.Fatalf("release record without a host token: HTTP %d", rec.Code)
	}
	record, err := os.ReadFile(filepath.Join(h.dir, "agent-installed", "release.json"))
	require(t, err)
	offer := h.json(h.do("GET", endpoint, h.tokens["pilot"], ""), 200)
	if offer["release"] != string(record) || offer["signature"] != "ed25519:c2lnbmF0dXJl" {
		t.Fatalf("released record or signature differed from the published files: %v", offer)
	}
	if rec := h.do("GET", "/agent/release/agent-unsigned", h.tokens["pilot"], ""); rec.Code != 409 {
		t.Fatalf("unsigned release record: HTTP %d", rec.Code)
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
