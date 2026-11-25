package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"
)

type consoleLocale struct {
	Name           string            `json:"name"`
	Messages       map[string]string `json:"messages"`
	ServerMessages map[string]string `json:"serverMessages"`
}

func consoleLocaleData(t *testing.T, page []byte) []byte {
	t.Helper()
	_, rest, found := bytes.Cut(page, []byte(consoleLocaleElement))
	if !found {
		t.Fatal("console has no embedded locale element")
	}
	data, _, found := bytes.Cut(rest, []byte("</script>"))
	if !found {
		t.Fatal("console locale element is incomplete")
	}
	return data
}

func TestConsoleRoutesEmbedChineseLocale(t *testing.T) {
	handler := newAPI(nil, testAdminToken, "", nil)
	for _, path := range []string{"/", "/console", "/dashboard"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = controlPlaneHost
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s returned %d", path, rec.Code)
		}
		if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Fatalf("%s lost its console framing policy", path)
		}
		var catalog consoleLocale
		if err := json.Unmarshal(consoleLocaleData(t, rec.Body.Bytes()), &catalog); err != nil {
			t.Fatalf("parse console locale on %s: %v", path, err)
		}
		if catalog.Name == "" || catalog.Messages["Sign in"] == "" || catalog.ServerMessages["no free egress IP on host {host}"] == "" {
			t.Fatalf("%s did not serve the login and assignment translations", path)
		}
	}
}

func TestConsoleLocaleKeysAndParameters(t *testing.T) {
	var catalog consoleLocale
	if err := json.Unmarshal(consoleChinese, &catalog); err != nil {
		t.Fatal(err)
	}
	// Translation calls with a literal key and the initial navigation labels
	// should continue to have a Chinese string as the console evolves.
	keys := regexp.MustCompile(`(?:\btr(?:HTML)?\(\s*|data-l10n(?:-label)?=)("([^"\\]|\\.)*")`)
	for _, m := range keys.FindAllSubmatch(consoleHTML, -1) {
		var key string
		if err := json.Unmarshal(m[1], &key); err != nil {
			t.Fatal(err)
		}
		if catalog.Messages[key] == "" {
			t.Errorf("missing console translation for %q", key)
		}
	}
	for _, key := range []string{"Complete this required field.", "Enter a valid value."} {
		if catalog.Messages[key] == "" {
			t.Errorf("missing console validation translation for %q", key)
		}
	}
	parameters := regexp.MustCompile(`\{\w+\}`)
	for _, group := range []map[string]string{catalog.Messages, catalog.ServerMessages} {
		for key, translated := range group {
			want, got := parameters.FindAllString(key, -1), parameters.FindAllString(translated, -1)
			slices.Sort(want)
			slices.Sort(got)
			if translated == "" || !slices.Equal(want, got) {
				t.Errorf("console translation for %q has parameters %v, want %v", key, got, want)
			}
		}
	}
}

func TestConsoleLocalePreservesMarkupCharactersAsData(t *testing.T) {
	data := []byte(`{"example":"</script> & other text"}`)
	embedded := consoleLocaleData(t, embedConsoleLocale(consoleHTML, data))
	var got map[string]string
	if err := json.Unmarshal(embedded, &got); err != nil || got["example"] != "</script> & other text" {
		t.Fatalf("embedded locale data did not survive HTML escaping: %s (%v)", embedded, err)
	}
}
