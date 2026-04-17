package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/plekt/relay/internal/config"
	"github.com/plekt/relay/internal/hmac"
)

const testSecret = "e2e-shared-secret-deadbeef"

// fakeClaudeBin is set by TestMain. The relay under test invokes it in
// place of the real claude CLI.
var fakeClaudeBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "relay-e2e-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: mktemp:", err)
		os.Exit(1)
	}
	bin := filepath.Join(dir, "fakeclaude")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, "./internal/testutil/fakeclaude")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "e2e: build fakeclaude:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	fakeClaudeBin = bin
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// callbackCapture spins up an httptest server that records the single
// callback the relay posts after processing a run, verifying the HMAC
// signature along the way.
type callbackCapture struct {
	srv *httptest.Server
	ch  chan callbackBody
}

func newCallbackCapture(t *testing.T, secret string) *callbackCapture {
	t.Helper()
	cc := &callbackCapture{ch: make(chan callbackBody, 1)}
	cc.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if err != nil {
			t.Errorf("callback: read body: %v", err)
			http.Error(w, "read", http.StatusInternalServerError)
			return
		}
		sig := r.Header.Get(hmac.SignatureHeader)
		if !hmac.Verify(secret, body, sig) {
			t.Errorf("callback: invalid signature (sig=%q body=%q)", sig, body)
			http.Error(w, "bad sig", http.StatusUnauthorized)
			return
		}
		var cb callbackBody
		if err := json.Unmarshal(body, &cb); err != nil {
			t.Errorf("callback: unmarshal: %v", err)
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		cc.ch <- cb
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(cc.srv.Close)
	return cc
}

func (cc *callbackCapture) wait(t *testing.T, d time.Duration) callbackBody {
	t.Helper()
	select {
	case cb := <-cc.ch:
		return cb
	case <-time.After(d):
		t.Fatalf("timed out after %s waiting for callback", d)
		return callbackBody{}
	}
}

// newRelay starts the relay handler on an httptest server using the
// fake claude binary and the supplied timeout.
func newRelay(t *testing.T, timeout time.Duration) *httptest.Server {
	t.Helper()
	cfg := &config.Config{
		Addr:          "unused",
		WebhookSecret: testSecret,
		ClaudeBin:     fakeClaudeBin,
		RunTimeout:    timeout,
	}
	srv := httptest.NewServer(newHandler(cfg))
	t.Cleanup(srv.Close)
	return srv
}

// postSigned signs body under testSecret and POSTs it to url, returning the
// HTTP status code (the body is drained and discarded).
func postSigned(t *testing.T, url string, body []byte, sig string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if sig != "" {
		req.Header.Set(hmac.SignatureHeader, sig)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestE2E_HappyPath(t *testing.T) {
	cb := newCallbackCapture(t, testSecret)
	relay := newRelay(t, 10*time.Second)

	raw, _ := json.Marshal(inboundPayload{
		RunID:       42,
		JobName:     "daily-digest",
		AgentName:   "digester",
		Prompt:      "hello world",
		CallbackURL: cb.srv.URL,
		TriggeredAt: time.Now(),
	})
	status := postSigned(t, relay.URL, raw, hmac.Sign(testSecret, raw))
	if status != http.StatusAccepted {
		t.Fatalf("relay status: got %d want 202", status)
	}

	got := cb.wait(t, 5*time.Second)
	if got.Error != "" {
		t.Fatalf("unexpected callback error: %q", got.Error)
	}
	if want := "reply: hello world"; got.Output != want {
		t.Errorf("callback output: got %q want %q", got.Output, want)
	}
}

func TestE2E_InvalidSignature(t *testing.T) {
	relay := newRelay(t, 10*time.Second)

	raw, _ := json.Marshal(inboundPayload{RunID: 1, Prompt: "x", CallbackURL: "http://127.0.0.1:0"})
	status := postSigned(t, relay.URL, raw, "sha256=deadbeef")
	if status != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401", status)
	}
}

func TestE2E_WrongMethod(t *testing.T) {
	relay := newRelay(t, 10*time.Second)

	resp, err := http.Get(relay.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d want 405", resp.StatusCode)
	}
}

func TestE2E_MalformedJSON(t *testing.T) {
	relay := newRelay(t, 10*time.Second)

	raw := []byte("{not valid json")
	status := postSigned(t, relay.URL, raw, hmac.Sign(testSecret, raw))
	if status != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", status)
	}
}

func TestE2E_ClaudeFails(t *testing.T) {
	t.Setenv("FAKE_CLAUDE_FAIL", "1")

	cb := newCallbackCapture(t, testSecret)
	relay := newRelay(t, 10*time.Second)

	raw, _ := json.Marshal(inboundPayload{
		RunID:       7,
		Prompt:      "will fail",
		CallbackURL: cb.srv.URL,
	})
	if status := postSigned(t, relay.URL, raw, hmac.Sign(testSecret, raw)); status != http.StatusAccepted {
		t.Fatalf("relay status: got %d want 202", status)
	}

	got := cb.wait(t, 5*time.Second)
	if got.Error == "" {
		t.Fatalf("expected callback error, got output=%q", got.Output)
	}
	if !strings.Contains(got.Error, "claude") {
		t.Errorf("error should mention claude: got %q", got.Error)
	}
}

// TestE2E_MultilinePromptPreserved guards against the regression where a
// multi-line prompt with embedded double-quotes is silently truncated
// before claude sees it. The bug: relay used to pass the prompt as a
// positional CLI argument, and on Windows `claude` resolves to a
// `.cmd` shim — cmd.exe re-parses argv and breaks at the first newline,
// so claude only saw the first line of the system prompt and replied
// "what should I do?" instead of executing the steps.
//
// The verbatim prompt below is the AI-news-digest agent prompt the user
// hit the bug with. Any change to relay arg/stdin handling must keep
// this round-tripping byte-for-byte through fakeclaude.
func TestE2E_MultilinePromptPreserved(t *testing.T) {
	const prompt = `You are an AI news digest agent. Working file: A:\Coding\AgentOS\Core\ai-news-digest.md

STEPS:
1. Check if A:\Coding\AgentOS\Core\ai-news-digest.md exists.
   - If it does NOT exist: create it with header "# AI News Digest\n\n".
   - If it exists: read it fully so you know which headlines were already recorded in previous runs.

2. Use WebSearch to find the latest AI news from the last 24 hours. Look for announcements from major labs (Anthropic, OpenAI, Google DeepMind, Meta AI, Mistral, xAI), notable model releases, research papers, and industry news.

3. For each candidate headline, compare against the existing file. SKIP any headline that is already present (match by title or URL — be tolerant of small wording differences).

4. Append a new section to the file with today's date as a heading:
   ## YYYY-MM-DD
   - **<headline>** — <one-sentence summary> ([source](<url>))
   - ...

   Only include items that are genuinely new since last run. If nothing new was found, append "## YYYY-MM-DD\n_No new items._" so the run is still recorded.

5. Save the file.

6. Output a full markdown of what you added (or "no new items") so the operator can see it in the run log.`

	cb := newCallbackCapture(t, testSecret)
	relay := newRelay(t, 10*time.Second)

	raw, _ := json.Marshal(inboundPayload{
		RunID:       100,
		JobName:     "ai-news-digest",
		AgentName:   "claude_code",
		Prompt:      prompt,
		CallbackURL: cb.srv.URL,
		TriggeredAt: time.Now(),
	})
	if status := postSigned(t, relay.URL, raw, hmac.Sign(testSecret, raw)); status != http.StatusAccepted {
		t.Fatalf("relay status: got %d want 202", status)
	}

	got := cb.wait(t, 10*time.Second)
	if got.Error != "" {
		t.Fatalf("unexpected callback error: %q", got.Error)
	}
	want := "reply: " + prompt
	if got.Output != want {
		t.Fatalf("prompt was truncated or mangled\n  want %d bytes ending %q\n  got  %d bytes ending %q",
			len(want), tail(want, 60), len(got.Output), tail(got.Output, 60))
	}
}

// tail returns the last n bytes of s with a leading ellipsis if truncated.
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}

func TestE2E_RunTimeout(t *testing.T) {
	t.Setenv("FAKE_CLAUDE_SLEEP", "2s")

	cb := newCallbackCapture(t, testSecret)
	relay := newRelay(t, 200*time.Millisecond)

	raw, _ := json.Marshal(inboundPayload{
		RunID:       9,
		Prompt:      "slow",
		CallbackURL: cb.srv.URL,
	})
	if status := postSigned(t, relay.URL, raw, hmac.Sign(testSecret, raw)); status != http.StatusAccepted {
		t.Fatalf("relay status: got %d want 202", status)
	}

	got := cb.wait(t, 5*time.Second)
	if got.Error == "" {
		t.Fatalf("expected timeout error, got output=%q", got.Output)
	}
}
