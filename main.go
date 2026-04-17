// Command plekt-relay is a tiny webhook receiver for Plekt scheduled job
// delivery. It accepts HMAC-signed POSTs from the core dispatcher,
// shells out to `claude code -p <prompt>`, and posts the captured stdout
// back to the run's callback URL using the same HMAC scheme.
//
// Usage:
//
//	./plekt-relay -config config.yml
//
// All runtime settings live in the YAML file (see config.example.yml):
// listen address, HMAC secret, claude binary, extra args, and per-run
// timeout. This binary is intentionally tiny so an operator can read it
// end to end before trusting it with a real API key. The whole protocol
// it implements is in internal/webhooks/{sign,dispatcher}.go on the core
// side.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/plekt/relay/internal/config"
	"github.com/plekt/relay/internal/hmac"
)

// inboundPayload is the JSON shape POSTed to us by the core dispatcher.
type inboundPayload struct {
	JobID       int64     `json:"job_id"`
	RunID       int64     `json:"run_id"`
	JobName     string    `json:"job_name"`
	AgentName   string    `json:"agent_name"`
	Prompt      string    `json:"prompt"`
	TriggeredAt time.Time `json:"triggered_at"`
	Manual      bool      `json:"manual"`
	CallbackURL string    `json:"callback_url"`
}

// callbackBody is the JSON we POST back to the run's callback URL.
type callbackBody struct {
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
}

func main() {
	configPath := flag.String("config", "config.yml", "path to YAML config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("plekt-relay listening on %s", cfg.Addr)
	log.Printf("  config file: %s", *configPath)
	log.Printf("  claude binary: %s", cfg.ClaudeBin)
	log.Printf("  per-run timeout: %s", cfg.RunTimeout)
	if err := http.ListenAndServe(cfg.Addr, newHandler(cfg)); err != nil {
		log.Fatal(err)
	}
}

// newHandler builds the HTTP handler that verifies inbound HMAC,
// dispatches the prompt to the claude CLI, and POSTs the result to
// the caller's callback URL. Extracted from main so e2e tests can
// drive it through httptest.
func newHandler(cfg *config.Config) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		_ = r.Body.Close()
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		sig := r.Header.Get(hmac.SignatureHeader)
		if !hmac.Verify(cfg.WebhookSecret, body, sig) {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
		var p inboundPayload
		if err := json.Unmarshal(body, &p); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}

		log.Printf("relay: run %d job=%q agent=%q prompt=%q",
			p.RunID, p.JobName, p.AgentName, truncate(p.Prompt, 80))

		w.WriteHeader(http.StatusAccepted)

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), cfg.RunTimeout)
			defer cancel()
			out, runErr := runClaude(ctx, cfg.ClaudeBin, p.Prompt, cfg.ClaudeArgs)
			postCallback(p.CallbackURL, cfg.WebhookSecret, out, runErr)
		}()
	})
	return mux
}

// runClaude invokes the claude CLI in print mode and pipes the prompt
// over stdin. We deliberately do NOT pass the prompt as a positional
// argument: on Windows the npm-installed `claude` resolves to a `.cmd`
// shim, and cmd.exe re-parses arguments containing newlines or quotes.
// A multi-line prompt with embedded `"` (e.g. inline header literals)
// gets truncated at the first newline before claude even sees it.
// stdin bypasses cmd.exe's argument parser entirely and round-trips
// arbitrary bytes on every platform.
func runClaude(ctx context.Context, bin, prompt string, extraArgs []string) (string, error) {
	args := append([]string{"--dangerously-skip-permissions", "-p"}, extraArgs...)
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = strings.NewReader(prompt)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		log.Printf("relay: claude exited: %v; stderr=%s", err, truncate(stderr.String(), 200))
		return "", fmt.Errorf("claude: %w", err)
	}
	return strings.TrimSpace(stdout.String()), nil
}

func postCallback(url, secret, output string, runErr error) {
	body := callbackBody{}
	if runErr != nil {
		body.Error = runErr.Error()
	} else {
		body.Output = output
	}
	raw, _ := json.Marshal(body)
	sig := hmac.Sign(secret, raw)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		log.Printf("relay: build callback request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hmac.SignatureHeader, sig)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("relay: callback POST failed: %v", err)
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("relay: callback returned status %d", resp.StatusCode)
		return
	}
	log.Printf("relay: callback delivered (%d bytes)", len(output))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
