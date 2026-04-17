// Command fakeclaude is a stand-in for the real claude CLI used by the
// relay's e2e tests. The relay invokes us as `claude -p` and pipes the
// prompt over stdin (the production path). For backwards compatibility
// we also accept `-p <prompt>` as a positional argument so older tests
// keep working unchanged.
//
// Behaviour is tuned via environment variables set by the test:
//
//	FAKE_CLAUDE_FAIL=1        exit non-zero with a message on stderr
//	FAKE_CLAUDE_SLEEP=500ms   sleep before producing output (for timeout tests)
package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

func main() {
	if d := os.Getenv("FAKE_CLAUDE_SLEEP"); d != "" {
		if parsed, err := time.ParseDuration(d); err == nil {
			time.Sleep(parsed)
		}
	}
	if os.Getenv("FAKE_CLAUDE_FAIL") == "1" {
		fmt.Fprintln(os.Stderr, "fake claude: intentional failure")
		os.Exit(2)
	}

	prompt := readPrompt()
	fmt.Printf("reply: %s", prompt)
}

// readPrompt pulls the prompt from `-p <value>` if a non-flag value
// follows -p, otherwise from stdin. This mirrors what the real claude
// CLI accepts.
func readPrompt() string {
	for i, a := range os.Args {
		if a != "-p" {
			continue
		}
		if i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "-") {
			return os.Args[i+1]
		}
		break
	}
	stdin, _ := io.ReadAll(os.Stdin)
	return string(stdin)
}
