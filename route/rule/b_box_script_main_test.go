package rule

import (
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/experimental/httpdebug"
)

var (
	ruleScriptTestDirectory string
	ruleScriptTestNamespace atomic.Uint64
)

func TestMain(m *testing.M) {
	var err error
	// The processing manager owns one capture store for this process, and
	// intentionally keeps it after StopService so saved data remains readable.
	ruleScriptTestDirectory, err = os.MkdirTemp("", "sing-box-rule-scripts-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "create rule script test storage:", err)
		os.Exit(1)
	}
	exitCode := m.Run()
	httpdebug.StopService()
	if err := os.RemoveAll(ruleScriptTestDirectory); err != nil {
		fmt.Fprintln(os.Stderr, "remove rule script test storage:", err)
		exitCode = 1
	}
	os.Exit(exitCode)
}
