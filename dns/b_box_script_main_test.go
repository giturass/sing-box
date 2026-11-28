package dns_test

import (
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/experimental/httpdebug"
)

var (
	bBoxDNSScriptTestDirectory string
	bBoxDNSScriptTestNamespace atomic.Uint64
)

func TestMain(m *testing.M) {
	var err error
	// The processing manager owns one capture store for this process, and
	// intentionally keeps it after StopService so saved data remains readable.
	bBoxDNSScriptTestDirectory, err = os.MkdirTemp("", "sing-box-dns-scripts-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "create DNS script test storage:", err)
		os.Exit(1)
	}
	exitCode := m.Run()
	httpdebug.StopService()
	if err := os.RemoveAll(bBoxDNSScriptTestDirectory); err != nil {
		fmt.Fprintln(os.Stderr, "remove DNS script test storage:", err)
		exitCode = 1
	}
	os.Exit(exitCode)
}
