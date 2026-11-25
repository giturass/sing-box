package libbox

import "github.com/sagernet/sing-box/experimental/httpdebug"

// Breakpoints are process state and pause only recorded exchanges. They are
// readable and writable with the local service stopped; nothing is persisted.
func ValidateUICaptureBreakpoints(configJSON string) (string, error) {
	return httpdebug.ValidateBreakpoints(configJSON)
}

func SetUICaptureBreakpoints(configJSON string) (string, error) {
	snapshot, err := httpdebug.SetBreakpoints(configJSON)
	if err != nil {
		return "", err
	}
	return captureJSON(snapshot)
}

func ReadUICaptureBreakpoints() (string, error) { return captureJSON(httpdebug.Breakpoints()) }

func ReadUICapturePausedMessage(id string) (string, error) {
	message, err := httpdebug.ReadPausedMessage(id)
	if err != nil {
		return "", err
	}
	return captureJSON(message)
}

func ResolveUICaptureBreakpoint(id, decisionJSON string) error {
	return httpdebug.ResolveBreakpoint(id, decisionJSON)
}
