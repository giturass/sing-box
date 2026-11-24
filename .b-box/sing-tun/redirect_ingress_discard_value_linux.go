package tun

import (
	"encoding/binary"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// Android vendor builds may use a single ifindex; AOSP uses two ifindices.
// Use the kernel's map metadata rather than the Android release number.
func validateAndroidIngressDiscardMapLayout(mapType uint32, keySize uint32, valueSize uint32) error {
	if mapType != unix.BPF_MAP_TYPE_HASH || keySize != 16 || (valueSize != 4 && valueSize != 8) {
		return E.New("unexpected ingress discard map layout: type ", mapType, ", key ", keySize, ", value ", valueSize)
	}
	return nil
}

func androidIngressDiscardValueMatchesInterface(value []byte, ifIndex int) bool {
	if ifIndex <= 0 || (len(value) != 4 && len(value) != 8) {
		return false
	}
	if int(binary.NativeEndian.Uint32(value[:4])) != ifIndex {
		return false
	}
	return len(value) == 4 || int(binary.NativeEndian.Uint32(value[4:])) == ifIndex
}

func androidIngressDiscardValueCanRestore(value []byte, valueSize int, ifIndex int) bool {
	// Never pass a saved short buffer to a map that now has a larger value.
	return len(value) == valueSize && androidIngressDiscardValueMatchesInterface(value, ifIndex)
}
