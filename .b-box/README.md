# B-box core

This branch is the [B-box](https://github.com/giturass/B-box) core: SagerNet/sing-box `v1.15.0-alpha.13` (`824dbcfb4dd0a95921840b1737b950cde590241e`) with B-box's patches and libbox bindings committed in place. B-box consumes it as the `core` git submodule; [libbox.md](https://github.com/giturass/B-box/blob/newui/libbox.md) documents every difference and its tests.

| Path | Content |
| --- | --- |
| `sing-tun/` | `github.com/sagernet/sing-tun` `v0.9.7-0.20261023115453-611d83b7a57b` with `patches/sing-tun-android-ingress.patch` and its regression test |
| `sing-vmess/` | `github.com/sagernet/sing-vmess` `v0.2.9-0.20261019223527-a0c58542bd9d` with `patches/sing-vmess-vision-pointer.patch` and its regression tests |
| `regexp2/` | `github.com/dlclark/regexp2/v2` `v2.11.0` with `patches/regexp2-cancel.patch` and `bbox_context.go` |
| `goja/` | `github.com/dop251/goja` `v0.0.0-20261102223426-a177d211bf60` with `patches/goja-regexp-cancel.patch` and `bbox_regexp_interrupt.go` |
| `patches/` | The dependency patches above, kept for rebasing when a pinned dependency changes |
| `xhttp/` | Provenance of the XHTTP and VLESS Encryption port |

`go.mod` points the four modules at these copies with local `replace` directives. To move to a new sing-box tag, rebase the commits after the upstream tag onto it; to change a pinned dependency, replace its copy with the new module source and reapply the matching patch.
