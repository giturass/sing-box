# B-box core

This branch is the [B-box](https://github.com/giturass/B-box) core: SagerNet/sing-box `v1.15.0-alpha.14` (`126ce6c21ddf10769fe793458d34ae3add575872`) with B-box's patches and libbox bindings committed in place. B-box consumes it as the `core` git submodule; [libbox.md](https://github.com/giturass/B-box/blob/newui/libbox.md) documents every difference and its tests.

| Path | Content |
| --- | --- |
| `sing-tun/` | `github.com/sagernet/sing-tun` `v0.9.7-0.20261126024559-1a13df1ac21f` with `patches/sing-tun-android-ingress.patch` and its regression test |
| `sing-vmess/` | `github.com/sagernet/sing-vmess` `v0.2.9-0.20261124075649-4acc92a6f6c6` with `patches/sing-vmess-vision-pointer.patch` and its regression tests |
| `regexp2/` | `github.com/dlclark/regexp2/v2` `v2.11.0` with `patches/regexp2-cancel.patch` and `bbox_context.go` |
| `goja/` | `github.com/dop251/goja` `v0.0.0-20261102223426-a177d211bf60` with `patches/goja-regexp-cancel.patch` and `bbox_regexp_interrupt.go` |
| `patches/` | The dependency patches above, kept for rebasing when a pinned dependency changes |
| `xhttp/` | Provenance of the XHTTP and VLESS Encryption port |
| `verify.py` | Checks every copy against the module hash of its pinned version |

`go.mod` points the four modules at these copies with local `replace` directives. `python3 .b-box/verify.py` reverses each patch on a scratch copy of the tracked files, checks the required version in `go.mod`, removes the files B-box adds and compares the result with the Go module hash (`h1`) of the pinned version; B-box's core setup runs it before every test and build.

To move to a new sing-box tag, rebase the commits after the upstream tag onto it. To change a pinned dependency, replace its copy with the new module source, reapply the matching patch and update the version and hash in `verify.py`. Add a copy with `git add -f`: sing-tun and regexp2 ignore files that they ship.
