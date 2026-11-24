# XHTTP 与 VLESS Encryption 来源

源代码取自 [MiChongs/sing-box `f88982450a13a818f680de884663fa914798e84a`](https://github.com/MiChongs/sing-box/tree/f88982450a13a818f680de884663fa914798e84a)，移植目标为 SagerNet/sing-box `v1.15.0-alpha.13` / `824dbcfb4dd0a95921840b1737b950cde590241e`。[manifest.json](manifest.json) 是拆分前 B-box `44879bd` 的安装清单（其中 `libbox/` 路径指当时的 B-box 仓库），保存每个文件的来源路径、原始 SHA-256、安装后的 SHA-256，以及集成补丁对应的上游文件哈希。

MiChongs/sing-box 沿用 sing-box 的 GPL-3.0-or-later 许可，许可原文保存在 [michongs-sing-box-LICENSE](https://github.com/giturass/B-box/blob/newui/flutter/assets/licenses/michongs-sing-box-LICENSE)。XHTTP 和 Encryption 的协议代码参考 XTLS/Xray-core `v26.9.30`（`b26a91de4f3294e26a0ad0a970b81a386a41f789`），相应 MPL-2.0 许可原文保存在 [xray-core-LICENSE](https://github.com/giturass/B-box/blob/newui/flutter/assets/licenses/xray-core-LICENSE)。保留 MiChongs 文件中的协议及参考版本注释；未复制 ref1nd/sing-box 的额外源码。

直接安装 `transport/v2rayxhttp/`、`protocol/vless/encryption/` 的生产代码及全部目录测试，以及选项和插件注册文件。B-box 的改动在清单中逐项注明：插件和 range schema 与稳定排序、错误信息去除凭据、下行端口独立覆写、[HTTP/1.1 标准请求体关闭错误归类及回归](https://github.com/giturass/B-box/blob/newui/libbox.md#xhttp-与-vless-encryption)、服务端握手随调用取消及服务 scope 关闭退出、针对当前 SagerNet TLS 字段的 HTTP/3 转换，以及去除 reference 中当前核心没有的 `certificate_server_name` 测试。集成补丁只增加 XHTTP 注册、VLESS `encryption` / `decryption`、加密连接握手、共享 ECH 查询和 `with_xhttp` 发货标签；不变更核心上游基线或依赖来源。

HTTP/3 沿用当前核心的 quic-go/sing-quic 与 BBR/Brutal API。uTLS 指纹只用于 TCP，HTTP/3 使用等价标准 TLS 配置，保留证书校验、SNI、客户端证书、证书 pin 和 ECH。VLESS Vision 的 `CommonConn` 适配使用当前固定 sing-vmess 的 `input` / `rawInput` 布局，构建仍使用项目原有 `-checklinkname=0`。未增加 libbox 的导出绑定。

[sing-vmess-vision-pointer.patch](../patches/sing-vmess-vision-pointer.patch) 适用于 SagerNet/sing-vmess `v0.2.9-0.20261019223527-a0c58542bd9d` / [`a0c58542bd9d99b00ea0c3cfacce6f03cf8a4017`](https://github.com/SagerNet/sing-vmess/tree/a0c58542bd9d99b00ea0c3cfacce6f03cf8a4017)。原 `tlsRegistry` 将 TLS 对象指针跨函数保存为 `uintptr`，随后转回字段指针，触发 Go race 构建的 `checkptr` 检查。补丁使标准 TLS、uTLS 和 Encryption 注册接口统一保持 `unsafe.Pointer`，通过 `unsafe.Add` 访问已核对存在及类型的缓冲字段，让 Go 持续追踪对象地址。修改后的固定 SagerNet 模块副本提交在 [`.b-box/sing-vmess`](../sing-vmess)，`go.mod` 用本地 replace 指向副本；依赖版本和来源保持上述固定值。清单记录依赖源码和补丁哈希，许可沿用 [sing-vmess GPL-3.0-or-later LICENSE](https://github.com/SagerNet/sing-vmess/blob/a0c58542bd9d99b00ea0c3cfacce6f03cf8a4017/LICENSE)。标准/uTLS 缓冲及无效字段布局回归以 race 运行，保留 `checkptr` 检查。

这些源码和集成改动已直接提交在本分支的安装位置。上游目录测试与 `experimental/libbox/ui_xhttp_test.go` 的完整核心测试由 B-box 的 GitHub Actions 运行；源码移植及静态检查不代表已通过 Xray 实际网络互通或 Android 实机验收。
