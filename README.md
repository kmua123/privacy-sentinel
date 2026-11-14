# 隐私哨兵 · Privacy Sentinel

Android 本地应用联网防火墙：在一个 VPN 中组合联网审批、Clash 订阅代理和 ZeroTier 私有网络访问。

**公开预览版 0.2.3-preview，尚未上架 Google Play。** 本项目派生自 NetGuard 与 Mihomo，采用 GPL-3.0，保留第三方许可和完整修改源码。

## 下载与使用

到本仓库的 [Releases](https://github.com/kmua123/privacy-sentinel/releases) 下载 APK。支持 Android 10+ 的 arm64-v8a / x86_64；内置无线调试辅助功能需要 Android 11+。目前只完成有限设备与模拟器验证，各厂商系统兼容性仍在完善。

1. 安装后启动“联网守卫”，按系统提示同意建立本地 VPN 并允许通知。
2. 普通应用首次联网会等待审批；允许后原应用可能需要重新加载。系统共享 UID 默认记录放行，可按整组调整策略。
3. 进入“Clash 订阅与 ZeroTier 回家”，导入你自己的 HTTPS Clash YAML 订阅或节点文件。可保存多个订阅、切换节点、单个或批量测延迟。
4. 若需要回家连接，填写你自己的 ZeroTier 网络 ID、家庭网段和 DNS，开启后在自己的控制器授权本机节点；家庭网关仍需具备相应路由、转发和出口配置。

**公开版没有内置节点、订阅、家庭网络或账号。** 首次安装默认关闭 ZeroTier。覆盖安装会保留用户已经保存的配置；清空默认值不会擦除已有配置。

## 功能与限制

- 一个 `VpnService` 处理应用审批、国内分流、代理与私有家庭网络；不需要另装 Shizuku。
- 支持临时允许、始终允许、拒绝、记录及撤销规则。共享 UID 只能按组控制。
- 智能分流优先家庭网段，再使用安装包内固定国内域名/IP 规则直连，其余走所选节点；无节点时其余公网直连。
- 节点测速通过指定代理完成真实 HTTPS 204 请求，显示连接、TLS、HTTP 耗时；不代表带宽，也不自动选择最快节点。
- IPv6 默认根据当前底层网络的地址和默认路由自动判断，可选只用 IPv4 或手动允许 IPv6；TUN 仍持续接管 IPv6，应用自带解析或旧缓存可能需要重新加载。
- 可选本机无线 ADB 配对辅助服务，提供 UID 流量快照与相机/麦克风 AppOps 事件提醒；这类提醒发生在使用开始后，不能替代系统的事前权限控制。
- 当前回家出口仅支持已配置的 IPv4 出口，**不支持经回家通道的 ICMP Ping**，不会生成本地假 Ping 应答。请用实际网页或文件访问确认连通。
- VPN 外、其他用户/分身、共享系统服务代发、基带及系统绕过 VPN 的行为不属于完整观测范围。外发流量或权限只提供核查线索，不能证明上传了什么内容。
- 应用本身的订阅下载、调试配对和隧道控制流量排除在本地 VPN 之外；节点、DNS 与 ZeroTier 基础服务会收到运行所需的网络请求。

这不是“保证发现所有监控”的工具。应用被系统终止时的断线保护应在系统 VPN 设置中配置“始终开启 VPN”和“阻止未使用 VPN 的连接”。

## 隐私与许可

阅读 [隐私说明](PRIVACY.md)、[第三方许可及来源](THIRD_PARTY_NOTICES.md) 和 [GPL-3.0](LICENSE)。应用清单、联网审批、订阅及辅助服务身份保存在本机私有目录；项目未添加广告、统计或自动上传报告 SDK。

本仓库不包含发布签名私钥、用户订阅、ADB 私钥、ZeroTier 身份、手机转储或原开发工作目录的 Git 历史。上游公开测试证书和密钥样例用于测试，不是用户凭据。

## 源码布局与构建

- `netguard/`：修改后的 Android 应用与原 NetGuard JNI 对应源码。
- `guard-core/`：Go/gomobile 转发核心及固定版本的 Mihomo 修改源码。
- `third_party/`：直接依赖的许可、NOTICE 和固定源码来源。完整 Go 依赖由 `go.mod` / `go.sum` 固定。
- `tools/build-legacy-jni.ps1`：从公开 C 源码重建旧 JNI 库；不使用个人版来源不明的预编译副本。

构建环境：JDK 21、Android SDK Platform 37、NDK r27d、Go 1.27.4。Android targetSdk 为 36。SDK/NDK/Go/JDK 自行安装，通过环境变量或参数提供路径。

Windows PowerShell：

```powershell
# 先设置 JAVA_HOME、ANDROID_HOME、ANDROID_NDK_HOME，且将匹配版本的 go 放入 PATH
./guard-core/build.ps1
Copy-Item ./guard-core/guardcore.aar ./netguard/app/libs/guardcore.aar
./tools/build-legacy-jni.ps1
Set-Location ./netguard
./gradlew.bat :app:assembleRelease :app:lintRelease --console=plain
```

生成的 release APK 未签名，需要用自己的密钥签名。覆盖安装必须使用原证书；请勿提交你的密钥、密码或配置到 Git。预览发布的 APK 与 GitHub 标签对应，发布附件提供 SHA256 校验值。

## 来源

NetGuard 上游为 [M66B/NetGuard](https://github.com/M66B/NetGuard)，Mihomo 上游为 [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo)。本项目是独立派生版本，不代表上游项目提供支持或认可。具体提交、依赖许可及修改范围见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
