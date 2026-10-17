# NATPair Mesh — UDP 打洞、Tailscale 直连与 Minecraft Java 联机

简体中文 · [English](README.en.md)

**NATPair Mesh 1.2.0** 是 Windows 上的多人 **UDP 打洞 / NAT 穿透（内网穿透）**辅助工具，配合 **Tailscale** 支持最多 8 人互连，以及 **Minecraft Java 局域网联机**的房主星形房间。需要自己的协调服务配置，不保证所有 NAT 或运营商网络都能直连。

**UDP hole punching and NAT traversal helper for Tailscale and Minecraft Java LAN multiplayer on Windows.** Up to 8 peers, mesh or host-star rooms, with self-hosted coordination. See the [English guide](README.en.md).

**[下载 Windows 完整包](https://github.com/endlessmaybe/natpair/releases/latest) · [使用说明](docs/USER_GUIDE.md) · [当前功能与优点](docs/FEATURES.md) · [协调服务部署](docs/SERVER_SETUP.md)**

## 适合哪些场景

| 你想做什么 | 使用方式 |
| --- | --- |
| Minecraft Java 远程联机，让朋友加入房主的局域网世界 | MC 星形房间：一名房主、最多七名玩家，自动公布房主 Tailscale 游戏地址与实际端口 |
| 尝试改善 Tailscale 节点之间的直连 | 多人辅助 UDP 打洞；保留已经验证的原生 IPv6 / IPv4 路径，分别展示 UDP 与 Tailscale 数据验证结果 |
| 研究或排查 NAT 穿透 | 仅 UDP 模式观察打洞过程与证据，不创建独立 VPN 或游戏转发服务 |

普通使用者下载完整 Windows 包，无需另装 Python；Tailscale 接入模式需要自行安装、登录并授权 Tailscale。所有模式都需要有效的协调服务配置，公开 ZIP 中只有模板。

## 网络与使用提醒

- **移动 Wi-Fi：** 公网 IPv4 / 端口映射不稳定时，不建议 IPv4 打洞，优先已验证的 IPv6 原生直连。
- **星形房间：** 房主最好有公网 IPv6；玩家也需要可用公网 IPv6，才能走这一原生路径。
- **全员两两互联：** 移动 Wi-Fi 最好别加入 IPv4 辅助打洞，避免影响多对连接。
- **使用前关闭防火墙、杀毒软件和代理软件。** 接入模式所需的 Tailscale 保持运行；使用结束后恢复安全防护。
- 联网时的 UDP 发包可能暂时导致网络连接不畅，提前保存工作并避开重要任务。

本软件以较大量 UDP 探测尝试打通、再通过保活维持连接，主要面向公网 IPv4 出口相对稳定的家庭大内网。请事先了解所在省份及运营商的 UDP 策略；因运营商封锁、限速或策略限制导致的问题，开发者不对此负责。完整说明见 [网络选择与免责声明](docs/NETWORK_AND_DISCLAIMER.md)。

## 当前版本

| 项目 | 说明 |
| --- | --- |
| 产品 | NATPair Mesh |
| 界面版本 | 1.2.0 |
| 源码版本标识 | `1.2.0-mesh`，见 `meshclient.py` |
| 原始发布包日期 | 2026-10-08 |
| 本次 GitHub 公开整理日期 | 2026-10-11 |
| 客户端 | Windows x64，完整 ZIP 交付 |
| 房间上限 | 8 人，包含自己 / 房主 |
| 当前新增功能 | MC 星形房间、房主游戏地址自动公布、预算用满后的有限复测 |

本仓库提供当前 Mesh 1.2.0 源码与测试，不附带旧版本验证脚本。

**公开包中的 `config.json` 是模板。** 使用前，需要管理员提供当前协调服务配置，或自行部署协调服务。真实共享密钥、私人服务器地址和个人诊断记录没有写入公开包。EXE、驱动和运行库保持原发布内容。

## 能做什么

| 功能 | 当前行为 |
| --- | --- |
| 全员互连 | 最多 8 人，逐对建立辅助 UDP 通道，8 人共 28 对 |
| MC Java 星形房间 | 一名房主、最多七名玩家；只探测房主与玩家，8 人共 7 对 |
| 自动交换 Tailscale 身份 | 加入同一房间后交换地址与节点信息，无需逐个手填对端 `100.x` 地址 |
| 保留原生直连 | 已核实的 Tailscale IPv6 / IPv4 直连跳过辅助扫描 |
| 多人探测调度 | 每台电脑同时集中探测一对；互不占用成员的对可并行，未完成的对公平轮转 |
| 打通即用 | 成功的一对先使用，其余继续排队尝试 |
| 独立恢复 | 某人退出、重进或某条通道失联，只恢复相关成员对 |
| 预算恢复 | 预算用满时保留扫描位置，有限复测旧候选并等待预算恢复 |
| 仅 UDP 模式 | 独立观察打洞过程，不接入 Tailscale，也不是独立虚拟网卡 VPN |
| 状态与记录 | 分开显示 UDP 已验证、Tailscale 已验证、原生直连、等待轮次等状态 |
| 证据导出 | 自动保存首次认证成功证据，可导出成员状态、轮转日志与预算信息 |

## 主要优点

1. **MC 联机少做无用探测。** 8 人房间从全互连的 28 对降到房主星形的 7 对，辅助关系减少 75%。它减少待处理关系，不代表连接速度必然提高四倍。
2. **已有好路径继续用。** 已验证的原生 IPv6 / IPv4 路径直接保留；只有需要辅助的成员对才广泛扫描。
3. **一个人重进，其他人继续用。** 每对有独立会话、套接字、进度和代理，降低成员变化对其他通道的影响。
4. **更容易与已有代理共用。** 默认共存档主动控制突发和新增组合；已有业务、认证回包、保活优先。
5. **故障位置更清楚。** 外层 UDP 成功和 Tailscale 数据通道成功分别显示，也能看见等待心跳、轮次和预算的原因。
6. **使用入口更简单。** 通过共同房间码加入，自动交换成员地址；MC 玩家直接复制房主游戏地址。

详细参数、使用范围和验证依据见 [功能与优点](docs/FEATURES.md)。

## 快速开始

1. 下载并完整解压 Windows ZIP，保留 EXE、`config.json` 与整个 `_internal`。
2. 用管理员提供的配置替换模板；所有成员使用兼容的同一协调服务。
3. 接入 Tailscale 时，先登录同一个已授权网络，再以管理员身份运行 `NATPairMesh.exe`。
4. 选择全员互连或 MC 星形模式，使用同一个房间码加入。
5. 看成员表的真实验证状态；MC 玩家复制 `100.x.x.x:游戏端口` 到游戏中连接。

Minecraft“开放到局域网”使用当次游戏显示的端口。软件不会替你启动 Minecraft 或自动开放任意游戏服务端口。

## 常见问题：内网穿透与游戏直连

### 没有公网 IPv4 能用吗？

NATPair 尝试在 NAT 后建立辅助 IPv4 UDP 通道，但是否成功取决于双方映射、网络与运营商策略。已有可用的 Tailscale 原生 IPv6 / IPv4 直连会保留；它不承诺所有对称 NAT、移动网络或 CGNAT 环境都能穿透。

### 可以用于 Minecraft Java 局域网联机吗？

可以使用 MC 星形房间：房主运行世界或服务端，玩家通过公布的 Tailscale 地址和实际游戏端口连接。8 人时只处理 7 条房主辅助关系；房主需要保持游戏、Tailscale 和 NATPair 在线。完整操作见 [MC 房间使用说明](docs/USER_GUIDE.md#3-minecraft-java-星形房间)。

### 可以代替 Tailscale，或独立进行 TCP 打洞吗？

游戏接入依赖 Tailscale，MC 的 TCP 流量由 Tailscale UDP 隧道承载。仅 UDP 模式用于观察和验证，不是独立 VPN；项目没有独立公网 TCP 打洞，也不提供公共游戏中继服务。

### 下载后能直接加入公共服务器吗？

公开包不附私人服务或接入密钥。请向自己的协调服务管理员取得配置，或按 [部署说明](docs/SERVER_SETUP.md) 自建。房间码用于加入房间，不能代替服务配置与 Tailscale 授权。

## 当前边界

- 不保证所有运营商、所有 NAT 类型都能直连；也不承诺八名不同运营商用户的 28 对都能打通。
- 当前调度是按等待顺序挑选不冲突配对的贪心轮转，尚未实现最优最大匹配。
- 共存预算只统计本程序掌握的组合，不能读取真实 ISP NAT 表，不能保证 Bifrost 永远不断线。
- 辅助通道是 IPv4 UDP。IPv6 优先指保留 Tailscale 已有且已验证的原生路径。
- 游戏 TCP 数据由 Tailscale UDP 隧道承载；没有独立公网 TCP 打洞，不把玩家之间业务交给房主任意转发。
- 多人房间不扩大 Tailscale 的账号、人数或设备授权额度。

## 源码与验证

GUI 入口：`meshapp.py`。多人客户端：`meshclient.py`。配对调度：`meshplan.py`。Tailscale 接入：`meshtail.py` / `tailbridge.py`。协调服务：`meshserver.py`。共存保护：`coexistguard.py`。加密传输：`transport.py`。

源码运行与打包见 [开发说明](docs/DEVELOPMENT.md)。发布检查见 [验证记录](docs/VALIDATION.md)。历史测试与重复发布摘要已精简，仅保留当前使用、功能、部署、开发和验证说明。

WinDivert 的许可和对应源码保留在 `driver/`。NATPair 自身源码未在本次整理中新增许可证授权。
