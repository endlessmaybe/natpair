# 开发与构建

GUI 使用 Python / Tkinter，Windows Tailscale 辅助接入使用 WinDivert。核心加密依赖 `cryptography`。Windows 交付由 PyInstaller 打包。

`requirements.txt` 锁定 `cryptography==48.0.0` 与 `pyinstaller==6.22.3`。本次原始发布包的 Python 运行时可从 `_internal` 和打包文件核对；不需要普通用户另装 Python。

## 源码运行

在自己的开发环境中安装依赖，复制 `config.example.json` 为 `config.json`，填写自己的协调服务配置：

```powershell
python -m pip install -r requirements.txt
python meshapp.py --config config.json
```

Tkinter 需要可用的桌面环境。服务端入口见 [协调服务部署](SERVER_SETUP.md)。

## CLI

以下示例中的 `ROOM_CODE` 需要替换为所有成员共用的房间码：

```powershell
python meshapp.py --cli --config config.json --code ROOM_CODE --name Alice --coexist
python meshapp.py --cli --config config.json --code ROOM_CODE --name Host --star-role host --game-port 25565 --coexist
python meshapp.py --cli --config config.json --code ROOM_CODE --name Player --star-role player --coexist
python meshapp.py --cli --config config.json --code ROOM_CODE --udp-only --coexist
```

GUI 默认选择共存档；CLI 需要显式 `--coexist`。CLI 未指定共存或新增限额时保持原来的不限额行为。

`--new-combinations-per-second 1000` 是单独的新增组合档。`--duration` 与 `--result` 用于有时限的验证和记录导出。

## 测试与打包

```powershell
python -m unittest discover -s . -p 'test_*.py'
python -m PyInstaller --noconfirm NATPairMesh.spec
```

PyInstaller 输出整套目录。分发时补上有效配置或明确标记的模板，并保留全部 `_internal` 与驱动许可。不要只分发 EXE。

## 关键模块

| 文件 | 用途 |
| --- | --- |
| `meshapp.py` | GUI、CLI、模式与档位入口 |
| `meshclient.py` | 多成员客户端、成员对维护与导出 |
| `meshplan.py` | 配对、轮转、任务续期 |
| `meshtail.py` / `tailbridge.py` | Tailscale 身份、抓包与辅助代理 |
| `client.py` / `strategy.py` | 底层双人打洞核心与候选策略 |
| `coexistguard.py` / `combinations.py` | 组合预算、平滑发送与共存保护 |
| `transport.py` | AEAD 数据封装、分片、防重放 |
| `roomudp.py` | 加密房间协议 |
| `meshserver.py` / `server.py` | 协调与映射观测服务 |
| `journal.py` / `evidence.py` | 轮转日志与首次成功证据 |

## 第三方许可

WinDivert 2.2.2 的许可、说明、DLL、驱动和对应源码包保留在 `driver/`。其许可允许在 LGPLv3 或 GPLv2 之间选择，完整文本见 `driver/LICENSE`。Windows 原运行库中保留各依赖附带的许可材料。

本次没有为 NATPair 自身代码新增 MIT、GPL 或其他开源授权；公开托管不等于已经补齐项目自身许可条款。
