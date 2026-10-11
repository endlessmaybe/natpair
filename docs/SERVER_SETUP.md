# 协调服务部署

公开包使用配置模板。协调服务负责房间配对、映射观测与信息交换，不承担游戏业务中继。

## 1. 准备

使用你有权限管理的服务器。安装 Python 与 `requirements.txt` 中的依赖，准备 TLS 证书和私钥。程序客户端使用证书 DER 内容的 SHA-256 指纹进行固定核对。

复制 `server-config.example.json` 为 `server-config.json`，填写：

- `listen_host`：服务器实际本地监听地址。模板为 `0.0.0.0`，避免使用源码中历史服务器地址的默认值。
- `lab_udp_base`：UDP 映射观测起始端口。
- `lab_control_port`：TLS 协调端口。
- `room_udp_port`：加密 UDP 房间端口。
- `mesh_window_seconds`：集中探测窗口，当前默认为 120。
- `access`：新生成的 32 字节共享密钥，编码为 64 位十六进制。不要使用模板全零值。

按配置与 `server.py` 的监听行为开放相应端口。观测服务使用从 `lab_udp_base` 开始的连续 8 个端口，每个同时监听 UDP 与 TCP；TLS 使用 `lab_control_port` 的 TCP 端口；房间 UDP 使用 `room_udp_port`。

## 2. 启动

```bash
python meshserver.py --config server-config.json --cert server-cert.pem --key server-key.pem
```

客户端需要管理员提供匹配的 `host`、端口、`access` 与 `pin`。可选 `control_tail_host` 为服务器 Tailscale 地址，留空则不用该协调路径。

用 Python 读取证书指纹：

```python
import hashlib, pathlib, ssl
pem = pathlib.Path("server-cert.pem").read_text()
print(hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest())
```

密钥可用 `secrets.token_hex(32)` 生成，并通过你自己的安全渠道交给授权成员。不要把真实 `server-config.json`、客户端配置、证书私钥或房间导出上传到公开仓库。

## 3. 兼容性

GUI 和多人客户端当前版本为 1.2.0。`meshserver.py` 的启动横幅仍保留 `v1.1.0` 历史字符串；版本判断以源码与客户端为准，不能只看该横幅。

MC 星形依赖当前的 `roomudp.py` 与 `meshplan.py`。更新协调服务时使用本发布的整套源码，不能只替换一个启动文件。

本次 GitHub 上传提供源码与模板，没有替你新建、替换或重启协调服务。你现有的私人配置仍单独管理。
