# NATPair Mesh — UDP Hole Punching for Tailscale and Minecraft Java

[简体中文](README.md) · English

**NATPair Mesh 1.2.0** is a Windows UDP hole punching and NAT traversal helper for **Tailscale** and **Minecraft Java LAN multiplayer**. Connect up to 8 peers in a mesh, or use a host-star room for one Minecraft host and up to seven players. Coordination is self-hosted; a working server configuration is required.

[Download Windows x64](https://github.com/endlessmaybe/natpair/releases/latest) · [User guide, Chinese](docs/USER_GUIDE.md) · [Server setup, Chinese](docs/SERVER_SETUP.md) · [Report an issue](https://github.com/endlessmaybe/natpair/issues)

## What it does

| Use case | Behavior |
| --- | --- |
| Minecraft Java remote LAN play | A host-star room publishes the host's Tailscale address and game port. Eight members need 7 assisted pairs instead of a full mesh's 28. |
| Assisted peer-to-peer connectivity | Attempts IPv4 UDP hole punching for pairs that need help; preserves verified native Tailscale IPv6 / IPv4 paths. |
| Multiplayer mesh | Up to 8 members; schedules non-conflicting pairs and retains progress while waiting for another round. |
| Recovery and diagnostics | Independent pair sessions, authenticated UDP checks, separate Tailscale data-path validation and evidence export. |
| Controlled probing | Default coexistence profile limits probing bursts and new combinations, with existing traffic and keepalives prioritized. |
| UDP-only experiments | Observe hole punching without Tailscale integration; this mode is not a standalone VPN or game tunnel. |

Fewer assisted pairs do not guarantee a proportional speedup. The tool does not guarantee connectivity across every NAT, CGNAT, router or ISP.

## Requirements

- Windows x64 for the packaged client; extract the complete archive. Python is not required for the Windows release.
- Your own compatible coordination server configuration, supplied by its administrator or created through [self-hosted setup](docs/SERVER_SETUP.md). The public package contains a template, not access to a public service.
- Tailscale installed, running and authorized on each participating device for game / Tailscale modes. This project does not extend Tailscale account or device entitlements.
- Administrator privileges for the Windows Tailscale integration using WinDivert; a working Minecraft Java world or server for game rooms.
- A network that permits the required UDP traffic. Mobile or unstable mappings can prevent assisted IPv4 connections; usable native IPv6 paths are retained.

## Quick start on Windows

1. Download `NATPair-Mesh-v1.2.0-Windows-x64-Public.zip` from [Releases](https://github.com/endlessmaybe/natpair/releases/latest), and extract it to a writable folder. Keep `NATPairMesh.exe`, `config.json` and all of `_internal` together.
2. Replace the template configuration with the one supplied by your server administrator. All room members must use a compatible coordination service; the room code is not the service access key.
3. Log in to the same authorized Tailscale network, then run `NATPairMesh.exe` as administrator for Tailscale integration.
4. Choose full mesh or **MC host-star** mode, and join using the same room code. All members must choose the same room type; a star room permits one host.
5. Check the actual validation status. In Minecraft Java, players paste the published `Tailscale-address:game-port` into **Multiplayer → Direct Connection**.

For a Minecraft LAN world, the host must enter the port shown by the game's current **Open to LAN** session. A dedicated server commonly uses `25565`, but use its actual configured port. NATPair does not launch Minecraft, open arbitrary game ports or relay arbitrary traffic through the host.

Read the [network conditions and existing usage guidance](docs/NETWORK_AND_DISCLAIMER.md) before probing. Probing can temporarily affect other traffic; use only networks you administer or have permission to test. Review your application-specific inbound permissions and network configuration when troubleshooting.

## Frequently asked questions

### Does this replace Tailscale or provide TCP hole punching?

No. Game integration uses Tailscale, including its authorization. Minecraft TCP traffic is carried by the Tailscale UDP tunnel. NATPair's assisted channel is IPv4 UDP; there is no independent public TCP hole-punching engine or public relay service.

### Does it always remove DERP relay usage?

No. An authenticated outer UDP channel and a verified Tailscale data path are reported separately. A working Tailscale native or relay path may remain in use while the assisted path is being tested. Native IPv6 preference preserves a verified Tailscale path rather than adding a separate IPv6 hole-punching engine.

### Why does the downloaded configuration fail to connect?

The public configuration is a template. Obtain your own server's address, ports, certificate fingerprint and access key. See [server deployment](docs/SERVER_SETUP.md); do not publish real configuration, room exports, keys or private logs in an issue.

### Which platforms and game editions are supported?

The current packaged client is Windows x64, and its game-specific workflow targets Minecraft **Java Edition**. Android, iOS and macOS native client packages are not included. Do not assume Bedrock Edition support from the Minecraft topic.

## Source, tests and license status

The GUI uses Python / Tkinter. Development dependencies are pinned in `requirements.txt`; see the [development guide](docs/DEVELOPMENT.md) for source execution and packaging.

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s . -p 'test_*.py'
```

The published [validation record](docs/VALIDATION.md) describes the 49-test Mesh suite and its limits. Local tests do not establish long-term connectivity among eight real networks or replace real Minecraft / Tailscale acceptance tests.

WinDivert license materials and corresponding source are retained in `driver/`. NATPair's own source has no additional project-wide open-source license grant; public hosting alone does not establish one.
