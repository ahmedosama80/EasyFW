# Changelog

## 1.1.0 (2026-11-12)

### New

- **Top Connections tab:** the busiest traffic, grouped by app, direction, remote address and destination port. It counts accepted and blocked connections over the last 10 minutes, 30 minutes or hour. You can rank by total, blocked or accepted. Right-click a row to accept or block its app.
- **Internet and LAN per app:** an Accept Always rule can turn off internet access, and allow all of the LAN, only the subnets you tick, or no LAN. The subnet list shows this PC's networks, and you can add your own.
- **Host names:** every IP column has a host name next to it, from reverse DNS, looked up in the background.
- **Countries:** every remote IP shows its country with a flag. The data comes from the free DB-IP database, which ships with EasyFW, so no address leaves the PC.
- **Choice on exit:** Exit asks whether to turn protection off or to keep blocking while EasyFW is closed.
- **Version number** under the shield in the main window, in the title bar and in the About box.
- **Exit button** in the main window, next to About. It asks the same question as Exit in the tray menu.

### Changed

- The rules list has a **Network** column.
- **Pause updates** is a button on Connections, and Top Connections has one too. It stays pressed while the list is paused.
- Open connections that break a rule's internet or LAN limits are closed, the same way as connections on a blocked port.
- The About box credits DB-IP and the flag icons. See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## 1.0.0 (2026-11-06)

First release.
