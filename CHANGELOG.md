# Changelog

## 3.0.0 (2026-11-21)

### New

- **Path and keyword rules:** accept or block every app in a folder (`C:\Games\*.*`, subfolders included), every path that matches a wildcard, or every path that contains a keyword such as `steam`. An app with its own rule keeps it. A matching app gets its own rule the first time it tries to connect. Accept only goes to apps with a valid digital signature: an unsigned app stays in Pending requests for you to decide.
- **App log:** right-click an app in any list and choose **Show log (last hour)** to see every connection it made or tried in the last hour.
- **Internet columns:** the rules list shows whether each app is allowed on the internet, and whether it has tried to reach the internet. Pending requests show the second one.
- **Signed column:** shows whether each app has a valid digital signature and who signed it, including Windows programs signed through a catalog. The check works offline.
- **Full text on hover:** rest the mouse on a cell that's too narrow, and its full text appears.
- **World Map tab:** a live map of where your traffic goes and comes from, with outgoing, incoming and blocked arcs drawn from your PC to each country, and moving dots for connections that are open now. Hover over a country to see its numbers and apps. Drag the timeline to look back up to 30 minutes, and pick how many minutes to show. Right-click the map to set your location. The map ships with EasyFW and works offline.
- **Block countries:** block all traffic to and from whole countries, for every app, including apps you accepted. Use **Options > Blocked countries...**, or right-click a country on the World Map. Open connections to them are closed.
- **Bandwidth tab:** live data rates for the whole PC, the internet and the LAN, down and up. A graph shows the last 2 or 10 minutes, and the table shows every app's rates, split into internet and LAN, and the data it has sent and received. The status bar shows the rates on every tab. The rates come from Windows' own network events and need EasyFW to run as administrator.
- **LAN now means your own networks:** everywhere in EasyFW (rules, columns, the map, the highlight on pending requests), LAN is the subnets of this PC's connected Ethernet and Wi-Fi adapters, plus link-local, broadcast and multicast. Virtual, VPN and Bluetooth adapters don't count. It follows the network you're on, and rules with LAN limits are rebuilt when it changes. Private addresses reached another way, such as through a VPN, count as internet. Blocklists still take only true public addresses.
- **Ports & Shares tab:**
  - **Open ports:** every port this PC listens on, with:
    - the program and its service, such as Remote Desktop or file sharing;
    - whether it listens on all networks or only this PC;
    - whether the firewall lets other devices reach it;
    - who is connected now;
    - who tried in the last hour.
  - **Who connected:** pick a port to see every address that connected or tried, with host, country, and accepted and blocked counts.
  - **Shared folders:** every share, with who's using it right now and whether file sharing can be reached from the network. Right-click to open the folder, copy its path or stop sharing it.
- **Blocklists of bad addresses:** **Options > Blocklists of bad addresses...** blocks every address on the lists you tick, for every app: Spamhaus DROP, FireHOL Level 1, abuse.ch Feodo Tracker (botnet servers) and Emerging Threats compromised hosts. EasyFW downloads them once a day, keeps a copy so they work offline, and takes only public internet addresses from them, so the local network is never blocked. You can list addresses never to block. Connections has a **Blocklist** column, and you get a notice when an app tries a listed address.
- **Lockdown:** one button, in the main window or the tray menu, blocks every app except the ones you choose. Your rules don't change, and **End lockdown** puts everything back.
- **Hours for apps:** an accepted app can be limited to certain days and times, for example games only on weekends from 10:00 to 20:00. Outside its hours it's blocked and its open connections are closed. Times can run past midnight. The rules list has **Hours** and **In lockdown** columns.
- **Password protection (optional):** **Options > Password protection...** sets a password. EasyFW then asks for it before protection is turned off, before it exits, before rules or options change, and before a lockdown ends or a country is unblocked. One entry is good for 5 minutes.
- **Flood alerts:** a tray warning when traffic suddenly jumps to several times the usual, when one app opens a flood of connections, or when one address knocks on this PC many times, as in a port scan. **Options > Alert on traffic floods** turns them off.
- **Automatic updates:** EasyFW asks once whether to keep itself up to date. If you agree, it checks the latest release on GitHub once a day. When there's a newer one, it downloads it, checks the size, the checksum and the version, installs it and restarts, and protection stays on. If anything fails, the old files go back. **Options > Automatic updates from GitHub** turns it on or off, and **Check for updates now...** checks straight away.
- **Rules for a while:** accept or block an app forever, until Windows restarts, or for 10 minutes, 30 minutes or 1 hour. Pending requests has a **Keep** list next to the buttons, Connections and Top Connections have **Accept for a while** and **Block for a while** when you right-click, and the rule editor has **Keep**. The rules list shows when each rule ends. When the time is up, the rule is deleted, a notice says so, and the app asks again.
- **Your public IP** shows beside "Protection is on", with its country. Click it to copy it, check it again or set your location. EasyFW asks api.ipify.org (with two backups) over HTTPS, checks again every 15 minutes and when the network changes, and has its own allow rule for this, outgoing HTTPS only. **Options > Show my public IP** turns it off, rule included.
- **Your location on the map** comes from your public IP's country. You can pick a country and city instead, and if EasyFW can't tell, it asks.
- **Copy path:** right-click an app in any list to copy its full path.
- **Sort pending requests:** click any column header in Pending requests to sort by it, and click again to reverse.
- **LAN requests stand out:** a pending request from or to the local network has a light blue background.
- **Your own column layout:** drag a column header to move it. The order and widths of every list are kept, and **Options > Reset column layout** puts them back.

### Fixed

- The window could lag or seem to hang on a busy PC. The rules lists were rebuilt every second, even while hidden, which reset their scrolling. They now update only when they're showing, and only the cells that changed.
- Internet and LAN limits were worked out again for every open connection, every second. They're now worked out once.
- A list refresh could fail over and over while the window was minimized.

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
