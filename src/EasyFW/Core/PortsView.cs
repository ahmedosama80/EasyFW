using System;
using System.Collections.Generic;
using System.Linq;

namespace EasyFW.Core
{
    /// <summary>A port this PC listens on, for one program.</summary>
    public sealed class ListeningPort
    {
        public string Protocol { get; set; }
        public int Port { get; set; }
        public int Pid { get; set; }
        public string ProcessName { get; set; }
        public string AppPath { get; set; }
        /// <summary>The addresses it's bound to, such as 0.0.0.0 and ::.</summary>
        public List<string> Binds { get; } = new List<string>();
        /// <summary>Bound only to loopback: nothing outside this PC can reach it.</summary>
        public bool LocalOnly => Binds.All(IpText.IsLoopback);
        public string ScopeText => LocalOnly ? "This PC only"
            : Binds.Any(b => b == "0.0.0.0" || b == "::" || b == "*") ? "All networks"
            : string.Join(", ", Binds.Where(b => !IpText.IsLoopback(b)));
        public string Service => PortNames.Name(Protocol, Port, ProcessName);
        /// <summary>Remote addresses connected to it now (TCP).</summary>
        public List<string> ConnectedNow { get; } = new List<string>();
        /// <summary>Remote addresses that tried it in the last hour, with how many tries were accepted and blocked.</summary>
        public Dictionary<string, PortVisitor> Visitors { get; } = new Dictionary<string, PortVisitor>(StringComparer.OrdinalIgnoreCase);
        public string Key => $"{Protocol}|{Port}|{Pid}";
    }

    public sealed class PortVisitor
    {
        public string Ip { get; set; }
        public int Accepted { get; set; }
        public int Blocked { get; set; }
        public bool ConnectedNow { get; set; }
        public DateTime LastUtc { get; set; }
    }

    public static class PortsView
    {
        /// <summary>
        /// Listening TCP ports and bound UDP ports, one row per program and port, with who's connected now and who tried in the last hour.
        /// </summary>
        public static List<ListeningPort> Build(IEnumerable<ActiveEndpoint> endpoints, IEnumerable<FirewallEvent> recent)
        {
            var all = (endpoints ?? Enumerable.Empty<ActiveEndpoint>()).ToList();
            var rows = new Dictionary<string, ListeningPort>();
            foreach (var e in all.Where(e => e.State == "Listening" || e.Protocol == "UDP" && e.State == "Bound"))
            {
                var key = $"{e.Protocol}|{e.LocalPort}|{e.Pid}";
                if (!rows.TryGetValue(key, out var row))
                    rows[key] = row = new ListeningPort { Protocol = e.Protocol, Port = e.LocalPort, Pid = e.Pid, ProcessName = e.ProcessName, AppPath = e.AppPath };
                var bind = string.IsNullOrEmpty(e.LocalIp) ? "*" : e.LocalIp;
                if (!row.Binds.Contains(bind)) row.Binds.Add(bind);
            }

            // Established connections whose local port is a listening port came in through it.
            var byPort = rows.Values.Where(r => r.Protocol == "TCP").GroupBy(r => r.Port).ToDictionary(g => g.Key, g => g.ToList());
            foreach (var c in all.Where(e => e.Protocol == "TCP" && e.State == "Established" && !IpText.IsLoopback(e.RemoteIp)))
            {
                if (!byPort.TryGetValue(c.LocalPort, out var owners)) continue;
                var owner = owners.FirstOrDefault(o => o.Pid == c.Pid) ?? owners[0];
                if (!owner.ConnectedNow.Contains(c.RemoteIp)) owner.ConnectedNow.Add(c.RemoteIp);
                Visit(owner, c.RemoteIp).ConnectedNow = true;
            }

            // Attempts the firewall saw coming in to these ports.
            var lookup = rows.Values.GroupBy(r => (r.Protocol, r.Port)).ToDictionary(g => g.Key, g => g.ToList());
            foreach (var ev in recent ?? Enumerable.Empty<FirewallEvent>())
            {
                if (ev.Direction != TrafficDirection.Inbound || string.IsNullOrEmpty(ev.RemoteIp) || IpText.IsLoopback(ev.RemoteIp)) continue;
                if (!lookup.TryGetValue((ev.Protocol, ev.LocalPort), out var owners)) continue;
                var owner = owners.FirstOrDefault(o => AppPaths.Same(o.AppPath, ev.AppPath)) ?? owners[0];
                var v = Visit(owner, ev.RemoteIp);
                if (ev.Verdict == Verdict.Blocked) v.Blocked++; else v.Accepted++;
                if (ev.TimeUtc > v.LastUtc) v.LastUtc = ev.TimeUtc;
            }
            return rows.Values.OrderBy(r => r.LocalOnly).ThenBy(r => r.Port).ThenBy(r => r.Protocol).ToList();
        }

        private static PortVisitor Visit(ListeningPort row, string ip)
        {
            if (!row.Visitors.TryGetValue(ip, out var v)) row.Visitors[ip] = v = new PortVisitor { Ip = ip };
            return v;
        }
    }

    /// <summary>What a well-known port is usually for.</summary>
    public static class PortNames
    {
        private static readonly Dictionary<int, string> Tcp = new Dictionary<int, string>
        {
            [20] = "FTP data", [21] = "FTP", [22] = "SSH", [23] = "Telnet", [25] = "SMTP mail", [53] = "DNS", [80] = "HTTP web", [110] = "POP3 mail",
            [135] = "Windows RPC", [139] = "NetBIOS file sharing", [143] = "IMAP mail", [389] = "LDAP", [443] = "HTTPS web", [445] = "SMB file sharing",
            [465] = "SMTPS mail", [587] = "SMTP mail", [636] = "LDAPS", [990] = "FTPS", [993] = "IMAPS mail", [995] = "POP3S mail", [1433] = "SQL Server",
            [1723] = "PPTP VPN", [2179] = "Hyper-V console", [3306] = "MySQL", [3389] = "Remote Desktop", [5040] = "Windows CDP", [5357] = "Network discovery (WSD)",
            [5432] = "PostgreSQL", [5800] = "VNC web", [5900] = "VNC", [5901] = "VNC", [5938] = "TeamViewer", [5985] = "WinRM", [5986] = "WinRM HTTPS",
            [6379] = "Redis", [7070] = "AnyDesk", [7680] = "Delivery Optimization", [8080] = "HTTP alt web", [8443] = "HTTPS alt web", [9100] = "Printer",
            [14147] = "FileZilla Server admin", [27017] = "MongoDB",
        };

        private static readonly Dictionary<int, string> Udp = new Dictionary<int, string>
        {
            [53] = "DNS", [67] = "DHCP server", [68] = "DHCP", [69] = "TFTP", [123] = "Time (NTP)", [137] = "NetBIOS names", [138] = "NetBIOS datagrams",
            [161] = "SNMP", [500] = "IPsec", [546] = "DHCPv6", [1194] = "OpenVPN", [1701] = "L2TP VPN", [1900] = "UPnP discovery (SSDP)", [3389] = "Remote Desktop",
            [3702] = "Device discovery (WSD)", [4500] = "IPsec NAT", [5050] = "Multimedia streaming", [5353] = "mDNS (Bonjour)", [5355] = "LLMNR name lookup",
            [51820] = "WireGuard VPN",
        };

        public static string Name(string protocol, int port, string process)
        {
            var table = protocol == "UDP" ? Udp : Tcp;
            if (table.TryGetValue(port, out var name)) return name;
            if (port >= 49152) return "Dynamic" + (IsSystemProcess(process) ? " (Windows RPC)" : "");
            return "";
        }

        private static bool IsSystemProcess(string process) =>
            new[] { "svchost.exe", "lsass.exe", "wininit.exe", "services.exe", "spoolsv.exe", "System" }.Contains(process ?? "", StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>A folder or printer this PC shares on the network.</summary>
    public sealed class ShareInfo
    {
        public string Name { get; set; }
        public string Path { get; set; }
        public string Description { get; set; }
        public string Type { get; set; }
        /// <summary>Windows' own shares such as C$ and ADMIN$, made for administrators.</summary>
        public bool IsAdmin { get; set; }
        public List<ShareUser> Users { get; } = new List<ShareUser>();
    }

    public sealed class ShareUser
    {
        public string Computer { get; set; }
        public string User { get; set; }
        public int Files { get; set; }
        public int Seconds { get; set; }
    }
}
