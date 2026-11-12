using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace EasyFW.Core
{
    public static class AppPaths
    {
        public const string SystemApp = "System";
        /// <summary>Stands in for "any app" on ping rules. Windows logs pings under System, so they can't be tied to a program.</summary>
        public const string PingApp = "Ping (ICMP)";

        public static string RuleTarget(string path, string protocol) =>
            path == SystemApp && (protocol ?? "").StartsWith("ICMP", StringComparison.OrdinalIgnoreCase) ? PingApp : path;

        public static string Normalize(string path)
        {
            path = (path ?? "").Trim().Trim('"');
            return Same(path, SystemApp) ? SystemApp : Same(path, PingApp) ? PingApp : path;
        }

        /// <summary>A rule's app that isn't a file on disk.</summary>
        public static bool IsPseudoApp(string path) => Same(path, SystemApp) || Same(path, PingApp);

        public static bool IsRuleTarget(string path)
        {
            if (IsPseudoApp(path)) return true;
            try { return path != null && path.Length > 2 && Path.IsPathRooted(path); }
            catch (ArgumentException) { return false; }
        }

        public static string DisplayName(string path)
        {
            if (string.IsNullOrEmpty(path)) return "(unknown)";
            if (path == SystemApp) return "Windows System";
            if (path == PingApp) return PingApp;
            try { return Path.GetFileName(path); } catch (ArgumentException) { return path; }
        }

        public static bool Same(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

        public static bool IsSharedServiceHost(string path) =>
            !string.IsNullOrEmpty(path) && path.EndsWith("\\svchost.exe", StringComparison.OrdinalIgnoreCase);
    }

    public static class AppInfo
    {
        public const string NonCommercial = "THIS IS FOR NON-COMMERCIAL USE ONLY";
        public const string Developer = "Ahmed Osama Mohamed";
        public const string Email = "ahmed_osama@hotmail.com";
        /// <summary>From the build, as major.minor.patch. The informational version can carry a commit hash, so it isn't used.</summary>
        public static readonly string Version = typeof(AppInfo).Assembly.GetName().Version.ToString(3);
        public const string Brief = "A simple firewall built on Windows Firewall. It blocks all network traffic until you approve each app, on all ports or only the ones you choose, and shows live connections.";
    }

    public static class IpText
    {
        public static string Normalize(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return "";
            var i = ip.IndexOf('%');
            if (i > 0) ip = ip.Substring(0, i);
            return IPAddress.TryParse(ip, out var a) ? a.ToString() : ip;
        }

        public static bool IsLoopback(string ip) =>
            IPAddress.TryParse(ip ?? "", out var a) && IPAddress.IsLoopback(a);

        /// <summary>Key that orders IPs numerically; string order would put 10.x before 9.x.</summary>
        public static string SortKey(string ip)
        {
            if (!IPAddress.TryParse(ip ?? "", out var a)) return "z" + ip;
            var sb = new StringBuilder(a.AddressFamily == AddressFamily.InterNetworkV6 ? "b" : "a");
            foreach (var b in a.GetAddressBytes()) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }
    }

    /// <summary>Minimal log for faults the UI can't show. Never throws.</summary>
    public static class Log
    {
        private static readonly object Gate = new object();
        public static string FilePath { get; set; } = Path.Combine(Path.GetTempPath(), "EasyFW.log");

        public static void Write(string message)
        {
            try
            {
                lock (Gate)
                {
                    var f = new FileInfo(FilePath);
                    if (f.Exists && f.Length > 1024 * 1024) f.Delete();
                    File.AppendAllText(FilePath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {message}{Environment.NewLine}");
                }
            }
            catch (Exception) { }
        }
    }
}
