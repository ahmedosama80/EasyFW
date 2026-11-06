using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using EasyFW.Core;

namespace EasyFW.Platform
{
    /// <summary>Watches the Security log live. Reading that log requires administrator rights.</summary>
    public sealed class SecurityLogEventSource : IEventSource
    {
        private EventLogWatcher _watcher;

        public void Start(Action<FirewallEvent> sink)
        {
            var query = new EventLogQuery("Security", PathType.LogName, "*[System[(EventID=5156 or EventID=5157)]]");
            _watcher = new EventLogWatcher(query);
            _watcher.EventRecordWritten += (_, e) =>
            {
                if (e.EventRecord == null)
                {
                    if (e.EventException != null) Log.Write("Event watcher error: " + e.EventException.Message);
                    return;
                }
                using (e.EventRecord)
                {
                    var values = e.EventRecord.Properties.Select(p => p.Value).ToList();
                    var time = e.EventRecord.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow;
                    var parsed = FirewallEventParser.Parse(e.EventRecord.Id, values, time, DevicePaths.ToDosPath);
                    if (parsed != null) sink(parsed);
                }
            };
            _watcher.Enabled = true;
        }

        public void Stop()
        {
            if (_watcher == null) return;
            _watcher.Enabled = false;
            _watcher.Dispose();
            _watcher = null;
        }
    }

    /// <summary>Audit events carry NT device paths; rules and the UI need drive-letter paths.</summary>
    public static class DevicePaths
    {
        private static readonly Lazy<Dictionary<string, string>> Map = new Lazy<Dictionary<string, string>>(Build);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint QueryDosDevice(string device, StringBuilder target, int max);

        private static Dictionary<string, string> Build()
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var drive in Directory.GetLogicalDrives())
            {
                var letter = drive.Substring(0, 2);
                var sb = new StringBuilder(512);
                if (QueryDosDevice(letter, sb, sb.Capacity) != 0) map[sb.ToString()] = letter;
            }
            return map;
        }

        public static string ToDosPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || path == "-") return "";
            if (path.Equals(AppPaths.SystemApp, StringComparison.OrdinalIgnoreCase)) return AppPaths.SystemApp;
            return Convert(path, Map.Value);
        }

        public static string Convert(string path, IDictionary<string, string> map)
        {
            foreach (var kv in map)
            {
                if (path.Length > kv.Key.Length && path[kv.Key.Length] == '\\'
                    && path.StartsWith(kv.Key, StringComparison.OrdinalIgnoreCase))
                    return kv.Value + path.Substring(kv.Key.Length);
            }
            return path;
        }
    }

    /// <summary>Maps PIDs to names and paths, cached because the connection table is polled every second.</summary>
    public sealed class ProcessInfoCache
    {
        private sealed class Item
        {
            public string Name, Path;
            public DateTime ExpiresUtc;
        }

        private readonly Dictionary<int, Item> _items = new Dictionary<int, Item>();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder name, ref int size);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        private const uint QueryLimitedInformation = 0x1000;

        public void Resolve(int pid, out string name, out string path)
        {
            var now = DateTime.UtcNow;
            if (!_items.TryGetValue(pid, out var item) || item.ExpiresUtc < now)
            {
                item = Lookup(pid);
                item.ExpiresUtc = now.AddSeconds(30);
                _items[pid] = item;
            }
            name = item.Name;
            path = item.Path;
        }

        private static Item Lookup(int pid)
        {
            if (pid == 0) return new Item { Name = "(no process)", Path = "" };
            if (pid == 4) return new Item { Name = AppPaths.DisplayName(AppPaths.SystemApp), Path = AppPaths.SystemApp };
            var path = ImagePath(pid);
            if (string.IsNullOrEmpty(path)) path = DevicePaths.ToDosPath(ImagePathWithoutHandle(pid));
            if (!string.IsNullOrEmpty(path)) return new Item { Name = Path.GetFileName(path), Path = path };
            try
            {
                using var p = Process.GetProcessById(pid);
                return new Item { Name = p.ProcessName + ".exe", Path = "" };
            }
            catch (Exception ex) when (ex is ArgumentException || ex is InvalidOperationException)
            {
                return new Item { Name = "PID " + pid, Path = "" };
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessIdInformation
        {
            public IntPtr ProcessId;
            public ushort Length, MaximumLength;
            public IntPtr Buffer;
        }

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(int infoClass, ref ProcessIdInformation info, int size, out int returned);

        private const int SystemProcessIdInformation = 88;

        /// <summary>
        /// Works for protected processes such as antivirus services, which refuse to be opened.
        /// Without this their connections have no program, so no rule could apply to them.
        /// </summary>
        /// <returns>The path in device form (\Device\HarddiskVolume3\...), or null.</returns>
        public static string ImagePathWithoutHandle(int pid)
        {
            const int bytes = 4096;
            var buffer = Marshal.AllocHGlobal(bytes);
            try
            {
                var info = new ProcessIdInformation { ProcessId = new IntPtr(pid), MaximumLength = bytes, Buffer = buffer };
                if (NtQuerySystemInformation(SystemProcessIdInformation, ref info, Marshal.SizeOf(info), out _) != 0) return null;
                return Marshal.PtrToStringUni(buffer, info.Length / 2);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private static string ImagePath(int pid)
        {
            var handle = OpenProcess(QueryLimitedInformation, false, pid);
            if (handle == IntPtr.Zero) return null;
            try
            {
                var size = 1024;
                var sb = new StringBuilder(size);
                return QueryFullProcessImageName(handle, 0, sb, ref size) ? sb.ToString() : null;
            }
            finally { CloseHandle(handle); }
        }
    }

    /// <summary>Reads the OS TCP and UDP tables, which work without administrator rights.</summary>
    public sealed class ActiveConnectionReader
    {
        private const int AfInet = 2, AfInet6 = 23;
        private const int TcpTableOwnerPidAll = 5, UdpTableOwnerPid = 1;
        private const int ErrorInsufficientBuffer = 122;

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int GetExtendedTcpTable(IntPtr table, ref int size, bool order, int family, int cls, int reserved);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int GetExtendedUdpTable(IntPtr table, ref int size, bool order, int family, int cls, int reserved);

        private delegate int TableFn(IntPtr table, ref int size, bool order, int family, int cls, int reserved);

        [StructLayout(LayoutKind.Sequential)]
        private struct TcpRow
        {
            public int State, LocalAddr, LocalPort, RemoteAddr, RemotePort;
        }

        [DllImport("iphlpapi.dll")]
        private static extern int SetTcpEntry(ref TcpRow row);

        private const int TcpStateDeleteTcb = 12;

        /// <summary>Closes an open connection. Needs elevation. Windows has no equivalent for IPv6, so those return false.</summary>
        public static bool CloseTcp(ActiveEndpoint e)
        {
            if (!IPAddress.TryParse(e.LocalIp, out var local) || !IPAddress.TryParse(e.RemoteIp, out var remote)) return false;
            if (local.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
                || remote.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;
            var row = new TcpRow
            {
                State = TcpStateDeleteTcb,
                LocalAddr = BitConverter.ToInt32(local.GetAddressBytes(), 0),
                LocalPort = Port(e.LocalPort),
                RemoteAddr = BitConverter.ToInt32(remote.GetAddressBytes(), 0),
                RemotePort = Port(e.RemotePort)
            };
            return SetTcpEntry(ref row) == 0;
        }

        private static readonly string[] TcpStates =
        {
            "", "Closed", "Listening", "SYN sent", "SYN received", "Established", "FIN wait 1", "FIN wait 2",
            "Close wait", "Closing", "Last ACK", "Time wait", "Delete"
        };

        private readonly ProcessInfoCache _processes = new ProcessInfoCache();

        public List<ActiveEndpoint> Read()
        {
            var raw = new List<ActiveEndpoint>();
            ReadTable(GetExtendedTcpTable, AfInet, TcpTableOwnerPidAll, 24, ParseTcp4, raw);
            ReadTable(GetExtendedTcpTable, AfInet6, TcpTableOwnerPidAll, 56, ParseTcp6, raw);
            ReadTable(GetExtendedUdpTable, AfInet, UdpTableOwnerPid, 12, ParseUdp4, raw);
            ReadTable(GetExtendedUdpTable, AfInet6, UdpTableOwnerPid, 28, ParseUdp6, raw);

            var listening = new HashSet<int>(raw.Where(x => x.State == "Listening").Select(x => x.LocalPort));
            foreach (var e in raw)
            {
                _processes.Resolve(e.Pid, out var name, out var path);
                e.ProcessName = name;
                e.AppPath = path;
                // The tables don't record who connected; a port we listen on implies an inbound connection.
                e.Direction = e.Protocol == "TCP" && !listening.Contains(e.LocalPort) ? TrafficDirection.Outbound
                    : e.State == "Bound" ? TrafficDirection.Unknown
                    : TrafficDirection.Inbound;
            }
            return raw;
        }

        private static void ReadTable(TableFn fn, int family, int cls, int rowSize, Func<IntPtr, ActiveEndpoint> parse, List<ActiveEndpoint> into)
        {
            var size = 0;
            var result = fn(IntPtr.Zero, ref size, false, family, cls, 0);
            if (result != ErrorInsufficientBuffer) return;
            // The table can grow between the size query and the read, so leave headroom.
            size += rowSize * 16;
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                result = fn(buffer, ref size, false, family, cls, 0);
                if (result != 0)
                {
                    Log.Write("Connection table read failed: " + new Win32Exception(result).Message);
                    return;
                }
                var count = Marshal.ReadInt32(buffer);
                // Rows start after a DWORD count; IPv4 rows are DWORD aligned, and IPv6 rows are too.
                var row = IntPtr.Add(buffer, 4);
                for (var i = 0; i < count; i++, row = IntPtr.Add(row, rowSize)) into.Add(parse(row));
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        public static int Port(int raw) => ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF);

        private static string Ip4(IntPtr p, int offset) =>
            new IPAddress(BitConverter.GetBytes(Marshal.ReadInt32(p, offset))).ToString();

        private static string Ip6(IntPtr p, int offset)
        {
            var bytes = new byte[16];
            Marshal.Copy(IntPtr.Add(p, offset), bytes, 0, 16);
            return new IPAddress(bytes).ToString();
        }

        private static string State(int state) => state > 0 && state < TcpStates.Length ? TcpStates[state] : "Unknown";

        private static ActiveEndpoint ParseTcp4(IntPtr p)
        {
            var state = State(Marshal.ReadInt32(p, 0));
            var listen = state == "Listening";
            return new ActiveEndpoint
            {
                Protocol = "TCP", State = state,
                LocalIp = Ip4(p, 4), LocalPort = Port(Marshal.ReadInt32(p, 8)),
                RemoteIp = listen ? "*" : Ip4(p, 12), RemotePort = listen ? 0 : Port(Marshal.ReadInt32(p, 16)),
                Pid = Marshal.ReadInt32(p, 20)
            };
        }

        private static ActiveEndpoint ParseTcp6(IntPtr p)
        {
            var state = State(Marshal.ReadInt32(p, 48));
            var listen = state == "Listening";
            return new ActiveEndpoint
            {
                Protocol = "TCP", State = state,
                LocalIp = Ip6(p, 0), LocalPort = Port(Marshal.ReadInt32(p, 20)),
                RemoteIp = listen ? "*" : Ip6(p, 24), RemotePort = listen ? 0 : Port(Marshal.ReadInt32(p, 44)),
                Pid = Marshal.ReadInt32(p, 52)
            };
        }

        private static ActiveEndpoint ParseUdp4(IntPtr p) => new ActiveEndpoint
        {
            Protocol = "UDP", State = "Bound", RemoteIp = "*",
            LocalIp = Ip4(p, 0), LocalPort = Port(Marshal.ReadInt32(p, 4)), Pid = Marshal.ReadInt32(p, 8)
        };

        private static ActiveEndpoint ParseUdp6(IntPtr p) => new ActiveEndpoint
        {
            Protocol = "UDP", State = "Bound", RemoteIp = "*",
            LocalIp = Ip6(p, 0), LocalPort = Port(Marshal.ReadInt32(p, 20)), Pid = Marshal.ReadInt32(p, 24)
        };
    }

    public sealed class ServiceStatusRow
    {
        public string ServiceName { get; set; }
        public string DisplayName { get; set; }
        public string Status { get; set; }
        public bool IsRunning { get; set; }
    }

    /// <summary>The Windows services that Windows Firewall, and so EasyFW, depends on.</summary>
    public static class WindowsServiceInfo
    {
        public static readonly (string Service, string Display)[] FirewallServices =
        {
            ("MpsSvc", "Windows Defender Firewall"),
            ("BFE", "Base Filtering Engine")
        };

        public static List<ServiceStatusRow> ReadFirewallServices() =>
            FirewallServices.Select(s => Read(s.Service, s.Display)).ToList();

        public static ServiceStatusRow Read(string serviceName, string fallbackDisplayName)
        {
            try
            {
                using var controller = new System.ServiceProcess.ServiceController(serviceName);
                var status = controller.Status;
                return new ServiceStatusRow
                {
                    ServiceName = serviceName, DisplayName = controller.DisplayName, Status = status.ToString(),
                    IsRunning = status == System.ServiceProcess.ServiceControllerStatus.Running
                };
            }
            catch (InvalidOperationException)
            {
                return new ServiceStatusRow { ServiceName = serviceName, DisplayName = fallbackDisplayName, Status = "Not found" };
            }
        }
    }

    /// <summary>Logon task that starts EasyFW elevated with no UAC prompt.</summary>
    public static class AutoStart
    {
        private const string TaskName = "EasyFW";
        private const string LegacyTaskName = "HomeFW";

        private static int Run(string args)
        {
            using var p = Process.Start(new ProcessStartInfo("schtasks.exe", args)
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
            });
            p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            p.WaitForExit();
            return p.ExitCode;
        }

        public static bool IsEnabled => Run($"/Query /TN {TaskName}") == 0;

        public static void Set(bool enabled, string exePath)
        {
            var args = enabled
                ? $"/Create /F /RL HIGHEST /SC ONLOGON /TN {TaskName} /TR \"\\\"{exePath}\\\" --tray\""
                : $"/Delete /F /TN {TaskName}";
            var code = Run(args);
            if (code != 0) throw new InvalidOperationException($"schtasks failed with exit code {code}.");
        }

        /// <summary>A task from when the app was called HomeFW points at an exe that's gone, so logon would silently start no firewall.</summary>
        public static void MoveLegacyTask(string exePath)
        {
            if (Run($"/Query /TN {LegacyTaskName}") != 0) return;
            Set(true, exePath);
            Run($"/Delete /F /TN {LegacyTaskName}");
        }

        /// <summary>The task runs elevated, so its exe must not sit where ordinary programs can replace it.</summary>
        public static bool IsInProtectedFolder(string exePath)
        {
            foreach (var folder in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 })
            {
                var root = Environment.GetFolderPath(folder);
                if (root.Length > 0 && exePath.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }
    }
}
