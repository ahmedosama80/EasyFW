using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using EasyFW.Core;

namespace EasyFW.Platform
{
    /// <summary>
    /// Reads every TCP and UDP send and receive from Windows' "Microsoft-Windows-Kernel-Network" events (ETW), with the process and
    /// remote address, and feeds the sizes to a <see cref="BandwidthMeter"/>. Needs administrator rights. The session is named, so one
    /// left behind by a crash is stopped and replaced at the next start.
    /// </summary>
    public sealed class NetTrace : IDisposable
    {
        public const string SessionName = "EasyFW-Network";
        private static readonly Guid KernelNetwork = new Guid("7DD42A49-5329-4832-8DFD-43D979153A88");

        // Event ids of Microsoft-Windows-Kernel-Network: TCP and UDP data sent and received, IPv4 and IPv6.
        private const ushort TcpSend4 = 10, TcpRecv4 = 11, TcpSend6 = 26, TcpRecv6 = 27, UdpSend4 = 42, UdpRecv4 = 43, UdpSend6 = 58, UdpRecv6 = 59;

        private const uint WnodeFlagTracedGuid = 0x00020000, RealTimeMode = 0x00000100, StopControl = 1;
        private const uint ProcessTraceModeRealTime = 0x00000100, ProcessTraceModeEventRecord = 0x10000000;
        private const int PropertiesSize = 120, NameSpace = 1024, LogFileSize = 448;
        private const int ErrorAlreadyExists = 183;

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void EventRecordCallback(IntPtr record);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int StartTraceW(out ulong handle, string name, IntPtr properties);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int ControlTraceW(ulong handle, string name, IntPtr properties, uint control);

        [DllImport("advapi32.dll")]
        private static extern int EnableTraceEx2(ulong handle, ref Guid provider, uint control, byte level, ulong matchAny, ulong matchAll, uint timeout, IntPtr parameters);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern ulong OpenTraceW(IntPtr logFile);

        [DllImport("advapi32.dll")]
        private static extern int ProcessTrace(ulong[] handles, uint count, IntPtr start, IntPtr end);

        [DllImport("advapi32.dll")]
        private static extern int CloseTrace(ulong handle);

        private readonly BandwidthMeter _meter;
        private readonly EventRecordCallback _callback;
        private ulong _session, _trace = ulong.MaxValue;
        private IntPtr _logFile, _loggerName;
        private Thread _thread;
        private HashSet<string> _local = new HashSet<string>();
        private int _disposed;

        public NetTrace(BandwidthMeter meter)
        {
            _meter = meter;
            _callback = OnEvent;
        }

        /// <summary>Starts reading. On failure the meter's <see cref="BandwidthMeter.Problem"/> says why, and nothing else changes.</summary>
        public void Start()
        {
            if (IntPtr.Size != 8)
            {
                _meter.Problem = "Data rates need the 64-bit version of Windows.";
                return;
            }
            RefreshLocalAddresses();
            System.Net.NetworkInformation.NetworkChange.NetworkAddressChanged += OnAddressChanged;
            var error = StartSession();
            if (error == ErrorAlreadyExists)
            {
                Stop(SessionName);
                error = StartSession();
            }
            if (error != 0)
            {
                _meter.Problem = $"Windows didn't start the network event session (error {error}). Data rates need EasyFW to run as administrator.";
                Log.Write("Network trace: " + _meter.Problem);
                return;
            }
            // Keywords 0x10 and 0x20: the IPv4 and IPv6 events. Level 4: information.
            var provider = KernelNetwork;
            error = EnableTraceEx2(_session, ref provider, 1, 4, 0x30, 0, 0, IntPtr.Zero);
            if (error != 0)
            {
                _meter.Problem = $"Windows didn't turn on its network events (error {error}).";
                Log.Write("Network trace: " + _meter.Problem);
                Stop(SessionName);
                return;
            }

            _loggerName = Marshal.StringToHGlobalUni(SessionName);
            _logFile = Marshal.AllocHGlobal(LogFileSize);
            Zero(_logFile, LogFileSize);
            Marshal.WriteIntPtr(_logFile, 8, _loggerName);                                       // LoggerName
            Marshal.WriteInt32(_logFile, 28, unchecked((int)(ProcessTraceModeRealTime | ProcessTraceModeEventRecord)));
            Marshal.WriteIntPtr(_logFile, 424, Marshal.GetFunctionPointerForDelegate(_callback)); // EventRecordCallback
            _trace = OpenTraceW(_logFile);
            if (_trace == ulong.MaxValue)
            {
                _meter.Problem = $"Windows didn't open the network event session (error {Marshal.GetLastWin32Error()}).";
                Log.Write("Network trace: " + _meter.Problem);
                Stop(SessionName);
                return;
            }
            _thread = new Thread(() =>
            {
                // Blocks until the session stops.
                var result = ProcessTrace(new[] { _trace }, 1, IntPtr.Zero, IntPtr.Zero);
                if (result != 0 && Volatile.Read(ref _disposed) == 0) Log.Write("Network trace ended: error " + result);
                _meter.Running = false;
            }) { IsBackground = true, Name = "EasyFW network events" };
            _thread.Start();
            _meter.Running = true;
            _meter.Problem = null;
            Log.Write("Network trace started: data rates per app are on.");
        }

        private int StartSession()
        {
            var props = Properties();
            try { return StartTraceW(out _session, SessionName, props); }
            finally { Marshal.FreeHGlobal(props); }
        }

        private static IntPtr Properties()
        {
            var size = PropertiesSize + NameSpace * 2;
            var p = Marshal.AllocHGlobal(size);
            Zero(p, size);
            Marshal.WriteInt32(p, 0, size);                                     // Wnode.BufferSize
            Marshal.WriteInt32(p, 40, 1);                                       // Wnode.ClientContext: QPC clock
            Marshal.WriteInt32(p, 44, unchecked((int)WnodeFlagTracedGuid));     // Wnode.Flags
            Marshal.WriteInt32(p, 48, 64);                                      // BufferSize, KB
            Marshal.WriteInt32(p, 52, 4);                                       // MinimumBuffers
            Marshal.WriteInt32(p, 56, 64);                                      // MaximumBuffers
            Marshal.WriteInt32(p, 64, unchecked((int)RealTimeMode));            // LogFileMode
            Marshal.WriteInt32(p, 68, 1);                                       // FlushTimer, seconds
            Marshal.WriteInt32(p, 116, PropertiesSize);                         // LoggerNameOffset
            return p;
        }

        private static void Stop(string name)
        {
            var props = Properties();
            try { ControlTraceW(0, name, props, StopControl); }
            finally { Marshal.FreeHGlobal(props); }
        }

        private static void Zero(IntPtr p, int size)
        {
            for (var i = 0; i < size; i += 8)
                if (size - i >= 8) Marshal.WriteInt64(p, i, 0); else for (var j = i; j < size; j++) Marshal.WriteByte(p, j, 0);
        }

        private void OnAddressChanged(object sender, EventArgs e) => RefreshLocalAddresses();

        /// <summary>This PC's own addresses, to tell the remote end of an event from the local one.</summary>
        private void RefreshLocalAddresses()
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                    foreach (var u in nic.GetIPProperties().UnicastAddresses)
                        set.Add(new IPAddress(u.Address.GetAddressBytes()).ToString());
            }
            catch (System.Net.NetworkInformation.NetworkInformationException) { }
            _local = set;
        }

        private void OnEvent(IntPtr record)
        {
            try
            {
                if (TryParse(record, _local, out var pid, out var remote, out var sent, out var size)) _meter.Add(pid, remote, sent, size);
            }
            catch (Exception ex) when (!(ex is OutOfMemoryException))
            {
                // A bad event must never take down the reading thread.
            }
        }

        /// <summary>Reads one EVENT_RECORD (64-bit layout) of Microsoft-Windows-Kernel-Network.</summary>
        /// <returns>False for events that aren't data sent or received.</returns>
        public static bool TryParse(IntPtr record, ICollection<string> local, out int pid, out string remote, out bool sent, out int size)
        {
            pid = size = 0;
            remote = null;
            sent = false;
            var id = (ushort)Marshal.ReadInt16(record, 40);
            bool v6;
            switch (id)
            {
                case TcpSend4: case UdpSend4: v6 = false; sent = true; break;
                case TcpRecv4: case UdpRecv4: v6 = false; break;
                case TcpSend6: case UdpSend6: v6 = true; sent = true; break;
                case TcpRecv6: case UdpRecv6: v6 = true; break;
                default: return false;
            }
            var length = (ushort)Marshal.ReadInt16(record, 86);
            var data = Marshal.ReadIntPtr(record, 96);
            if (data == IntPtr.Zero || length < (v6 ? 40 : 16)) return false;
            pid = Marshal.ReadInt32(data, 0);
            size = Marshal.ReadInt32(data, 4);
            var addressBytes = v6 ? 16 : 4;
            var daddr = ReadAddress(data, 8, addressBytes);
            var saddr = ReadAddress(data, 8 + addressBytes, addressBytes);
            // Windows names the far end daddr. Should a build differ, whichever end isn't one of this PC's addresses is the remote one.
            remote = local != null && local.Contains(daddr) && !local.Contains(saddr) ? saddr : daddr;
            return true;
        }

        public static string ReadAddress(IntPtr data, int offset, int length)
        {
            var bytes = new byte[length];
            Marshal.Copy(IntPtr.Add(data, offset), bytes, 0, length);
            var a = new IPAddress(bytes);
            return (a.IsIPv4MappedToIPv6 ? a.MapToIPv4() : a).ToString();
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 1) return;
            System.Net.NetworkInformation.NetworkChange.NetworkAddressChanged -= OnAddressChanged;
            if (_meter.Running || _session != 0) Stop(SessionName);
            if (_trace != ulong.MaxValue) CloseTrace(_trace);
            _thread?.Join(2000);
            if (_logFile != IntPtr.Zero) Marshal.FreeHGlobal(_logFile);
            if (_loggerName != IntPtr.Zero) Marshal.FreeHGlobal(_loggerName);
        }
    }
}
