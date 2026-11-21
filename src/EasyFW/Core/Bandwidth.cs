using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace EasyFW.Core
{
    /// <summary>Data rates for one app, in bits per second, and its totals since EasyFW started.</summary>
    public sealed class AppRate
    {
        public string AppPath { get; set; }
        public string Name { get; set; }
        public double InternetDown { get; set; }
        public double InternetUp { get; set; }
        public double LanDown { get; set; }
        public double LanUp { get; set; }
        public double Down => InternetDown + LanDown;
        public double Up => InternetUp + LanUp;
        public long TotalDown { get; set; }
        public long TotalUp { get; set; }
        public DateTime LastActiveUtc { get; set; }
    }

    /// <summary>All traffic over one second, in bits per second.</summary>
    public struct RatePoint
    {
        public DateTime TimeUtc;
        public double InternetDown, InternetUp, LanDown, LanUp;
        public double Down => InternetDown + LanDown;
        public double Up => InternetUp + LanUp;
    }

    /// <summary>
    /// Counts bytes sent and received per program and remote address, fed from Windows' network events on their own thread,
    /// and turns them into rates once a second on the UI thread. Internet and LAN follow <see cref="NetRanges"/>; this PC talking to itself is left out.
    /// </summary>
    public sealed class BandwidthMeter
    {
        public const int HistorySeconds = 600;

        private sealed class Counter
        {
            public long Down, Up;
        }

        private ConcurrentDictionary<(int Pid, string Ip), Counter> _current = new ConcurrentDictionary<(int, string), Counter>();
        private readonly Dictionary<string, AppRate> _apps = new Dictionary<string, AppRate>(StringComparer.OrdinalIgnoreCase);
        private readonly Queue<RatePoint> _history = new Queue<RatePoint>();
        private DateTime _lastSampleUtc = DateTime.MinValue;

        /// <summary>Set when the network events can't be read, to say why.</summary>
        public string Problem { get; set; }
        public bool Running { get; set; }

        public RatePoint Now { get; private set; }
        public IReadOnlyCollection<RatePoint> History => _history;
        /// <summary>Apps seen since EasyFW started, busiest now first.</summary>
        public List<AppRate> Apps { get; private set; } = new List<AppRate>();

        /// <summary>Called for every send and receive. Safe from any thread, and quick.</summary>
        public void Add(int pid, string remoteIp, bool sent, int bytes)
        {
            if (bytes <= 0 || string.IsNullOrEmpty(remoteIp)) return;
            var c = _current.GetOrAdd((pid, remoteIp), _ => new Counter());
            if (sent) Interlocked.Add(ref c.Up, bytes); else Interlocked.Add(ref c.Down, bytes);
        }

        /// <summary>Turns the bytes counted since the last call into rates. Call about once a second.</summary>
        /// <param name="resolve">The program path and name of a process id.</param>
        public void Sample(DateTime nowUtc, Func<int, (string Path, string Name)> resolve)
        {
            var counted = Interlocked.Exchange(ref _current, new ConcurrentDictionary<(int, string), Counter>());
            var seconds = _lastSampleUtc == DateTime.MinValue ? 1.0 : Math.Max(0.2, (nowUtc - _lastSampleUtc).TotalSeconds);
            _lastSampleUtc = nowUtc;

            foreach (var app in _apps.Values) app.InternetDown = app.InternetUp = app.LanDown = app.LanUp = 0;
            var point = new RatePoint { TimeUtc = nowUtc };
            foreach (var pair in counted)
            {
                var (pid, ip) = pair.Key;
                if (IpText.IsLoopback(ip)) continue;
                var lan = NetRanges.IsLan(ip);
                if (!lan && !NetRanges.IsInternet(ip)) continue;
                var (path, name) = resolve(pid);
                var key = string.IsNullOrEmpty(path) ? "pid " + pid : path;
                if (!_apps.TryGetValue(key, out var app)) _apps[key] = app = new AppRate { AppPath = path ?? "", Name = string.IsNullOrEmpty(name) ? key : name };
                double down = pair.Value.Down * 8 / seconds, up = pair.Value.Up * 8 / seconds;
                if (lan) { app.LanDown += down; app.LanUp += up; point.LanDown += down; point.LanUp += up; }
                else { app.InternetDown += down; app.InternetUp += up; point.InternetDown += down; point.InternetUp += up; }
                app.TotalDown += pair.Value.Down;
                app.TotalUp += pair.Value.Up;
                app.LastActiveUtc = nowUtc;
            }
            Now = point;
            _history.Enqueue(point);
            while (_history.Count > HistorySeconds) _history.Dequeue();
            Apps = _apps.Values.OrderByDescending(a => a.Down + a.Up).ThenByDescending(a => a.TotalDown + a.TotalUp).ToList();
        }

        /// <summary>"12.4 Mb/s", "830 kb/s", "0 b/s".</summary>
        public static string Text(double bitsPerSecond)
        {
            if (bitsPerSecond >= 1e9) return (bitsPerSecond / 1e9).ToString("0.00") + " Gb/s";
            if (bitsPerSecond >= 1e6) return (bitsPerSecond / 1e6).ToString(bitsPerSecond >= 1e8 ? "0" : "0.0") + " Mb/s";
            if (bitsPerSecond >= 1e3) return (bitsPerSecond / 1e3).ToString("0") + " kb/s";
            return bitsPerSecond.ToString("0") + " b/s";
        }

        /// <summary>"1.2 GB", "340 MB", "12 KB".</summary>
        public static string Bytes(long bytes)
        {
            if (bytes >= 1L << 30) return (bytes / (double)(1L << 30)).ToString("0.0") + " GB";
            if (bytes >= 1L << 20) return (bytes / (double)(1L << 20)).ToString("0.0") + " MB";
            if (bytes >= 1L << 10) return (bytes / (double)(1L << 10)).ToString("0") + " KB";
            return bytes + " B";
        }
    }
}
