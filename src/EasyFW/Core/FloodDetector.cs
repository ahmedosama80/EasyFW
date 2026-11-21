using System;
using System.Collections.Generic;
using System.Linq;

namespace EasyFW.Core
{
    public enum FloodKind { Spike, AppBurst, Scan }

    public sealed class FloodAlert
    {
        public FloodKind Kind { get; set; }
        /// <summary>The app path or remote IP, or null for all traffic.</summary>
        public string Subject { get; set; }
        public int Count { get; set; }
        public string Title { get; set; }
        public string Text { get; set; }
    }

    /// <summary>
    /// Spots sudden bursts of connection attempts over the last 10 seconds: far more than usual overall,
    /// one app opening a flood of connections, or one remote address knocking on many ports (a scan).
    /// Each kind of alert about the same thing is given once per 10 minutes.
    /// </summary>
    public sealed class FloodDetector
    {
        public static readonly TimeSpan Window = TimeSpan.FromSeconds(10);
        public static readonly TimeSpan Quiet = TimeSpan.FromMinutes(10);
        /// <summary>Overall: at least this many in 10 seconds, and at least <see cref="SpikeFactor"/> times the usual.</summary>
        public int SpikeMinimum { get; set; } = 400;
        public double SpikeFactor { get; set; } = 5;
        /// <summary>One app, in 10 seconds.</summary>
        public int AppLimit { get; set; } = 250;
        /// <summary>Blocked incoming attempts from one address, in 10 seconds.</summary>
        public int ScanLimit { get; set; } = 40;

        private readonly Queue<FirewallEvent> _recent = new Queue<FirewallEvent>();
        /// <summary>Attempts per second over the last 5 minutes, for what "usual" is.</summary>
        private readonly SortedDictionary<long, int> _perSecond = new SortedDictionary<long, int>();
        private readonly Dictionary<string, DateTime> _lastAlert = new Dictionary<string, DateTime>();

        public List<FloodAlert> Add(IEnumerable<FirewallEvent> events, DateTime nowUtc, Func<string, string> countryName = null)
        {
            foreach (var e in events)
            {
                if (IpText.IsLoopback(e.RemoteIp)) continue;
                _recent.Enqueue(e);
                var second = e.TimeUtc.Ticks / TimeSpan.TicksPerSecond;
                _perSecond.TryGetValue(second, out var n);
                _perSecond[second] = n + 1;
            }
            var cutoff = nowUtc - Window;
            while (_recent.Count > 0 && _recent.Peek().TimeUtc < cutoff) _recent.Dequeue();
            var oldest = (nowUtc - TimeSpan.FromMinutes(5)).Ticks / TimeSpan.TicksPerSecond;
            foreach (var old in _perSecond.Keys.TakeWhile(k => k < oldest).ToList()) _perSecond.Remove(old);

            var alerts = new List<FloodAlert>();
            var total = _recent.Count;
            // Usual: the average 10 seconds over the last 5 minutes, leaving out the 10 seconds being judged.
            var windowStart = cutoff.Ticks / TimeSpan.TicksPerSecond;
            var before = _perSecond.Where(p => p.Key < windowStart).ToList();
            var span = before.Count == 0 ? 0 : Math.Max(10, windowStart - before[0].Key);
            var usual = span == 0 ? 0 : before.Sum(p => p.Value) * 10.0 / span;
            if (total >= SpikeMinimum && total >= usual * SpikeFactor && Due("spike", nowUtc))
                alerts.Add(new FloodAlert
                {
                    Kind = FloodKind.Spike, Count = total, Title = "Sudden burst of traffic",
                    Text = $"{total:N0} connection attempts in the last 10 seconds" + (usual >= 1 ? $", about {total / usual:0}x the usual." : ".")
                });

            foreach (var app in _recent.Where(e => !string.IsNullOrEmpty(e.AppPath)).GroupBy(e => e.AppPath, StringComparer.OrdinalIgnoreCase))
            {
                var n = app.Count();
                if (n < AppLimit || !Due("app|" + app.Key.ToLowerInvariant(), nowUtc)) continue;
                var blocked = app.Count(e => e.Verdict == Verdict.Blocked);
                var targets = app.Select(e => e.RemoteIp).Distinct().Count();
                alerts.Add(new FloodAlert
                {
                    Kind = FloodKind.AppBurst, Subject = app.Key, Count = n, Title = $"{AppPaths.DisplayName(app.Key)} is flooding the network",
                    Text = $"{n:N0} connection attempts in 10 seconds to {targets:N0} address(es)" + (blocked > 0 ? $", {blocked:N0} blocked." : ".")
                });
            }

            foreach (var source in _recent.Where(e => e.Direction == TrafficDirection.Inbound && e.Verdict == Verdict.Blocked && !string.IsNullOrEmpty(e.RemoteIp))
                         .GroupBy(e => e.RemoteIp, StringComparer.OrdinalIgnoreCase))
            {
                var n = source.Count();
                if (n < ScanLimit || !Due("scan|" + source.Key, nowUtc)) continue;
                var ports = source.Select(e => e.LocalPort).Distinct().Count();
                var where = countryName?.Invoke(source.Key);
                alerts.Add(new FloodAlert
                {
                    Kind = FloodKind.Scan, Subject = source.Key, Count = n,
                    Title = ports > 5 ? "Possible port scan" : "Repeated attempts to get in",
                    Text = $"{source.Key}{(string.IsNullOrEmpty(where) ? "" : " (" + where + ")")} tried to connect {n:N0} times in 10 seconds" +
                           (ports > 1 ? $", on {ports:N0} ports." : ".") + " All were blocked."
                });
            }
            return alerts;
        }

        private bool Due(string key, DateTime nowUtc)
        {
            if (_lastAlert.TryGetValue(key, out var last) && nowUtc - last < Quiet) return false;
            _lastAlert[key] = nowUtc;
            return true;
        }
    }
}
