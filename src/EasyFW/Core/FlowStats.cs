using System;
using System.Collections.Generic;
using System.Linq;

namespace EasyFW.Core
{
    /// <summary>
    /// Every connection one app made or tried to the same remote address and port over a period, however many local ports it used.
    /// A snapshot: the counts cover only the period it was asked for.
    /// </summary>
    public sealed class FlowStat
    {
        public string Key { get; set; }
        public string AppPath { get; set; }
        public string ProcessName { get; set; }
        public TrafficDirection Direction { get; set; }
        public string Protocol { get; set; }
        public string RemoteIp { get; set; }
        public int DestPort { get; set; }
        public long Accepted { get; set; }
        public long Blocked { get; set; }
        public long Total => Accepted + Blocked;
        public DateTime FirstSeenUtc { get; set; }
        public DateTime LastSeenUtc { get; set; }

        public bool IsLoopback => IpText.IsLoopback(RemoteIp);
    }

    public enum FlowRank { Total = 0, Blocked = 1, Accepted = 2 }

    public sealed class FlowFilter
    {
        public string Text { get; set; } = "";
        /// <summary>Accepted or Blocked keeps groups with at least one of those.</summary>
        public Verdict? Status { get; set; }
        public TrafficDirection? Direction { get; set; }
        public string Protocol { get; set; }
        public bool HideLoopback { get; set; } = true;

        public bool Matches(FlowStat f)
        {
            if (Status == Verdict.Accepted && f.Accepted == 0) return false;
            if (Status == Verdict.Blocked && f.Blocked == 0) return false;
            if (Direction.HasValue && f.Direction != Direction.Value) return false;
            if (!string.IsNullOrEmpty(Protocol) && !string.Equals(f.Protocol, Protocol, StringComparison.OrdinalIgnoreCase)) return false;
            if (HideLoopback && f.IsLoopback) return false;
            return TextFilter.MatchesAll(Text, f.ProcessName, f.AppPath, f.RemoteIp, f.Protocol, f.DestPort.ToString(),
                IpInfo.HostName(f.RemoteIp, false), IpInfo.CountryText(f.RemoteIp));
        }
    }

    /// <summary>
    /// Counts of connections per app, direction, protocol, remote address and destination port, minute by minute for the last hour,
    /// for finding the busiest traffic. They count how often a connection was made or tried, since Windows doesn't report bytes per connection.
    /// Touched only from the UI thread.
    /// </summary>
    public sealed class FlowStats
    {
        /// <summary>The longest period that can be asked for.</summary>
        public const int MaxMinutes = 60;

        private sealed class Flow
        {
            public FlowStat Info;
            public readonly long[] Minute = new long[MaxMinutes];
            public readonly long[] Accepted = new long[MaxMinutes];
            public readonly long[] Blocked = new long[MaxMinutes];
        }

        private readonly Dictionary<string, Flow> _flows = new Dictionary<string, Flow>();
        private readonly int _capacity;
        private int _sinceSweep;

        public FlowStats(int capacity = 20000) { _capacity = capacity; }

        public long Version { get; private set; }
        public int Count => _flows.Count;

        public static long MinuteOf(DateTime utc) => utc.Ticks / TimeSpan.TicksPerMinute;

        public void Record(string appPath, string processName, TrafficDirection direction, string protocol, string remoteIp, int destPort, Verdict verdict, DateTime timeUtc)
        {
            if (verdict == Verdict.Unknown) return;
            var key = $"{(appPath ?? "").ToLowerInvariant()}|{direction}|{protocol}|{remoteIp}|{destPort}";
            if (!_flows.TryGetValue(key, out var f))
            {
                f = new Flow
                {
                    Info = new FlowStat
                    {
                        Key = key, AppPath = appPath, ProcessName = processName ?? AppPaths.DisplayName(appPath), Direction = direction,
                        Protocol = protocol, RemoteIp = remoteIp, DestPort = destPort, FirstSeenUtc = timeUtc, LastSeenUtc = timeUtc
                    }
                };
                _flows[key] = f;
            }
            var minute = MinuteOf(timeUtc);
            var slot = (int)(minute % MaxMinutes);
            // A slot still holding an older minute is reused, which drops counts more than an hour old.
            if (f.Minute[slot] != minute)
            {
                f.Minute[slot] = minute;
                f.Accepted[slot] = 0;
                f.Blocked[slot] = 0;
            }
            if (verdict == Verdict.Blocked) f.Blocked[slot]++;
            else f.Accepted[slot]++;
            if (timeUtc > f.Info.LastSeenUtc) f.Info.LastSeenUtc = timeUtc;
            Version++;
            if (++_sinceSweep >= 1000 || _flows.Count > _capacity) Sweep(timeUtc);
        }

        public void Clear()
        {
            _flows.Clear();
            Version++;
        }

        /// <summary>Drops groups with nothing in the last hour, then the oldest if still over capacity.</summary>
        private void Sweep(DateTime nowUtc)
        {
            _sinceSweep = 0;
            var cutoff = nowUtc.AddMinutes(-MaxMinutes - 1);
            foreach (var key in _flows.Where(x => x.Value.Info.LastSeenUtc < cutoff).Select(x => x.Key).ToList())
                _flows.Remove(key);
            if (_flows.Count <= _capacity) return;
            // In chunks, so a burst doesn't sort everything on every connection.
            var excess = _flows.Count - _capacity + _capacity / 10;
            foreach (var f in _flows.Values.OrderBy(x => x.Info.LastSeenUtc).Take(excess).ToList())
                _flows.Remove(f.Info.Key);
        }

        /// <param name="minutes">The period, up to <see cref="MaxMinutes"/>, counted in whole minutes up to and including the current one.</param>
        /// <param name="matching">How many groups match before the limit, for "top N of M".</param>
        public List<FlowStat> Top(FlowFilter filter, FlowRank rank, int minutes, int limit, DateTime nowUtc, out int matching)
        {
            minutes = Math.Max(1, Math.Min(MaxMinutes, minutes));
            var first = MinuteOf(nowUtc) - minutes + 1;
            Func<FlowStat, long> by = rank == FlowRank.Blocked ? f => f.Blocked : rank == FlowRank.Accepted ? (Func<FlowStat, long>)(f => f.Accepted) : f => f.Total;
            var all = new List<FlowStat>();
            foreach (var f in _flows.Values)
            {
                long accepted = 0, blocked = 0;
                for (var i = 0; i < MaxMinutes; i++)
                {
                    if (f.Minute[i] < first) continue;
                    accepted += f.Accepted[i];
                    blocked += f.Blocked[i];
                }
                if (accepted + blocked == 0) continue;
                var row = new FlowStat
                {
                    Key = f.Info.Key, AppPath = f.Info.AppPath, ProcessName = f.Info.ProcessName, Direction = f.Info.Direction, Protocol = f.Info.Protocol,
                    RemoteIp = f.Info.RemoteIp, DestPort = f.Info.DestPort, FirstSeenUtc = f.Info.FirstSeenUtc, LastSeenUtc = f.Info.LastSeenUtc,
                    Accepted = accepted, Blocked = blocked
                };
                if (filter.Matches(row) && by(row) > 0) all.Add(row);
            }
            matching = all.Count;
            return all.OrderByDescending(by).ThenByDescending(f => f.Total).ThenByDescending(f => f.LastSeenUtc)
                .ThenBy(f => f.Key, StringComparer.Ordinal).Take(limit).ToList();
        }
    }
}
