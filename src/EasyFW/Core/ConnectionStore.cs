using System;
using System.Collections.Generic;
using System.Linq;

namespace EasyFW.Core
{
    public sealed class ConnectionEntry
    {
        public string Key { get; set; }
        public DateTime LastSeenUtc { get; set; }
        public Verdict Verdict { get; set; }
        public string ProcessName { get; set; }
        public string AppPath { get; set; }
        public int Pid { get; set; }
        public TrafficDirection Direction { get; set; }
        public string Protocol { get; set; }
        public string LocalIp { get; set; }
        public int LocalPort { get; set; }
        public string RemoteIp { get; set; }
        public int RemotePort { get; set; }
        /// <summary>Whoever started the connection is the source: the far end when it came in, this PC otherwise.</summary>
        public int SourcePort => Direction == TrafficDirection.Inbound ? RemotePort : LocalPort;
        public int DestPort => Direction == TrafficDirection.Inbound ? LocalPort : RemotePort;
        public string State { get; set; }
        public long Hits { get; set; }
        public bool IsActive { get; set; }

        public bool IsLoopback => IpText.IsLoopback(LocalIp) || IpText.IsLoopback(RemoteIp);
    }

    public enum ConnectionColumn { Time, Status, Process, Pid, Direction, Protocol, LocalIp, LocalHost, RemoteIp, RemoteHost, Country, SourcePort, DestPort, State, Hits, Path }

    public sealed class ConnectionFilter
    {
        public string Text { get; set; } = "";
        public Verdict? Verdict { get; set; }
        public TrafficDirection? Direction { get; set; }
        public string Protocol { get; set; }
        public bool ActiveOnly { get; set; }
        public bool HideLoopback { get; set; } = true;
    }

    /// <summary>Live connection history, one row per 5-tuple. Touched only from the UI thread.</summary>
    public sealed class ConnectionStore
    {
        private readonly Dictionary<string, ConnectionEntry> _entries = new Dictionary<string, ConnectionEntry>();
        private readonly int _capacity;
        private int _acceptedCount, _blockedCount;

        public ConnectionStore(int capacity = 5000) { _capacity = capacity; }

        public long Version { get; private set; }
        public int Count => _entries.Count;
        /// <summary>Counted at the same points as the graph. Clearing the history leaves these alone.</summary>
        public FlowStats Flows { get; } = new FlowStats();

        /// <summary>Connections accepted and blocked since the last call. History clearing doesn't affect these.</summary>
        public (int Accepted, int Blocked) TakeCounts()
        {
            var counts = (_acceptedCount, _blockedCount);
            _acceptedCount = _blockedCount = 0;
            return counts;
        }

        private static string MakeKey(string proto, string lip, int lport, string rip, int rport) =>
            $"{proto}|{lip}|{lport}|{rip}|{rport}";

        public void Add(FirewallEvent e)
        {
            var key = MakeKey(e.Protocol, e.LocalIp, e.LocalPort, e.RemoteIp, e.RemotePort);
            if (!_entries.TryGetValue(key, out var entry))
            {
                entry = new ConnectionEntry
                {
                    Key = key, Protocol = e.Protocol, LocalIp = e.LocalIp, LocalPort = e.LocalPort,
                    RemoteIp = e.RemoteIp, RemotePort = e.RemotePort, State = "Attempt"
                };
                _entries[key] = entry;
            }
            if (e.Verdict == Verdict.Blocked) _blockedCount++;
            else _acceptedCount++;
            entry.Verdict = e.Verdict;
            entry.LastSeenUtc = e.TimeUtc;
            entry.Pid = e.Pid;
            entry.AppPath = e.AppPath;
            entry.ProcessName = AppPaths.DisplayName(e.AppPath);
            entry.Direction = e.Direction;
            entry.Hits++;
            Flows.Record(e.AppPath, entry.ProcessName, e.Direction, e.Protocol, e.RemoteIp, entry.DestPort, e.Verdict, e.TimeUtc);
            Version++;
            Trim();
        }

        /// <summary>Merges a poll of the OS connection tables. Rows that vanished are kept and marked closed.</summary>
        public void ApplyActive(IEnumerable<ActiveEndpoint> active, DateTime nowUtc)
        {
            var seen = new HashSet<string>();
            var changed = false;
            foreach (var a in active)
            {
                var key = MakeKey(a.Protocol, a.LocalIp, a.LocalPort, a.RemoteIp, a.RemotePort);
                seen.Add(key);
                if (!_entries.TryGetValue(key, out var entry))
                {
                    entry = new ConnectionEntry
                    {
                        Key = key, Protocol = a.Protocol, LocalIp = a.LocalIp, LocalPort = a.LocalPort,
                        RemoteIp = a.RemoteIp, RemotePort = a.RemotePort, LastSeenUtc = nowUtc, Hits = 1, Verdict = Verdict.Unknown
                    };
                    _entries[key] = entry;
                    changed = true;
                }
                var verdict = PolledVerdict(a, entry.Verdict);
                if (verdict == Verdict.Accepted && entry.Verdict != Verdict.Accepted)
                {
                    _acceptedCount++;
                    var dest = a.Direction == TrafficDirection.Inbound ? a.LocalPort : a.RemotePort;
                    Flows.Record(a.AppPath, a.ProcessName, a.Direction, a.Protocol, a.RemoteIp, dest, Verdict.Accepted, nowUtc);
                }
                if (!entry.IsActive || entry.State != a.State || entry.Verdict != verdict)
                {
                    entry.LastSeenUtc = nowUtc;
                    changed = true;
                }
                entry.IsActive = true;
                entry.State = a.State;
                entry.Verdict = verdict;
                entry.Pid = a.Pid;
                entry.ProcessName = a.ProcessName;
                entry.AppPath = a.AppPath;
                entry.Direction = a.Direction;
            }
            foreach (var entry in _entries.Values.Where(x => x.IsActive && !seen.Contains(x.Key)))
            {
                entry.IsActive = false;
                entry.State = "Closed";
                entry.LastSeenUtc = nowUtc;
                changed = true;
            }
            if (changed) Version++;
            Trim();
        }

        /// <summary>
        /// Only a connection that completed got past the firewall. A blocked app's socket also sits in the table
        /// while it tries to connect, and a listener has no peer, so neither counts as accepted.
        /// </summary>
        private static Verdict PolledVerdict(ActiveEndpoint a, Verdict current)
        {
            if (a.RemoteIp != "*" && a.State != "SYN sent" && a.State != "SYN received") return Verdict.Accepted;
            return current == Verdict.Blocked ? Verdict.Blocked : Verdict.Unknown;
        }

        public void Clear()
        {
            foreach (var key in _entries.Where(x => !x.Value.IsActive).Select(x => x.Key).ToList())
                _entries.Remove(key);
            Version++;
        }

        private void Trim()
        {
            if (_entries.Count <= _capacity) return;
            // Trim in chunks so a burst of events doesn't sort the whole table on every add.
            var excess = _entries.Count - _capacity + _capacity / 10;
            foreach (var e in _entries.Values.Where(x => !x.IsActive).OrderBy(x => x.LastSeenUtc).Take(excess).ToList())
                _entries.Remove(e.Key);
        }

        public static bool Matches(ConnectionEntry e, ConnectionFilter f)
        {
            if (f.Verdict.HasValue && e.Verdict != f.Verdict.Value) return false;
            if (f.Direction.HasValue && e.Direction != f.Direction.Value) return false;
            if (!string.IsNullOrEmpty(f.Protocol) && !string.Equals(e.Protocol, f.Protocol, StringComparison.OrdinalIgnoreCase)) return false;
            if (f.ActiveOnly && !e.IsActive) return false;
            if (f.HideLoopback && e.IsLoopback) return false;
            foreach (var term in (f.Text ?? "").Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (!Contains(e.ProcessName, term) && !Contains(e.AppPath, term) && !Contains(e.LocalIp, term)
                    && !Contains(e.RemoteIp, term) && !Contains(e.Protocol, term) && !Contains(e.State, term)
                    && !Contains(e.Verdict.ToString(), term)
                    && !Contains(IpInfo.HostName(e.LocalIp, false), term) && !Contains(IpInfo.HostName(e.RemoteIp, false), term)
                    && !Contains(IpInfo.CountryText(e.RemoteIp), term)
                    && e.LocalPort.ToString() != term && e.RemotePort.ToString() != term && e.Pid.ToString() != term)
                    return false;
            }
            return true;
        }

        private static bool Contains(string s, string term) =>
            s != null && s.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0;

        public List<ConnectionEntry> Query(ConnectionFilter filter, ConnectionColumn column, bool ascending)
        {
            var list = _entries.Values.Where(e => Matches(e, filter)).ToList();
            list.Sort((a, b) =>
            {
                var c = Compare(a, b, column);
                if (!ascending) c = -c;
                return c != 0 ? c : string.CompareOrdinal(a.Key, b.Key);
            });
            return list;
        }

        private static int Compare(ConnectionEntry a, ConnectionEntry b, ConnectionColumn column)
        {
            switch (column)
            {
                case ConnectionColumn.Time: return a.LastSeenUtc.CompareTo(b.LastSeenUtc);
                case ConnectionColumn.Status: return a.Verdict.CompareTo(b.Verdict);
                case ConnectionColumn.Process: return string.Compare(a.ProcessName, b.ProcessName, StringComparison.OrdinalIgnoreCase);
                case ConnectionColumn.Pid: return a.Pid.CompareTo(b.Pid);
                case ConnectionColumn.Direction: return a.Direction.CompareTo(b.Direction);
                case ConnectionColumn.Protocol: return string.CompareOrdinal(a.Protocol, b.Protocol);
                case ConnectionColumn.LocalIp: return string.CompareOrdinal(IpText.SortKey(a.LocalIp), IpText.SortKey(b.LocalIp));
                case ConnectionColumn.LocalHost: return string.Compare(IpInfo.HostName(a.LocalIp, false), IpInfo.HostName(b.LocalIp, false), StringComparison.OrdinalIgnoreCase);
                case ConnectionColumn.RemoteHost: return string.Compare(IpInfo.HostName(a.RemoteIp, false), IpInfo.HostName(b.RemoteIp, false), StringComparison.OrdinalIgnoreCase);
                case ConnectionColumn.Country: return string.Compare(IpInfo.CountryText(a.RemoteIp), IpInfo.CountryText(b.RemoteIp), StringComparison.OrdinalIgnoreCase);
                case ConnectionColumn.SourcePort: return a.SourcePort.CompareTo(b.SourcePort);
                case ConnectionColumn.RemoteIp: return string.CompareOrdinal(IpText.SortKey(a.RemoteIp), IpText.SortKey(b.RemoteIp));
                case ConnectionColumn.DestPort: return a.DestPort.CompareTo(b.DestPort);
                case ConnectionColumn.State: return string.CompareOrdinal(a.State, b.State);
                case ConnectionColumn.Hits: return a.Hits.CompareTo(b.Hits);
                case ConnectionColumn.Path: return string.Compare(a.AppPath, b.AppPath, StringComparison.OrdinalIgnoreCase);
                default: return 0;
            }
        }
    }
}
