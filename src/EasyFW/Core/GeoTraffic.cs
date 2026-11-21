using System;
using System.Collections.Generic;
using System.Linq;

namespace EasyFW.Core
{
    /// <summary>Traffic between this PC and one country, over the window the map shows.</summary>
    public sealed class GeoFlow
    {
        public string Country { get; set; }
        public int OutAccepted { get; set; }
        public int InAccepted { get; set; }
        public int OutBlocked { get; set; }
        public int InBlocked { get; set; }
        /// <summary>Connections open right now. Only known for the live view.</summary>
        public int ActiveOut { get; set; }
        public int ActiveIn { get; set; }
        public DateTime LastUtc { get; set; }
        public Dictionary<string, int> Apps { get; } = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Ips { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public int Out => OutAccepted + ActiveOut;
        public int In => InAccepted + ActiveIn;
        public int Blocked => OutBlocked + InBlocked;
        public int Active => ActiveOut + ActiveIn;
        public int Total => OutAccepted + InAccepted + Blocked + Active;

        public IEnumerable<string> TopApps(int count) => Apps.OrderByDescending(a => a.Value).ThenBy(a => a.Key).Take(count).Select(a => AppPaths.DisplayName(a.Key));
    }

    public sealed class GeoSnapshot
    {
        public DateTime FromUtc { get; set; }
        public DateTime ToUtc { get; set; }
        public bool Live { get; set; }
        /// <summary>Busiest first.</summary>
        public List<GeoFlow> Countries { get; set; } = new List<GeoFlow>();
        public int Lan { get; set; }
        /// <summary>Public addresses whose country isn't known, or isn't on the map.</summary>
        public int Unknown { get; set; }

        public int Out => Countries.Sum(c => c.Out);
        public int In => Countries.Sum(c => c.In);
        public int Blocked => Countries.Sum(c => c.Blocked);
        public int Active => Countries.Sum(c => c.Active);
    }

    /// <summary>One slice of the timeline under the map.</summary>
    public struct GeoBucket
    {
        public int Out, In, Blocked;
        public int Total => Out + In + Blocked;
    }

    public static class GeoTraffic
    {
        /// <param name="events">Attempts in the window.</param>
        /// <param name="active">Connections open now, for the live view; empty for a look back.</param>
        /// <param name="country">Country code of an IP, "LAN", or null.</param>
        public static GeoSnapshot Build(IEnumerable<FirewallEvent> events, IEnumerable<ConnectionEntry> active, DateTime fromUtc, DateTime toUtc, bool live, Func<string, string> country)
        {
            var snap = new GeoSnapshot { FromUtc = fromUtc, ToUtc = toUtc, Live = live };
            var flows = new Dictionary<string, GeoFlow>(StringComparer.OrdinalIgnoreCase);

            GeoFlow FlowFor(string ip)
            {
                if (string.IsNullOrEmpty(ip) || IpText.IsLoopback(ip)) return null;
                var code = country(ip);
                if (code == "LAN") { snap.Lan++; return null; }
                if (!WorldGeo.TryLocate(code, out _, out _)) { snap.Unknown++; return null; }
                if (!flows.TryGetValue(code, out var flow)) flows[code] = flow = new GeoFlow { Country = code.ToUpperInvariant() };
                flow.Ips.Add(ip);
                return flow;
            }

            foreach (var e in events)
            {
                if (e.TimeUtc < fromUtc || e.TimeUtc > toUtc) continue;
                var flow = FlowFor(e.RemoteIp);
                if (flow == null) continue;
                var inbound = e.Direction == TrafficDirection.Inbound;
                if (e.Verdict == Verdict.Blocked) { if (inbound) flow.InBlocked++; else flow.OutBlocked++; }
                else { if (inbound) flow.InAccepted++; else flow.OutAccepted++; }
                if (e.TimeUtc > flow.LastUtc) flow.LastUtc = e.TimeUtc;
                Count(flow, e.AppPath);
            }

            foreach (var c in active ?? Enumerable.Empty<ConnectionEntry>())
            {
                if (!c.IsActive || c.IsLoopback) continue;
                var flow = FlowFor(c.RemoteIp);
                if (flow == null) continue;
                if (c.Direction == TrafficDirection.Inbound) flow.ActiveIn++; else flow.ActiveOut++;
                if (toUtc > flow.LastUtc) flow.LastUtc = toUtc;
                Count(flow, c.AppPath);
            }

            snap.Countries = flows.Values.OrderByDescending(f => f.Total).ThenBy(f => f.Country).ToList();
            return snap;
        }

        private static void Count(GeoFlow flow, string app)
        {
            if (string.IsNullOrEmpty(app)) return;
            flow.Apps.TryGetValue(app, out var n);
            flow.Apps[app] = n + 1;
        }

        /// <summary>Attempts per slice of time, oldest first, for the timeline. LAN and loopback are left out, as on the map.</summary>
        public static GeoBucket[] Timeline(IEnumerable<FirewallEvent> events, DateTime endUtc, TimeSpan span, int buckets, Func<string, string> country)
        {
            var result = new GeoBucket[buckets];
            var start = endUtc - span;
            var width = span.Ticks / (double)buckets;
            foreach (var e in events)
            {
                if (e.TimeUtc < start || e.TimeUtc > endUtc || string.IsNullOrEmpty(e.RemoteIp) || IpText.IsLoopback(e.RemoteIp) || country(e.RemoteIp) == "LAN") continue;
                var i = Math.Min(buckets - 1, (int)((e.TimeUtc - start).Ticks / width));
                if (e.Verdict == Verdict.Blocked) result[i].Blocked++;
                else if (e.Direction == TrafficDirection.Inbound) result[i].In++;
                else result[i].Out++;
            }
            return result;
        }
    }
}
