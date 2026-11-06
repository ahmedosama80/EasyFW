using System;
using System.Collections.Generic;

namespace EasyFW.Core
{
    /// <summary>Parses Security log events 5156 (connection permitted) and 5157 (connection blocked).</summary>
    public static class FirewallEventParser
    {
        public const int Permitted = 5156, Blocked = 5157;

        /// <returns>The event, or null if the record isn't usable.</returns>
        public static FirewallEvent Parse(int eventId, IList<object> p, DateTime timeUtc, Func<string, string> resolvePath)
        {
            if ((eventId != Permitted && eventId != Blocked) || p == null || p.Count < 8) return null;
            var dir = Text(p[2]);
            return new FirewallEvent
            {
                TimeUtc = timeUtc,
                Verdict = eventId == Blocked ? Verdict.Blocked : Verdict.Accepted,
                Pid = (int)Number(p[0]),
                AppPath = resolvePath(Text(p[1])),
                Direction = dir.Contains("14592") ? TrafficDirection.Inbound
                    : dir.Contains("14593") ? TrafficDirection.Outbound
                    : TrafficDirection.Unknown,
                // "Source" is the local machine for both directions in these events.
                LocalIp = IpText.Normalize(Text(p[3])),
                LocalPort = (int)Number(p[4]),
                RemoteIp = IpText.Normalize(Text(p[5])),
                RemotePort = (int)Number(p[6]),
                Protocol = FirewallProtocols.Name((int)Number(p[7]))
            };
        }

        private static string Text(object o) => Convert.ToString(o) ?? "";

        private static long Number(object o) => long.TryParse(Text(o), out var n) ? n : 0;
    }

    public static class AuditSettingParser
    {
        /// <summary>Reads "auditpol /get /r" CSV. Inclusion text is localized, so unknown means "don't touch on restore".</summary>
        public static string Parse(string csv, string subcategoryGuid)
        {
            foreach (var line in (csv ?? "").Split('\n'))
            {
                if (line.IndexOf(subcategoryGuid, StringComparison.OrdinalIgnoreCase) < 0) continue;
                var cols = line.Split(',');
                if (cols.Length < 5) break;
                switch (cols[4].Trim().ToLowerInvariant())
                {
                    case "no auditing": return "none";
                    case "success": return "success";
                    case "failure": return "failure";
                    case "success and failure": return "both";
                }
                break;
            }
            return "unknown";
        }
    }
}
