using System;

namespace EasyFW.Core
{
    public sealed class PendingFilter
    {
        public string Text { get; set; } = "";
        public TrafficDirection? Direction { get; set; }
        public string Protocol { get; set; }

        public bool Matches(PendingRequest p)
        {
            if (Direction == TrafficDirection.Inbound && !p.SawInbound) return false;
            if (Direction == TrafficDirection.Outbound && !p.SawOutbound) return false;
            if (!string.IsNullOrEmpty(Protocol) && !string.Equals(p.LastProtocol, Protocol, StringComparison.OrdinalIgnoreCase)) return false;
            return TextFilter.MatchesAll(Text, p.DisplayName, p.AppPath, p.LastRemote, p.LastProtocol, p.LastSourcePort.ToString(), p.LastDestPort.ToString(),
                IpInfo.HostName(p.LastRemoteIp, false), IpInfo.CountryText(p.LastRemoteIp));
        }
    }

    public sealed class RuleFilter
    {
        public string Text { get; set; } = "";
        public RuleAction? Action { get; set; }
        public TrafficDirection? Direction { get; set; }
        public bool? Enabled { get; set; }

        public bool Matches(AppRule r)
        {
            if (Action.HasValue && r.Action != Action.Value) return false;
            if (Direction.HasValue && !r.Covers(Direction.Value)) return false;
            if (Enabled.HasValue && r.Enabled != Enabled.Value) return false;
            return TextFilter.MatchesAll(Text, r.DisplayName, r.AppPath, r.Notes, r.Ports, r.NetworkText);
        }
    }

    public static class TextFilter
    {
        /// <summary>Every word typed must appear in at least one field.</summary>
        public static bool MatchesAll(string text, params string[] fields)
        {
            foreach (var term in (text ?? "").Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var found = false;
                foreach (var field in fields)
                {
                    if (field != null && field.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        found = true;
                        break;
                    }
                }
                if (!found) return false;
            }
            return true;
        }
    }
}
