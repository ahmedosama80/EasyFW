using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;

namespace EasyFW.Core
{
    // Values are persisted as numbers by DataContractJsonSerializer, so they must stay stable.
    public enum RuleAction { Allow = 0, Block = 1 }
    public enum RuleDirection { Both = 0, Outbound = 1, Inbound = 2 }
    public enum TrafficDirection { Unknown = 0, Inbound = 1, Outbound = 2 }
    /// <summary>Unknown is for sockets the firewall hasn't ruled on: listening, bound, or still trying to connect.</summary>
    public enum Verdict { Accepted = 0, Blocked = 1, Unknown = 2 }
    public enum RunMode { Live, MonitorOnly, Demo }

    [DataContract]
    public sealed class AppRule
    {
        [DataMember] public string Id { get; set; } = Guid.NewGuid().ToString("N").Substring(0, 8);
        [DataMember] public string AppPath { get; set; }
        [DataMember] public RuleAction Action { get; set; }
        [DataMember] public RuleDirection Direction { get; set; }
        [DataMember] public bool Enabled { get; set; } = true;
        [DataMember] public string Notes { get; set; }
        [DataMember] public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
        /// <summary>Empty means all ports. With ports, Allow permits only those, and Block stops only those and permits the rest.</summary>
        [DataMember] public string Ports { get; set; }
        /// <summary>Accept rules only. True keeps the app off the internet, so it can reach only the LAN choice below.</summary>
        [DataMember] public bool NoInternet { get; set; }
        /// <summary>Accept rules only. Rules saved before this existed read as All.</summary>
        [DataMember] public LanAccess Lan { get; set; }
        /// <summary>Used when <see cref="Lan"/> is Selected, in a.b.c.d/n form.</summary>
        [DataMember] public List<string> LanSubnets { get; set; }
        /// <summary>A rule for a while: it's deleted at this time. Null keeps it.</summary>
        [DataMember] public DateTime? ExpiresUtc { get; set; }
        /// <summary>A rule until Windows restarts: the time Windows had started when the rule was made. Null keeps it across restarts.</summary>
        [DataMember] public DateTime? BootUtc { get; set; }
        /// <summary>Accept rules only: the app keeps working during a lockdown.</summary>
        [DataMember] public bool KeepInLockdown { get; set; }
        /// <summary>Accept rules only. Days the app may connect, bit 0 = Sunday. 0 means any time, with no schedule.</summary>
        [DataMember] public int ScheduleDays { get; set; }
        /// <summary>Minutes after midnight. A "to" at or before "from" runs past midnight into the next day.</summary>
        [DataMember] public int ScheduleFrom { get; set; }
        [DataMember] public int ScheduleTo { get; set; }

        /// <summary>Lets traffic through: an accept rule, or a block rule on some ports, which opens the rest.</summary>
        public bool Opens => Action == RuleAction.Allow || HasPorts;

        public bool HasSchedule => ScheduleDays != 0;

        /// <param name="local">Local time.</param>
        public bool InSchedule(DateTime local)
        {
            if (!HasSchedule) return true;
            var minute = local.Hour * 60 + local.Minute;
            bool On(DayOfWeek d) => (ScheduleDays & (1 << (int)d)) != 0;
            if (ScheduleFrom < ScheduleTo) return On(local.DayOfWeek) && minute >= ScheduleFrom && minute < ScheduleTo;
            // Past midnight: the evening part belongs to the day it starts, the early morning part to the day before.
            return On(local.DayOfWeek) && minute >= ScheduleFrom || On(local.AddDays(-1).DayOfWeek) && minute < ScheduleTo;
        }

        public string ScheduleText
        {
            get
            {
                if (!HasSchedule) return "Any time";
                var days = new[] { DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Thursday, DayOfWeek.Friday, DayOfWeek.Saturday, DayOfWeek.Sunday }
                    .Where(d => (ScheduleDays & (1 << (int)d)) != 0).ToList();
                var dayText = days.Count == 7 ? "Every day"
                    : ScheduleDays == 0b0111110 ? "Mon-Fri"
                    : ScheduleDays == 0b1000001 ? "Sat-Sun"
                    : string.Join(" ", days.Select(d => d.ToString().Substring(0, 3)));
                return $"{dayText} {Clock(ScheduleFrom)}-{Clock(ScheduleTo)}";
            }
        }

        private static string Clock(int minutes) => $"{minutes / 60 % 24:00}:{minutes % 60:00}";

        public string DisplayName => AppPaths.DisplayName(AppPath);

        public bool IsTemporary => ExpiresUtc != null || BootUtc != null;

        /// <summary>Sets how long the rule lasts, from now.</summary>
        public void SetDuration(RuleDuration duration, DateTime nowUtc, DateTime bootUtc)
        {
            ExpiresUtc = RuleDurations.Length(duration) is TimeSpan length ? nowUtc + length : (DateTime?)null;
            BootUtc = duration == RuleDuration.UntilRestart ? bootUtc : (DateTime?)null;
        }

        /// <summary>A rule ends at its time, or once Windows has restarted. Boot times a minute or two apart are the same boot, since the clock can be adjusted.</summary>
        public bool HasExpired(DateTime nowUtc, DateTime bootUtc) =>
            ExpiresUtc != null && nowUtc >= ExpiresUtc.Value
            || BootUtc != null && Math.Abs((bootUtc - BootUtc.Value).TotalMinutes) > 2;

        public string ExpiresText(DateTime nowUtc)
        {
            if (ExpiresUtc is DateTime end)
            {
                var left = end - nowUtc;
                var at = end.ToLocalTime().ToString("HH:mm");
                return left.TotalSeconds <= 0 ? "Ending" : left.TotalMinutes < 1 ? $"In under a minute ({at})" : $"In {Math.Ceiling(left.TotalMinutes):0} min ({at})";
            }
            return BootUtc != null ? "At restart" : "Never";
        }

        public bool LimitsNetwork => Action == RuleAction.Allow && (NoInternet || Lan != LanAccess.All);

        /// <summary>Remote addresses for the Windows Firewall rules. Null means any.</summary>
        public string RemoteAddresses => LimitsNetwork ? NetRanges.ForWindows(!NoInternet, Lan, LanSubnets) : null;

        public bool AllowsAddress(string ip) => !LimitsNetwork || NetRanges.Allows(!NoInternet, Lan, LanSubnets, ip);

        public string NetworkText
        {
            get
            {
                if (Action == RuleAction.Block) return "-";
                var subnets = string.Join(", ", LanSubnets ?? new List<string>());
                if (NoInternet) return Lan == LanAccess.All ? "LAN only" : Lan == LanAccess.Selected ? "Only " + subnets : "None";
                return Lan == LanAccess.All ? "Internet + LAN" : Lan == LanAccess.Selected ? "Internet + " + subnets : "Internet only";
            }
        }

        /// <summary>Tidies the network choices. They only mean something on an accept rule, so a block rule has them cleared.</summary>
        /// <exception cref="FormatException">The choices aren't usable. The message says why.</exception>
        public void NormalizeNetwork()
        {
            if (!Enum.IsDefined(typeof(LanAccess), Lan)) throw new FormatException("The LAN choice isn't valid.");
            if (Action == RuleAction.Block)
            {
                NoInternet = false;
                Lan = LanAccess.All;
                LanSubnets = null;
                return;
            }
            LanSubnets = Lan == LanAccess.Selected ? NetRanges.NormalizeSubnets(LanSubnets) : null;
            if (Lan == LanAccess.Selected && LanSubnets.Count == 0) throw new FormatException("Choose at least one LAN subnet, or allow all of the LAN.");
            if (NoInternet && Lan == LanAccess.None) throw new FormatException("With no internet and no LAN, the app couldn't use the network at all. Use Block Always instead.");
        }

        public bool HasPorts => !string.IsNullOrEmpty(Ports);

        public string PortsText => !HasPorts ? "All" : Action == RuleAction.Allow ? "Only " + Ports : "All except " + Ports;

        /// <summary>Ignores direction, which <see cref="Covers"/> answers.</summary>
        public bool AllowsPort(int port)
        {
            if (!HasPorts) return Action == RuleAction.Allow;
            var listed = PortList.Contains(Ports, port);
            return Action == RuleAction.Allow ? listed : !listed;
        }

        public bool Covers(TrafficDirection d) =>
            Direction == RuleDirection.Both
            || (d == TrafficDirection.Outbound && Direction == RuleDirection.Outbound)
            || (d == TrafficDirection.Inbound && Direction == RuleDirection.Inbound);

        public AppRule Clone()
        {
            var copy = (AppRule)MemberwiseClone();
            copy.LanSubnets = LanSubnets?.ToList();
            return copy;
        }
    }

    /// <summary>
    /// A rule for every app whose path matches: C:\Games\*.* for a folder and its subfolders, *\steam*.exe with wildcards,
    /// or a plain keyword such as steam, which matches anywhere in the path. When a matching app with no rule of its own
    /// tries to connect, EasyFW gives it a normal rule with this decision.
    /// </summary>
    [DataContract]
    public sealed class PatternRule
    {
        [DataMember] public string Id { get; set; } = Guid.NewGuid().ToString("N").Substring(0, 8);
        [DataMember] public string Pattern { get; set; }
        [DataMember] public RuleAction Action { get; set; }
        [DataMember] public bool Enabled { get; set; } = true;
        [DataMember] public string Notes { get; set; }
        [DataMember] public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;

        private string _compiledFor;
        private System.Text.RegularExpressions.Regex _regex;

        /// <summary>Without a backslash, * or ?, the pattern is a keyword.</summary>
        public bool IsKeyword => IsKeywordText(Pattern);

        public static bool IsKeywordText(string pattern) => (pattern ?? "").IndexOfAny(new[] { '\\', '*', '?', '/' }) < 0;

        public string KindText => IsKeyword ? "Keyword" : "Path pattern";

        /// <summary>System and Ping aren't files, so patterns never cover them.</summary>
        public bool Matches(string appPath)
        {
            var p = (Pattern ?? "").Trim();
            if (p.Length == 0 || string.IsNullOrEmpty(appPath) || AppPaths.IsPseudoApp(appPath)) return false;
            if (IsKeywordText(p)) return appPath.IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0;
            if (_compiledFor != p)
            {
                // * is any text, across folders too, so C:\Games\*.* covers subfolders. *.* also matches a name with no dot.
                var body = System.Text.RegularExpressions.Regex.Escape(Environment.ExpandEnvironmentVariables(p.Replace('/', '\\')))
                    .Replace(@"\*\.\*", ".*").Replace(@"\*", ".*").Replace(@"\?", ".");
                _regex = new System.Text.RegularExpressions.Regex("^" + body + "$",
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);
                _compiledFor = p;
            }
            return _regex.IsMatch(Environment.ExpandEnvironmentVariables(appPath));
        }

        public PatternRule Clone() => new PatternRule { Id = Id, Pattern = Pattern, Action = Action, Enabled = Enabled, Notes = Notes, CreatedUtc = CreatedUtc };
    }

    public enum RuleDuration { Forever, UntilRestart, Minutes10, Minutes30, Hour1 }

    public static class RuleDurations
    {
        public static readonly RuleDuration[] All = { RuleDuration.Forever, RuleDuration.UntilRestart, RuleDuration.Minutes10, RuleDuration.Minutes30, RuleDuration.Hour1 };

        public static TimeSpan? Length(RuleDuration d) =>
            d == RuleDuration.Minutes10 ? TimeSpan.FromMinutes(10)
            : d == RuleDuration.Minutes30 ? TimeSpan.FromMinutes(30)
            : d == RuleDuration.Hour1 ? TimeSpan.FromHours(1)
            : (TimeSpan?)null;

        /// <summary>For lists: "Forever", "Until restart", "For 10 minutes".</summary>
        public static string Text(RuleDuration d) =>
            d == RuleDuration.Forever ? "Forever" : d == RuleDuration.UntilRestart ? "Until restart"
            : d == RuleDuration.Minutes10 ? "For 10 minutes" : d == RuleDuration.Minutes30 ? "For 30 minutes" : "For 1 hour";

        /// <summary>For buttons: "Accept Always", "Accept until restart", "Accept for 10 min".</summary>
        public static string ActionText(RuleAction action, RuleDuration d)
        {
            var verb = action == RuleAction.Allow ? "Accept" : "Block";
            return d == RuleDuration.Forever ? verb + " Always" : d == RuleDuration.UntilRestart ? verb + " until restart"
                : d == RuleDuration.Minutes10 ? verb + " for 10 min" : d == RuleDuration.Minutes30 ? verb + " for 30 min" : verb + " for 1 hour";
        }
    }

    [DataContract]
    public sealed class PendingRequest
    {
        [DataMember] public string AppPath { get; set; }
        [DataMember] public bool SawInbound { get; set; }
        [DataMember] public bool SawOutbound { get; set; }
        [DataMember] public DateTime FirstSeenUtc { get; set; } = DateTime.UtcNow;
        [DataMember] public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;
        [DataMember] public long Attempts { get; set; }
        [DataMember] public string LastRemote { get; set; }
        [DataMember] public string LastProtocol { get; set; }
        [DataMember] public int LastSourcePort { get; set; }
        [DataMember] public int LastDestPort { get; set; }

        public string DisplayName => AppPaths.DisplayName(AppPath);

        /// <summary>LastRemote without its port. Cut at the last colon, because IPv6 addresses contain colons too.</summary>
        public string LastRemoteIp
        {
            get
            {
                var i = (LastRemote ?? "").LastIndexOf(':');
                return i < 0 ? LastRemote ?? "" : LastRemote.Substring(0, i);
            }
        }

        /// <summary>Requests saved before ports were kept only have the remote port, which is the source when coming in and the destination when going out.</summary>
        public void FillPortsFromLastRemote()
        {
            if (LastSourcePort != 0 || LastDestPort != 0 || SawInbound == SawOutbound) return;
            var text = (LastRemote ?? "").Substring((LastRemote ?? "").LastIndexOf(':') + 1);
            if (!int.TryParse(text, out var port)) return;
            if (SawInbound) LastSourcePort = port;
            else LastDestPort = port;
        }

        public string DirectionText =>
            SawInbound && SawOutbound ? "In + Out" : SawInbound ? "Inbound" : "Outbound";
    }

    /// <summary>Everything needed to put Windows Firewall back as it was before EasyFW took over.</summary>
    [DataContract]
    public sealed class WindowsSnapshot
    {
        [DataMember] public int[] DefaultInbound { get; set; }
        [DataMember] public int[] DefaultOutbound { get; set; }
        [DataMember] public bool[] FirewallEnabled { get; set; }
        [DataMember] public string AuditSetting { get; set; }
        [DataMember] public List<string> DisabledRuleKeys { get; set; } = new List<string>();

        /// <summary>Stock Windows policy, for recovery when the real snapshot has been lost.</summary>
        public static WindowsSnapshot StockDefaults() => new WindowsSnapshot
        {
            DefaultInbound = new[] { 0, 0, 0 },
            DefaultOutbound = new[] { 1, 1, 1 },
            FirewallEnabled = new[] { true, true, true },
            AuditSetting = "unknown"
        };
    }

    /// <summary>How the user arranged one list's columns. Both arrays are by column, in the list's own column order.</summary>
    [DataContract]
    public sealed class ColumnLayout
    {
        [DataMember] public string List { get; set; }
        /// <summary>Where each column is shown, left to right from 0.</summary>
        [DataMember] public int[] Order { get; set; }
        [DataMember] public int[] Widths { get; set; }
    }

    [DataContract]
    public sealed class AppConfig
    {
        [DataMember] public bool SetupCompleted { get; set; }
        [DataMember] public bool ProtectionEnabled { get; set; }
        [DataMember] public bool AllowEssentials { get; set; } = true;
        [DataMember] public bool NotifyNewApps { get; set; } = true;
        [DataMember] public bool HideFirewallNotice { get; set; }
        [DataMember] public List<AppRule> Rules { get; set; } = new List<AppRule>();
        [DataMember] public List<PendingRequest> Pending { get; set; } = new List<PendingRequest>();
        [DataMember] public WindowsSnapshot Snapshot { get; set; }
        /// <summary>Wildcard and keyword rules, which decide for apps that have no rule of their own.</summary>
        [DataMember] public List<PatternRule> Patterns { get; set; } = new List<PatternRule>();
        /// <summary>Apps seen connecting, or trying to connect, to an internet address. Rule targets, as in <see cref="AppRule.AppPath"/>.</summary>
        [DataMember] public List<string> InternetApps { get; set; } = new List<string>();
        /// <summary>Column order and widths the user chose, per list.</summary>
        [DataMember] public List<ColumnLayout> Columns { get; set; } = new List<ColumnLayout>();
        /// <summary>Country the world map draws this PC in. Null means the Windows region.</summary>
        [DataMember] public string MapHome { get; set; }
        /// <summary>City within <see cref="MapHome"/>, or null for the middle of the country.</summary>
        [DataMember] public string MapCity { get; set; }
        /// <summary>Off by default: EasyFW asks a public service for this PC's internet address.</summary>
        [DataMember] public bool NoPublicIpLookup { get; set; }
        /// <summary>Whether EasyFW updates itself from GitHub. Asked once.</summary>
        [DataMember] public UpdateChoice Updates { get; set; }
        [DataMember] public DateTime? LastUpdateCheckUtc { get; set; }
        /// <summary>Two-letter codes. All traffic to and from these countries is blocked, for every app.</summary>
        [DataMember] public List<string> BlockedCountries { get; set; } = new List<string>();
        /// <summary>Only accept rules marked to keep working stay in force.</summary>
        [DataMember] public bool Lockdown { get; set; }
        /// <summary>Salted hash of the password that guards changes. Null means none.</summary>
        [DataMember] public string PasswordHash { get; set; }
        [DataMember] public bool NoFloodAlerts { get; set; }
        /// <summary>Ids of the blocklists in use. Empty means none.</summary>
        [DataMember] public List<string> Blocklists { get; set; } = new List<string>();
        /// <summary>Addresses or CIDRs never blocked by a blocklist.</summary>
        [DataMember] public List<string> BlocklistExceptions { get; set; } = new List<string>();
        [DataMember] public DateTime? BlocklistsUpdatedUtc { get; set; }

        /// <summary>EasyFW connects out itself for the public IP and for updates.</summary>
        public bool NeedsOwnConnection => !NoPublicIpLookup || Updates == UpdateChoice.Auto || (Blocklists?.Count ?? 0) > 0;

        public ColumnLayout ColumnsFor(string list) => (Columns ?? new List<ColumnLayout>()).FirstOrDefault(c => c.List == list);

        /// <summary>The serializer skips constructors, so missing lists arrive as null.</summary>
        public void Normalize()
        {
            Rules ??= new List<AppRule>();
            BlockedCountries ??= new List<string>();
            Blocklists ??= new List<string>();
            BlocklistExceptions ??= new List<string>();
            Pending ??= new List<PendingRequest>();
            Patterns ??= new List<PatternRule>();
            InternetApps ??= new List<string>();
            if (Snapshot != null) Snapshot.DisabledRuleKeys ??= new List<string>();
        }
    }

    public sealed class FirewallEvent
    {
        public DateTime TimeUtc { get; set; }
        public Verdict Verdict { get; set; }
        public int Pid { get; set; }
        public string AppPath { get; set; }
        public TrafficDirection Direction { get; set; }
        public string Protocol { get; set; }
        public string LocalIp { get; set; }
        public int LocalPort { get; set; }
        public string RemoteIp { get; set; }
        public int RemotePort { get; set; }

        public bool IsLoopback => IpText.IsLoopback(LocalIp) || IpText.IsLoopback(RemoteIp);
    }

    public sealed class ActiveEndpoint
    {
        public string Protocol { get; set; }
        public string LocalIp { get; set; }
        public int LocalPort { get; set; }
        public string RemoteIp { get; set; }
        public int RemotePort { get; set; }
        public string State { get; set; }
        public int Pid { get; set; }
        public string ProcessName { get; set; }
        public string AppPath { get; set; }
        public TrafficDirection Direction { get; set; }
    }

    public sealed class FirewallRuleSpec
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public string AppPath { get; set; }
        public string Service { get; set; }
        public TrafficDirection Direction { get; set; }
        public bool Allow { get; set; }
        public int Protocol { get; set; } = FirewallProtocols.Any;
        public string LocalPorts { get; set; }
        public string RemotePorts { get; set; }
        /// <summary>Null means any address.</summary>
        public string RemoteAddresses { get; set; }
        public string IcmpTypes { get; set; }
    }

    public sealed class PolicyInfo
    {
        public bool GroupPolicyOverrides { get; set; }
        public string Message { get; set; }
    }

    public static class FirewallProtocols
    {
        public const int Icmp4 = 1, Tcp = 6, Udp = 17, Icmp6 = 58, Any = 256;

        public static string Name(int p) => p switch
        {
            1 => "ICMP", 2 => "IGMP", 6 => "TCP", 17 => "UDP", 58 => "ICMPv6", _ => "IP " + p
        };
    }

    public interface IFirewallBackend
    {
        PolicyInfo GetPolicyInfo();
        WindowsSnapshot CaptureState();
        /// <summary>Enabled allow rules EasyFW does not own. Left active, they would bypass the opt-in posture.</summary>
        List<string> ListForeignAllowRules();
        /// <summary>Slow on a PC with many rules, since Windows commits each change. Progress reports (done, total).</summary>
        void SetRulesEnabled(IEnumerable<string> keys, bool enabled, Action<int, int> progress = null);
        /// <summary>Removes EasyFW-owned rules; a null tag removes all of them.</summary>
        void RemoveManagedRules(string tag);
        bool HasManagedRules();
        void AddManagedRules(IEnumerable<FirewallRuleSpec> specs);
        void ApplyBlockDefaults();
        bool IsBlockDefaultActive();
        void EnableAudit();
        void RestoreState(WindowsSnapshot snapshot);
    }

    public interface IEventSource
    {
        void Start(Action<FirewallEvent> sink);
        void Stop();
    }
}
