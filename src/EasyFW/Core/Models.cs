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

        public string DisplayName => AppPaths.DisplayName(AppPath);

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

        /// <summary>The serializer skips constructors, so missing lists arrive as null.</summary>
        public void Normalize()
        {
            Rules ??= new List<AppRule>();
            Pending ??= new List<PendingRequest>();
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
