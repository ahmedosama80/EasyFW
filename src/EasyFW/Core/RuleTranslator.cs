using System.Collections.Generic;
using System.Linq;

namespace EasyFW.Core
{
    /// <summary>Turns EasyFW's per-app rules into Windows Firewall rule definitions.</summary>
    public static class RuleTranslator
    {
        public const string Group = "EasyFW";
        /// <summary>Rules from when the app was called HomeFW. Treated as foreign, they would be saved and switched back on at restore.</summary>
        public const string LegacyGroup = "HomeFW";

        public static bool IsManagedGroup(string group) => group == Group || group == LegacyGroup;

        public const string EssentialTag = "[essential]";
        private const string SvcHost = @"%SystemRoot%\system32\svchost.exe";

        public static string Tag(AppRule rule) => $"[{rule.Id}]";

        public static IEnumerable<FirewallRuleSpec> ForApp(AppRule rule)
        {
            if (!rule.Enabled) yield break;
            foreach (var d in new[] { TrafficDirection.Outbound, TrafficDirection.Inbound })
            {
                if (!rule.Covers(d)) continue;
                if (AppPaths.Same(rule.AppPath, AppPaths.PingApp))
                {
                    yield return PingRule(rule, d, FirewallProtocols.Icmp4, "8:*", "v4");
                    yield return PingRule(rule, d, FirewallProtocols.Icmp6, "128:*", "v6");
                    continue;
                }
                var allow = rule.Action == RuleAction.Allow;
                // Port rules go first: on a block rule, the listed ports must be shut before the rest opens.
                if (rule.HasPorts)
                {
                    yield return PortRule(rule, d, FirewallProtocols.Tcp, "TCP");
                    yield return PortRule(rule, d, FirewallProtocols.Udp, "UDP");
                }
                // Block on ports means the app may use everything else. Windows applies block rules over allow rules.
                if (!rule.HasPorts || !allow)
                {
                    yield return new FirewallRuleSpec
                    {
                        Name = BaseName(rule, d),
                        Description = Describe(rule),
                        AppPath = rule.AppPath,
                        Direction = d,
                        Allow = allow || rule.HasPorts
                    };
                }
            }
        }

        private static string BaseName(AppRule rule, TrafficDirection d) =>
            $"EasyFW: {rule.DisplayName} {Tag(rule)} {(d == TrafficDirection.Outbound ? "Out" : "In")}";

        private static string Describe(AppRule rule) =>
            (rule.Action == RuleAction.Allow ? "Accept Always: " : "Block Always: ") + rule.AppPath + (rule.HasPorts ? ", ports: " + rule.PortsText : "");

        /// <summary>A port belongs to the far end when going out and to this PC when coming in. Windows needs one rule per protocol.</summary>
        private static FirewallRuleSpec PortRule(AppRule rule, TrafficDirection d, int protocol, string protocolName) =>
            new FirewallRuleSpec
            {
                Name = $"{BaseName(rule, d)} {protocolName}",
                Description = Describe(rule),
                AppPath = rule.AppPath,
                Direction = d,
                Allow = rule.Action == RuleAction.Allow,
                Protocol = protocol,
                RemotePorts = d == TrafficDirection.Outbound ? rule.Ports : null,
                LocalPorts = d == TrafficDirection.Inbound ? rule.Ports : null
            };

        private static FirewallRuleSpec PingRule(AppRule rule, TrafficDirection d, int protocol, string types, string version) =>
            new FirewallRuleSpec
            {
                Name = $"EasyFW: {rule.DisplayName} {Tag(rule)} {(d == TrafficDirection.Outbound ? "Out" : "In")} {version}",
                Description = (rule.Action == RuleAction.Allow ? "Accept Always: " : "Block Always: ") + "ping requests from any app",
                Direction = d,
                Allow = rule.Action == RuleAction.Allow,
                Protocol = protocol,
                IcmpTypes = types
            };

        /// <summary>
        /// What Windows needs to stay on the network at all: an address (DHCP, IPv6 neighbor discovery),
        /// name resolution, and the connectivity check. Without these every approved app would still fail.
        /// </summary>
        public static List<FirewallRuleSpec> Essentials()
        {
            var o = TrafficDirection.Outbound;
            var i = TrafficDirection.Inbound;
            var list = new List<FirewallRuleSpec>
            {
                Svc("DNS (UDP)", "Dnscache", o, FirewallProtocols.Udp, null, "53"),
                Svc("DNS (TCP)", "Dnscache", o, FirewallProtocols.Tcp, null, "53"),
                Svc("DHCP Out", "Dhcp", o, FirewallProtocols.Udp, "68", "67"),
                Svc("DHCP In", "Dhcp", i, FirewallProtocols.Udp, "68", "67"),
                Svc("DHCPv6 Out", "Dhcp", o, FirewallProtocols.Udp, "546", "547"),
                Svc("DHCPv6 In", "Dhcp", i, FirewallProtocols.Udp, "546", "547"),
                Svc("Network status check", "NlaSvc", o, FirewallProtocols.Tcp, null, "80"),
                Icmp("Path MTU (ICMP)", i, FirewallProtocols.Icmp4, "3:4")
            };
            foreach (var type in new[] { 133, 134, 135, 136, 143 })
            {
                list.Add(Icmp($"IPv6 neighbor {type} Out", o, FirewallProtocols.Icmp6, type + ":*"));
                list.Add(Icmp($"IPv6 neighbor {type} In", i, FirewallProtocols.Icmp6, type + ":*"));
            }
            list.Add(Icmp("Path MTU (ICMPv6)", i, FirewallProtocols.Icmp6, "2:*"));
            return list;
        }

        public static List<FirewallRuleSpec> All(AppConfig config)
        {
            var specs = config.AllowEssentials ? Essentials() : new List<FirewallRuleSpec>();
            specs.AddRange(config.Rules.SelectMany(ForApp));
            return specs;
        }

        private static FirewallRuleSpec Svc(string name, string service, TrafficDirection d, int proto, string local, string remote) =>
            new FirewallRuleSpec
            {
                Name = $"EasyFW essential: {name} {EssentialTag}",
                Description = "Required for basic networking.",
                AppPath = SvcHost,
                Service = service,
                Direction = d,
                Allow = true,
                Protocol = proto,
                LocalPorts = local,
                RemotePorts = remote
            };

        private static FirewallRuleSpec Icmp(string name, TrafficDirection d, int proto, string types) =>
            new FirewallRuleSpec
            {
                Name = $"EasyFW essential: {name} {EssentialTag}",
                Description = "Required for basic networking.",
                Direction = d,
                Allow = true,
                Protocol = proto,
                IcmpTypes = types
            };
    }
}
