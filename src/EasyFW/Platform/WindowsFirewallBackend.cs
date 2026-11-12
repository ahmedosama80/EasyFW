using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using EasyFW.Core;

namespace EasyFW.Platform
{
    /// <summary>Drives Windows Firewall through its HNetCfg COM API, so enforcement needs no kernel driver.</summary>
    public sealed class WindowsFirewallBackend : IFirewallBackend
    {
        private static readonly int[] Profiles = { 1, 2, 4 }; // domain, private, public
        private const int ActionBlock = 0, ActionAllow = 1;
        private const int DirIn = 1, DirOut = 2;
        private const int AllProfiles = 0x7FFFFFFF;

        private static dynamic NewPolicy() => Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));

        // Per-profile properties take an argument. These go through IDispatch directly, which is
        // more dependable for parameterized property puts than the dynamic binder.
        private static object GetIndexed(object policy, string name, int profile) =>
            policy.GetType().InvokeMember(name, BindingFlags.GetProperty, null, policy, new object[] { profile });

        private static void SetIndexed(object policy, string name, int profile, object value) =>
            policy.GetType().InvokeMember(name, BindingFlags.SetProperty, null, policy, new[] { profile, value });

        public PolicyInfo GetPolicyInfo()
        {
            dynamic policy = NewPolicy();
            int state = policy.LocalPolicyModifyState;
            return new PolicyInfo
            {
                GroupPolicyOverrides = state == 1,
                Message = state == 1
                    ? "Windows Firewall on this PC is controlled by Group Policy (usually a work or school device), so EasyFW's settings would not take effect."
                    : null
            };
        }

        public WindowsSnapshot CaptureState()
        {
            object policy = NewPolicy();
            return new WindowsSnapshot
            {
                DefaultInbound = Profiles.Select(p => Convert.ToInt32(GetIndexed(policy, "DefaultInboundAction", p))).ToArray(),
                DefaultOutbound = Profiles.Select(p => Convert.ToInt32(GetIndexed(policy, "DefaultOutboundAction", p))).ToArray(),
                FirewallEnabled = Profiles.Select(p => Convert.ToBoolean(GetIndexed(policy, "FirewallEnabled", p))).ToArray(),
                AuditSetting = AuditPolicy.Read()
            };
        }

        public void ApplyBlockDefaults()
        {
            object policy = NewPolicy();
            foreach (var p in Profiles)
            {
                SetIndexed(policy, "DefaultInboundAction", p, ActionBlock);
                SetIndexed(policy, "DefaultOutboundAction", p, ActionBlock);
                SetIndexed(policy, "BlockAllInboundTraffic", p, false);
                SetIndexed(policy, "FirewallEnabled", p, true);
            }
        }

        public bool IsBlockDefaultActive()
        {
            object policy = NewPolicy();
            return Profiles.All(p =>
                Convert.ToBoolean(GetIndexed(policy, "FirewallEnabled", p))
                && Convert.ToInt32(GetIndexed(policy, "DefaultInboundAction", p)) == ActionBlock
                && Convert.ToInt32(GetIndexed(policy, "DefaultOutboundAction", p)) == ActionBlock);
        }

        public void EnableAudit() => AuditPolicy.Apply("both");

        public void RestoreState(WindowsSnapshot s)
        {
            object policy = NewPolicy();
            for (var i = 0; i < Profiles.Length; i++)
            {
                SetIndexed(policy, "DefaultInboundAction", Profiles[i], s.DefaultInbound[i]);
                SetIndexed(policy, "DefaultOutboundAction", Profiles[i], s.DefaultOutbound[i]);
                SetIndexed(policy, "FirewallEnabled", Profiles[i], s.FirewallEnabled[i]);
            }
            AuditPolicy.Apply(s.AuditSetting);
        }

        private static string RuleKey(dynamic r) => string.Join("|",
            (string)r.Name, (int)r.Direction, (string)r.ApplicationName, (string)r.ServiceName,
            (int)r.Protocol, (string)r.LocalPorts, (string)r.RemotePorts, (int)r.Profiles);

        public List<string> ListForeignAllowRules()
        {
            var keys = new List<string>();
            dynamic policy = NewPolicy();
            foreach (dynamic r in policy.Rules)
            {
                if ((bool)r.Enabled && (int)r.Action == ActionAllow && !RuleTranslator.IsManagedGroup((string)r.Grouping))
                    keys.Add(RuleKey(r));
            }
            return keys;
        }

        public void SetRulesEnabled(IEnumerable<string> keys, bool enabled, Action<int, int> progress = null)
        {
            var wanted = new HashSet<string>(keys);
            if (wanted.Count == 0) return;
            dynamic policy = NewPolicy();
            // Collected first so progress has a real total. Rules already in the right state are skipped, which makes a retry quick.
            var matches = new List<dynamic>();
            foreach (dynamic r in policy.Rules)
            {
                if (RuleTranslator.IsManagedGroup((string)r.Grouping)) continue;
                if ((bool)r.Enabled != enabled && wanted.Contains((string)RuleKey(r))) matches.Add(r);
            }
            for (var i = 0; i < matches.Count; i++)
            {
                matches[i].Enabled = enabled;
                progress?.Invoke(i + 1, matches.Count);
            }
        }

        public bool HasManagedRules()
        {
            dynamic policy = NewPolicy();
            foreach (dynamic r in policy.Rules)
            {
                if (RuleTranslator.IsManagedGroup((string)r.Grouping)) return true;
            }
            return false;
        }

        public void RemoveManagedRules(string tag)
        {
            dynamic policy = NewPolicy();
            var names = new List<string>();
            foreach (dynamic r in policy.Rules)
            {
                if (!RuleTranslator.IsManagedGroup((string)r.Grouping)) continue;
                string name = r.Name;
                if (tag == null || name.Contains(tag)) names.Add(name);
            }
            foreach (var name in names) policy.Rules.Remove(name);
        }

        public void AddManagedRules(IEnumerable<FirewallRuleSpec> specs)
        {
            dynamic policy = NewPolicy();
            foreach (var spec in specs) policy.Rules.Add(BuildRule(spec));
        }

        public static object BuildRule(FirewallRuleSpec spec)
        {
            dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
            rule.Name = spec.Name;
            rule.Description = spec.Description;
            rule.Grouping = RuleTranslator.Group;
            if (spec.AppPath != null) rule.ApplicationName = spec.AppPath;
            if (spec.Service != null) rule.ServiceName = spec.Service;
            // The COM object rejects ports and ICMP types until the protocol is set.
            rule.Protocol = spec.Protocol;
            if (spec.IcmpTypes != null) rule.IcmpTypesAndCodes = spec.IcmpTypes;
            if (spec.LocalPorts != null) rule.LocalPorts = spec.LocalPorts;
            if (spec.RemotePorts != null) rule.RemotePorts = spec.RemotePorts;
            if (spec.RemoteAddresses != null) rule.RemoteAddresses = spec.RemoteAddresses;
            rule.Direction = spec.Direction == TrafficDirection.Inbound ? DirIn : DirOut;
            rule.Action = spec.Allow ? ActionAllow : ActionBlock;
            rule.Profiles = AllProfiles;
            rule.Enabled = true;
            return rule;
        }
    }

    /// <summary>The audit subcategory that makes Windows log events 5156 and 5157.</summary>
    public static class AuditPolicy
    {
        public const string FilteringPlatformConnection = "{0CCE9226-69AE-11D9-BED3-505054503030}";

        public static string Read()
        {
            try { return AuditSettingParser.Parse(Run($"/get /subcategory:{FilteringPlatformConnection} /r"), FilteringPlatformConnection); }
            catch (Exception ex)
            {
                Log.Write("auditpol read failed: " + ex.Message);
                return "unknown";
            }
        }

        public static void Apply(string setting)
        {
            string flags;
            switch (setting)
            {
                case "none": flags = "/success:disable /failure:disable"; break;
                case "success": flags = "/success:enable /failure:disable"; break;
                case "failure": flags = "/success:disable /failure:enable"; break;
                case "both": flags = "/success:enable /failure:enable"; break;
                default: return;
            }
            Run($"/set /subcategory:{FilteringPlatformConnection} {flags}");
        }

        private static string Run(string args)
        {
            using var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("auditpol.exe", args)
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
            });
            var errors = p.StandardError.ReadToEndAsync();
            var output = p.StandardOutput.ReadToEnd();
            errors.Wait();
            p.WaitForExit();
            if (p.ExitCode != 0) throw new InvalidOperationException($"auditpol {args} failed with exit code {p.ExitCode}");
            return output;
        }
    }
}
