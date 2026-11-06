using System;
using System.Collections.Generic;
using EasyFW.Core;

namespace EasyFW.Demo
{
    /// <summary>A backend that changes nothing. Lets the whole UI run without touching Windows Firewall.</summary>
    public sealed class DemoBackend : IFirewallBackend
    {
        public PolicyInfo GetPolicyInfo() => new PolicyInfo();
        public WindowsSnapshot CaptureState() => new WindowsSnapshot
        {
            DefaultInbound = new int[3], DefaultOutbound = new[] { 1, 1, 1 }, FirewallEnabled = new[] { true, true, true }, AuditSetting = "none"
        };
        public List<string> ListForeignAllowRules() => new List<string>();
        public void SetRulesEnabled(IEnumerable<string> keys, bool enabled, Action<int, int> progress = null) { }
        public void RemoveManagedRules(string tag) { }
        public bool HasManagedRules() => false;
        public void AddManagedRules(IEnumerable<FirewallRuleSpec> specs) { }
        public void ApplyBlockDefaults() { }
        public bool IsBlockDefaultActive() => true;
        public void EnableAudit() { }
        public void RestoreState(WindowsSnapshot snapshot) { }
    }

    /// <summary>Simulated traffic whose verdicts follow the rules the user sets in the UI.</summary>
    public sealed class DemoTraffic : IEventSource
    {
        private static readonly (string Path, TrafficDirection Dir, string Proto, string Remote, int Port)[] Apps =
        {
            (@"C:\Program Files\Browser\browser.exe", TrafficDirection.Outbound, "TCP", "142.250.74.14", 443),
            (@"C:\Program Files\MusicPlayer\player.exe", TrafficDirection.Outbound, "TCP", "35.186.224.25", 443),
            (@"C:\Games\GameLauncher\launcher.exe", TrafficDirection.Outbound, "UDP", "162.254.197.40", 27015),
            (@"C:\Tools\SyncAgent\syncagent.exe", TrafficDirection.Inbound, "TCP", "192.168.1.44", 49822),
            (@"C:\Program Files\Vendor\updater.exe", TrafficDirection.Outbound, "TCP", "93.184.216.34", 80),
            (@"C:\Windows\System32\svchost.exe", TrafficDirection.Outbound, "TCP", "13.107.4.50", 443)
        };

        private readonly Func<string, TrafficDirection, int, Verdict> _evaluate;
        private readonly System.Windows.Forms.Timer _timer = new System.Windows.Forms.Timer { Interval = 1500 };
        private readonly Random _random = new Random(7);
        private Action<FirewallEvent> _sink;

        public DemoTraffic(Func<string, TrafficDirection, int, Verdict> evaluate)
        {
            _evaluate = evaluate;
            _timer.Tick += (_, __) => EmitOne();
        }

        public void Start(Action<FirewallEvent> sink)
        {
            _sink = sink;
            _timer.Start();
        }

        public void Stop() => _timer.Stop();

        public void EmitOne()
        {
            var app = Apps[_random.Next(Apps.Length)];
            _sink?.Invoke(new FirewallEvent
            {
                TimeUtc = DateTime.UtcNow,
                Verdict = _evaluate(app.Path, app.Dir, app.Port),
                Pid = 2000 + Array.IndexOf(Apps, app) * 412,
                AppPath = app.Path,
                Direction = app.Dir,
                Protocol = app.Proto,
                LocalIp = "192.168.1.20",
                LocalPort = 50000 + _random.Next(40),
                RemoteIp = app.Remote,
                RemotePort = app.Port
            });
        }

        public static List<ActiveEndpoint> ActiveSample() => new List<ActiveEndpoint>
        {
            new ActiveEndpoint
            {
                Protocol = "TCP", State = "Established", Pid = 2000, ProcessName = "browser.exe", AppPath = Apps[0].Path,
                LocalIp = "192.168.1.20", LocalPort = 51544, RemoteIp = "142.250.74.14", RemotePort = 443, Direction = TrafficDirection.Outbound
            },
            new ActiveEndpoint
            {
                Protocol = "TCP", State = "Listening", Pid = 4, ProcessName = AppPaths.DisplayName(AppPaths.SystemApp), AppPath = AppPaths.SystemApp,
                LocalIp = "0.0.0.0", LocalPort = 445, RemoteIp = "*", RemotePort = 0, Direction = TrafficDirection.Inbound
            }
        };
    }
}
