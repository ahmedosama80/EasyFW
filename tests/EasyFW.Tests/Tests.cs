using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using EasyFW;
using EasyFW.Core;
using EasyFW.Demo;
using EasyFW.Platform;
using EasyFW.UI;

internal sealed class FakeBackend : IFirewallBackend
{
    public readonly List<string> Calls = new List<string>();
    public readonly List<string> Foreign = new List<string> { "RDP", "Bonjour" };
    public readonly List<FirewallRuleSpec> Managed = new List<FirewallRuleSpec>();
    public bool Blocking;
    public string FailOn;
    public System.Threading.ManualResetEventSlim HoldRestore;

    private void Hit(string call)
    {
        Calls.Add(call);
        if (call == FailOn) throw new InvalidOperationException("boom: " + call);
    }

    public PolicyInfo GetPolicyInfo() => new PolicyInfo();
    public WindowsSnapshot CaptureState()
    {
        Hit("capture");
        return new WindowsSnapshot { DefaultInbound = new[] { 0, 0, 0 }, DefaultOutbound = new[] { 1, 1, 1 }, FirewallEnabled = new[] { true, true, false }, AuditSetting = "none" };
    }
    public List<string> ListForeignAllowRules() { Hit("list"); return Foreign.ToList(); }
    public void SetRulesEnabled(IEnumerable<string> keys, bool enabled, Action<int, int> progress = null)
    {
        var k = keys.ToList();
        Hit(enabled ? "enableRules" : "disableRules");
        progress?.Invoke(k.Count, k.Count);
        if (enabled) Foreign.AddRange(k.Except(Foreign));
        else Foreign.RemoveAll(k.Contains);
    }
    public void RemoveManagedRules(string tag) { Hit("remove"); Managed.RemoveAll(s => tag == null || s.Name.Contains(tag)); }
    public bool HasManagedRules() => Managed.Count > 0;
    public void AddManagedRules(IEnumerable<FirewallRuleSpec> specs) { Hit("add"); Managed.AddRange(specs); }
    public void ApplyBlockDefaults() { Hit("block"); Blocking = true; }
    public bool IsBlockDefaultActive() => Blocking;
    public void EnableAudit() => Hit("audit");
    public void RestoreState(WindowsSnapshot s) { HoldRestore?.Wait(); Hit("restore"); Blocking = false; }
}

internal static class Tests
{
    private static int _pass, _fail;

    private static void Check(bool ok, string name)
    {
        if (ok) _pass++;
        else { _fail++; Console.WriteLine("  FAIL: " + name); }
    }

    private static void Throws(Action a, string name)
    {
        try { a(); Check(false, name + " (no exception)"); }
        catch (Exception) { Check(true, name); }
    }

    private static FirewallService NewService(FakeBackend b) =>
        new FirewallService(new ConfigStore(null, true), b, RunMode.Live);

    private static FirewallEvent Blocked(string path, TrafficDirection d = TrafficDirection.Outbound, string remote = "8.8.8.8", int lport = 50000) => new FirewallEvent
    {
        TimeUtc = DateTime.UtcNow, Verdict = Verdict.Blocked, Pid = 100, AppPath = path, Direction = d, Protocol = "TCP",
        LocalIp = "192.168.1.5", LocalPort = lport, RemoteIp = remote, RemotePort = 443
    };

    /// <summary>Pumps messages: once a form exists, awaits resume on this thread and would deadlock a plain block.</summary>
    private static void Wait(Task t)
    {
        while (!t.IsCompleted)
        {
            Application.DoEvents();
            System.Threading.Thread.Sleep(1);
        }
        t.GetAwaiter().GetResult();
    }

    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "--probe") return Probe();
        if (args.Length > 0 && args[0] == "--avast") { PrintAvastPaths(); return 0; }
        // The LAN is the PC's Ethernet and Wi-Fi subnets. A fixed one keeps results the same on any machine.
        NetRanges.AdapterSource = () => new List<(string, string)> { ("192.168.1.0/24", "Wi-Fi"), ("10.0.0.0/24", "Ethernet") };
        NetRanges.Refresh();
        if (args.Length > 1 && args[0] == "--shots") return Shots(args[1]);

        Parser();
        Config();
        Store();
        Translator();
        Enforcement();
        Pending();
        Rules();
        Ports();
        RuleFiles();
        Startup();
        OldName();
        PendingPorts();
        Copying();
        Network();
        TopFlows();
        Lookups();
        Patterns();
        Signatures();
        HistoryAndInternet();
        ColumnLayouts();
        WorldMap();
        PublicIpAndLocation();
        RuleDurationsTest();
        Updates();
        CountryBlocking();
        LockdownAndSchedules();
        PasswordsAndFloods();
        BlocklistTests();
        PortsAndShares();
        BandwidthTests();
        Console.WriteLine($"{_pass} passed, {_fail} failed");
        return _fail == 0 ? 0 : 1;
    }

    private static void Parser()
    {
        var map = new Dictionary<string, string> { [@"\device\harddiskvolume3"] = "C:" };
        Func<string, string> resolve = p => DevicePaths.Convert(p, map);
        var props = new object[] { (ulong)1234, @"\device\harddiskvolume3\app\x.exe", "%%14593", "192.168.1.5", "50000", "8.8.8.8", "443", (uint)6, (ulong)1, "%%14611", (uint)48 };
        var e = FirewallEventParser.Parse(5157, props, DateTime.UtcNow, resolve);
        Check(e.Verdict == Verdict.Blocked, "5157 is blocked");
        Check(e.Pid == 1234, "pid");
        Check(e.AppPath == @"C:\app\x.exe", "device path converted");
        Check(e.Direction == TrafficDirection.Outbound, "direction out");
        Check(e.LocalIp == "192.168.1.5" && e.LocalPort == 50000 && e.RemoteIp == "8.8.8.8" && e.RemotePort == 443, "endpoints");
        Check(e.Protocol == "TCP", "protocol");
        props[2] = "%%14592";
        var e2 = FirewallEventParser.Parse(5156, props, DateTime.UtcNow, resolve);
        Check(e2.Verdict == Verdict.Accepted && e2.Direction == TrafficDirection.Inbound, "5156 inbound accepted");
        Check(FirewallEventParser.Parse(4624, props, DateTime.UtcNow, resolve) == null, "other event ignored");
        Check(FirewallEventParser.Parse(5157, new object[2], DateTime.UtcNow, resolve) == null, "short record ignored");
        Check(DevicePaths.Convert(@"\device\harddiskvolume31\a.exe", map) == @"\device\harddiskvolume31\a.exe", "volume3 doesn't match volume31");
        Check(DevicePaths.ToDosPath("System") == "System" && DevicePaths.ToDosPath("-") == "", "system and unknown paths");

        const string g = AuditPolicy.FilteringPlatformConnection;
        Check(AuditSettingParser.Parse($"Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\r\nPC,System,Filtering Platform Connection,{g},Success and Failure,\r\n", g) == "both", "audit both");
        Check(AuditSettingParser.Parse($"PC,System,x,{g},No Auditing,\r\n", g) == "none", "audit none");
        Check(AuditSettingParser.Parse($"PC,System,x,{g},Keine Uberwachung,\r\n", g) == "unknown", "localized audit is unknown");
        Check(ActiveConnectionReader.Port(0xBB01) == 443, "port byte order");
    }

    private static void Config()
    {
        var cfg = new AppConfig { SetupCompleted = true, ProtectionEnabled = true };
        cfg.Rules.Add(new AppRule { AppPath = @"C:\a\b.exe", Action = RuleAction.Block, Direction = RuleDirection.Inbound, Notes = "x" });
        cfg.Pending.Add(new PendingRequest { AppPath = @"C:\c.exe", Attempts = 3, SawInbound = true });
        cfg.Snapshot = WindowsSnapshot.StockDefaults();
        cfg.Snapshot.DisabledRuleKeys.Add("k|1");
        var bytes = ConfigStore.Serialize(cfg);
        Check(bytes[0] == (byte)'{', "no BOM written");
        Check(Encoding.UTF8.GetString(bytes).Contains("\"AppPath\""), "clean JSON keys");
        var back = ConfigStore.Deserialize(bytes);
        Check(back.Rules[0].Action == RuleAction.Block && back.Rules[0].Direction == RuleDirection.Inbound && back.Rules[0].Id == cfg.Rules[0].Id, "rule round trip");
        Check(back.Pending[0].Attempts == 3 && back.Snapshot.DisabledRuleKeys[0] == "k|1", "pending and snapshot round trip");
        var bom = new byte[] { 0xEF, 0xBB, 0xBF }.Concat(bytes).ToArray();
        Check(ConfigStore.Deserialize(bom).SetupCompleted, "BOM tolerated");

        var dir = Path.Combine(Path.GetTempPath(), "EasyFW.Tests." + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var path = Path.Combine(dir, "config.json");
            var fresh = new ConfigStore(path, false);
            Check(!fresh.Config.SetupCompleted, "missing file means first run");
            fresh.Config.SetupCompleted = true;
            fresh.Save();
            fresh.Save();
            Check(new ConfigStore(path, false).Config.SetupCompleted, "persists across reload");
            File.WriteAllText(path, "{broken");
            var bad = new ConfigStore(path, false);
            Check(!bad.Config.SetupCompleted && File.Exists(path + ".bad"), "corrupt file kept as .bad");
            var ro = new ConfigStore(Path.Combine(dir, "ro.json"), true);
            ro.Save();
            Check(!File.Exists(Path.Combine(dir, "ro.json")), "read-only never writes");
            var a = new AppConfig { Rules = null, Pending = null };
            a.Normalize();
            Check(a.Rules != null && a.Pending != null, "normalize");
        }
        finally { Directory.Delete(dir, true); }
    }

    private static ActiveEndpoint Live(string lip, int lport, string rip, int rport, string proc) => new ActiveEndpoint
    {
        Protocol = "TCP", LocalIp = lip, LocalPort = lport, RemoteIp = rip, RemotePort = rport, State = "Established",
        Pid = 7, ProcessName = proc, AppPath = @"C:\" + proc, Direction = TrafficDirection.Outbound
    };

    private static void Store()
    {
        var s = new ConnectionStore();
        s.Add(Blocked(@"C:\a.exe"));
        s.Add(Blocked(@"C:\a.exe"));
        Check(s.Count == 1, "same 5-tuple collapses");
        var all = new ConnectionFilter { HideLoopback = false };
        Check(s.Query(all, ConnectionColumn.Time, true)[0].Hits == 2, "hits counted");

        var both = new[] { Live("192.168.1.5", 50000, "8.8.8.8", 443, "a.exe"), Live("127.0.0.1", 9, "127.0.0.1", 10, "lo.exe") };
        s.ApplyActive(both, DateTime.UtcNow);
        var row = s.Query(new ConnectionFilter(), ConnectionColumn.Time, true).Single();
        Check(row.IsActive && row.Verdict == Verdict.Accepted && row.State == "Established", "live socket means accepted");
        Check(s.Query(new ConnectionFilter { HideLoopback = false }, ConnectionColumn.Time, true).Count == 2, "loopback shown when asked");
        var v = s.Version;
        s.ApplyActive(both, DateTime.UtcNow);
        Check(s.Version == v, "unchanged poll causes no redraw");
        s.ApplyActive(new ActiveEndpoint[0], DateTime.UtcNow);
        row = s.Query(new ConnectionFilter(), ConnectionColumn.Time, true).Single();
        Check(!row.IsActive && row.State == "Closed", "vanished socket is closed");
        Check(s.Query(new ConnectionFilter { ActiveOnly = true }, ConnectionColumn.Time, true).Count == 0, "active-only filter");

        var q = new ConnectionStore();
        q.Add(Blocked(@"C:\zeta.exe", remote: "10.0.0.1"));
        q.Add(Blocked(@"C:\alpha.exe", remote: "9.0.0.1", d: TrafficDirection.Inbound));
        q.Add(new FirewallEvent { TimeUtc = DateTime.UtcNow, Verdict = Verdict.Accepted, AppPath = @"C:\mid.exe", Direction = TrafficDirection.Outbound, Protocol = "UDP", LocalIp = "192.168.1.5", LocalPort = 1, RemoteIp = "1.1.1.1", RemotePort = 53 });
        Check(q.Query(new ConnectionFilter(), ConnectionColumn.Process, true)[0].ProcessName == "alpha.exe", "sort by process");
        Check(q.Query(new ConnectionFilter(), ConnectionColumn.Process, false)[0].ProcessName == "zeta.exe", "sort descending");
        var byIp = q.Query(new ConnectionFilter(), ConnectionColumn.RemoteIp, true).Select(x => x.RemoteIp).ToList();
        Check(byIp.SequenceEqual(new[] { "1.1.1.1", "9.0.0.1", "10.0.0.1" }), "IP sort is numeric");
        Check(q.Query(new ConnectionFilter { Verdict = Verdict.Accepted }, ConnectionColumn.Time, true).Single().Protocol == "UDP", "verdict filter");
        Check(q.Query(new ConnectionFilter { Direction = TrafficDirection.Inbound }, ConnectionColumn.Time, true).Single().ProcessName == "alpha.exe", "direction filter");
        Check(q.Query(new ConnectionFilter { Protocol = "udp" }, ConnectionColumn.Time, true).Count == 1, "protocol filter");
        Check(q.Query(new ConnectionFilter { Text = "ZETA 443" }, ConnectionColumn.Time, true).Count == 1, "search terms AND together");
        Check(q.Query(new ConnectionFilter { Text = "zeta 53" }, ConnectionColumn.Time, true).Count == 0, "search terms exclude");
        q.Clear();
        Check(q.Count == 0, "clear history");

        var capped = new ConnectionStore(100);
        for (var i = 0; i < 1000; i++) capped.Add(Blocked(@"C:\a.exe", lport: i));
        Check(capped.Count <= 100, "history is bounded");
    }

    private static void Translator()
    {
        var both = RuleTranslator.ForApp(new AppRule { AppPath = @"C:\a.exe", Action = RuleAction.Allow }).ToList();
        Check(both.Count == 2 && both.All(x => x.Allow && x.AppPath == @"C:\a.exe"), "both directions make two rules");
        Check(both.Select(x => x.Name).Distinct().Count() == 2, "rule names unique");
        var inOnly = RuleTranslator.ForApp(new AppRule { AppPath = @"C:\a.exe", Action = RuleAction.Block, Direction = RuleDirection.Inbound }).Single();
        Check(!inOnly.Allow && inOnly.Direction == TrafficDirection.Inbound, "block inbound only");
        Check(!RuleTranslator.ForApp(new AppRule { AppPath = @"C:\a.exe", Enabled = false }).Any(), "disabled rule emits nothing");
        var ess = RuleTranslator.Essentials();
        Check(ess.Any(x => x.Service == "Dnscache" && x.RemotePorts == "53") && ess.Any(x => x.Service == "Dhcp"), "essentials have DNS and DHCP");
        Check(ess.Where(x => x.AppPath != null).All(x => x.Service != null), "essentials never open all of svchost");
        Check(ess.Select(x => x.Name).Distinct().Count() == ess.Count, "essential names unique");
        Check(RuleTranslator.All(new AppConfig { AllowEssentials = false }).Count == 0, "essentials optional");
    }

    private static void Enforcement()
    {
        var b = new FakeBackend();
        var s = NewService(b);
        Check(!s.IsEnabled && s.Mode == RunMode.Live, "starts off until the user consents");
        s.Config.Rules.Add(new AppRule { AppPath = @"C:\a.exe" });
        Wait(s.EnableAsync());
        Check(s.IsEnabled && b.Blocking, "enable blocks");
        Check(b.Calls.IndexOf("capture") < b.Calls.IndexOf("disableRules"), "snapshot before changes");
        Check(b.Calls.IndexOf("add") < b.Calls.IndexOf("block"), "rules exist before default block");
        Check(b.Foreign.Count == 0, "foreign allow rules disabled");
        Check(s.Config.Snapshot.DisabledRuleKeys.SequenceEqual(new[] { "RDP", "Bonjour" }), "disabled rules recorded");
        Check(b.Managed.Any(x => x.AppPath == @"C:\a.exe") && b.Managed.Any(x => x.Service == "Dnscache"), "app and essential rules installed");

        Wait(s.DisableAsync());
        Check(!s.IsEnabled && !b.Blocking, "disable restores defaults");
        Check(b.Foreign.Contains("RDP") && b.Foreign.Contains("Bonjour"), "foreign rules back on");
        Check(b.Managed.Count == 0, "managed rules removed");
        Check(s.Config.Snapshot == null, "snapshot cleared after restore");

        var f = new FakeBackend { FailOn = "block" };
        var s2 = NewService(f);
        Throws(() => Wait(s2.EnableAsync()), "enable failure surfaces");
        Check(!s2.IsEnabled, "failed enable reports off");
        Check(f.Calls.Contains("restore") && f.Foreign.Contains("RDP") && f.Managed.Count == 0, "failed enable rolls back");

        var f2 = new FakeBackend();
        var s3 = NewService(f2);
        Wait(s3.EnableAsync());
        f2.FailOn = "restore";
        Throws(() => Wait(s3.DisableAsync()), "restore failure surfaces");
        Check(s3.IsEnabled && s3.Config.Snapshot != null, "failed restore keeps snapshot and state");
        f2.FailOn = null;
        Wait(s3.DisableAsync());
        Check(!s3.IsEnabled && !f2.Blocking, "restore can be retried");

        // Reconcile: tampering is undone.
        var r = new FakeBackend();
        var s4 = NewService(r);
        Wait(s4.EnableAsync());
        r.Foreign.Add("Installer rule");
        r.Blocking = false;
        var n = s4.ReconcileAsync(false).GetAwaiter().GetResult();
        Check(n == 1 && r.Foreign.Count == 0 && r.Blocking, "reconcile disables new allow rule and re-blocks");
        Check(s4.Config.Snapshot.DisabledRuleKeys.Contains("Installer rule"), "new rule recorded for restore");

        // Lost config while enforcing must not record the block state as "original".
        var l = new FakeBackend { Blocking = true };
        l.Managed.Add(new FirewallRuleSpec { Name = "EasyFW: old [abc] Out" });
        var s5 = NewService(l);
        Wait(s5.EnableAsync());
        Check(s5.Config.Snapshot.DefaultOutbound.All(x => x == 1), "lost config restores to allow-outbound");
        Check(!l.Calls.Contains("capture"), "tainted state not captured");

        // --restore with no config but EasyFW rules present must still recover.
        var l2 = new FakeBackend { Blocking = true };
        l2.Managed.Add(new FirewallRuleSpec { Name = "EasyFW: old [abc] Out" });
        var s6 = NewService(l2);
        Wait(s6.DisableAsync());
        Check(!l2.Blocking && l2.Managed.Count == 0, "recovery works without a snapshot");

        // --restore on a PC EasyFW never touched must change nothing.
        var l3 = new FakeBackend();
        Wait(NewService(l3).DisableAsync());
        Check(!l3.Calls.Contains("restore"), "restore is a no-op when nothing was applied");

        // The one-minute check can fire during a slow turn-off, and must not block everything again afterwards.
        var q = new FakeBackend();
        var s7 = NewService(q);
        Wait(s7.EnableAsync());
        Check(!s7.IsBusy && s7.CanChange && s7.Activity == null, "not busy once enabled");
        q.HoldRestore = new System.Threading.ManualResetEventSlim(false);
        var turningOff = s7.DisableAsync();
        Check(s7.IsBusy && !s7.CanChange && s7.ActivityTitle == "Turning protection off", "busy during turn-off");
        Check(s7.ReconcileAsync(false).GetAwaiter().GetResult() == 0, "check is skipped during turn-off");
        q.HoldRestore.Set();
        Wait(turningOff);
        Check(!s7.IsEnabled && !q.Blocking && q.Foreign.Contains("RDP") && s7.Config.Snapshot == null, "turn-off stays off");
        Check(!s7.IsBusy && s7.ActivityTitle == null, "not busy after turn-off");

        // A failed switch must clear the busy state, or the buttons stay disabled for good.
        var q2 = new FakeBackend { FailOn = "block" };
        var s8 = NewService(q2);
        Throws(() => Wait(s8.EnableAsync()), "failed enable surfaces");
        Check(!s8.IsBusy && s8.CanChange, "failed enable clears busy");

        // An enable that died part-way finishes on the next start, keeping the original snapshot for restore.
        var q3 = new FakeBackend();
        var s9 = NewService(q3);
        s9.Config.Snapshot = q3.CaptureState();
        s9.Config.Snapshot.DisabledRuleKeys.Add("Lost");
        q3.Calls.Clear();
        Wait(s9.EnableAsync());
        Check(s9.IsEnabled && q3.Blocking && !q3.Calls.Contains("capture"), "interrupted enable finishes without recapturing");
        Check(s9.Config.Snapshot.DisabledRuleKeys.Contains("Lost") && s9.Config.Snapshot.DisabledRuleKeys.Contains("RDP"), "interrupted enable keeps earlier rules for restore");
        Wait(s9.DisableAsync());
        Check(q3.Foreign.Contains("Lost"), "restore after finished enable puts rules back");

        // The startup check must turn logging back on, or blocked attempts vanish after an interrupted turn-off.
        var q4 = new FakeBackend();
        var s10 = NewService(q4);
        Wait(s10.EnableAsync());
        q4.Calls.Clear();
        s10.ReconcileAsync(true).GetAwaiter().GetResult();
        Check(q4.Calls.Contains("audit"), "startup check re-enables logging");
        q4.Calls.Clear();
        s10.ReconcileAsync(false).GetAwaiter().GetResult();
        Check(!q4.Calls.Contains("audit"), "one-minute check doesn't run auditpol");

        // Exiting stops protection, including a switch that never finished.
        var x = new FakeBackend();
        var s11 = NewService(x);
        Check(!s11.NeedsRestoreOnExit, "nothing to restore on a clean exit");
        Wait(s11.EnableAsync());
        Check(s11.NeedsRestoreOnExit, "exit restores while protection is on");
        Wait(s11.DisableAsync());
        Check(!s11.NeedsRestoreOnExit, "nothing to restore once off");
        s11.Config.Snapshot = x.CaptureState();
        Check(s11.NeedsRestoreOnExit, "exit finishes an interrupted switch");
        Check(!new FirewallService(new ConfigStore(null, true), new FakeBackend(), RunMode.MonitorOnly).NeedsRestoreOnExit, "monitor-only restores nothing");

        // services.exe is protected, so this shows the path lookup works where opening the process is refused.
        var protectedPid = System.Diagnostics.Process.GetProcessesByName("services")[0].Id;
        var protectedPath = DevicePaths.ToDosPath(ProcessInfoCache.ImagePathWithoutHandle(protectedPid));
        Check(protectedPath != null && protectedPath.EndsWith(@"\system32\services.exe", StringComparison.OrdinalIgnoreCase), "protected process path resolves");
        Check(string.IsNullOrEmpty(ProcessInfoCache.ImagePathWithoutHandle(int.MaxValue - 3)), "missing process has no path");

        var missing = WindowsServiceInfo.Read("EasyFWNoSuchService", "Fallback");
        Check(missing.Status == "Not found" && !missing.IsRunning && missing.DisplayName == "Fallback", "missing service is reported, not thrown");
        Check(WindowsServiceInfo.FirewallServices.Any(s => s.Service == "MpsSvc") && WindowsServiceInfo.FirewallServices.Any(s => s.Service == "BFE"), "notice names the firewall services");

        OpenConnections();
        Filters();
        PingRules();
        Traffic();

        var mon = new FirewallService(new ConfigStore(null, true), new FakeBackend(), RunMode.MonitorOnly);
        Check(!mon.CanChange, "monitor-only can't change");
        Throws(() => Wait(mon.EnableAsync()), "monitor-only can't enable");
        Throws(() => Wait(mon.SaveRuleAsync(new AppRule { AppPath = @"C:\a.exe" })), "monitor-only can't edit rules");
    }

    private static ActiveEndpoint Open(string path, TrafficDirection d = TrafficDirection.Outbound, string state = "Established", string proto = "TCP", string remote = "8.8.8.8", int port = 443, int pid = 100) => new ActiveEndpoint
    {
        Protocol = proto, State = state, Pid = pid, AppPath = path, ProcessName = "x", Direction = d,
        LocalIp = "192.168.1.5", LocalPort = 50000, RemoteIp = remote, RemotePort = port
    };

    private static void OpenConnections()
    {
        const string approved = @"C:\ok.exe", other = @"C:\other.exe";
        const string svchost = @"C:\Windows\System32\svchost.exe";
        var s = NewService(new FakeBackend());
        Check(s.FindDisallowed(new[] { Open(other) }).Count == 0, "nothing closed while protection is off");
        Wait(s.EnableAsync());
        Wait(s.DecideAsync(approved, RuleAction.Allow));
        Check(s.FindDisallowed(new[] { Open(other) }).Count == 1, "open connection with no rule is closed");
        Check(s.FindDisallowed(new[] { Open(approved) }).Count == 0, "approved app keeps its connection");
        Check(s.FindDisallowed(new[] { Open(other, remote: "127.0.0.1") }).Count == 0, "loopback left alone");
        Check(s.FindDisallowed(new[] { Open(other, state: "Listening") }).Count == 0, "listeners left alone");
        Check(s.FindDisallowed(new[] { Open(other, proto: "UDP") }).Count == 0, "UDP has no connection to close");
        Check(s.FindDisallowed(new[] { Open("", pid: 0) }).Count == 0, "no process left alone");
        Check(s.FindDisallowed(new[] { Open(svchost, port: 53) }).Count == 0, "essential DNS kept");
        Check(s.FindDisallowed(new[] { Open(svchost, port: 443) }).Count == 1, "other svchost traffic closed");

        // Direction matters: an app allowed out only must lose its inbound connections.
        Wait(s.SaveRuleAsync(new AppRule { AppPath = @"C:\out.exe", Direction = RuleDirection.Outbound }));
        Check(s.FindDisallowed(new[] { Open(@"C:\out.exe") }).Count == 0, "outbound rule keeps outbound");
        Check(s.FindDisallowed(new[] { Open(@"C:\out.exe", TrafficDirection.Inbound) }).Count == 1, "outbound rule closes inbound");

        Wait(s.DecideAsync(approved, RuleAction.Block));
        Check(s.FindDisallowed(new[] { Open(approved) }).Count == 1, "Block Always closes open connection");

        var added = s.ReportClosed(new[] { Open(other) });
        Check(added.Count == 1 && added[0].AppPath == other, "closed connection becomes a request");
        Check(s.Connections.Query(new ConnectionFilter(), ConnectionColumn.Time, false)[0].Verdict == Verdict.Blocked, "closed connection shows blocked");

        var e = new FakeBackend();
        var off = NewService(e);
        Wait(off.EnableAsync());
        e.HoldRestore = new System.Threading.ManualResetEventSlim(false);
        var turningOff = off.DisableAsync();
        Check(off.FindDisallowed(new[] { Open(other) }).Count == 0, "nothing closed during turn-off");
        e.HoldRestore.Set();
        Wait(turningOff);
    }

    private static void Filters()
    {
        var chrome = new PendingRequest { AppPath = @"C:\Program Files\Chrome\chrome.exe", SawOutbound = true, LastProtocol = "TCP", LastRemote = "1.2.3.4:443" };
        var ping = new PendingRequest { AppPath = AppPaths.PingApp, SawOutbound = true, SawInbound = true, LastProtocol = "ICMP", LastRemote = "10.0.0.5:0" };
        var old = new PendingRequest { AppPath = @"C:\old.exe", SawInbound = true };

        Check(new PendingFilter().Matches(chrome) && new PendingFilter().Matches(old), "empty pending filter shows everything");
        Check(new PendingFilter { Text = "CHROME" }.Matches(chrome) && !new PendingFilter { Text = "chrome" }.Matches(ping), "pending search ignores case");
        Check(new PendingFilter { Text = "10.0.0.5" }.Matches(ping), "pending search covers destination");
        Check(new PendingFilter { Text = "program 1.2.3" }.Matches(chrome) && !new PendingFilter { Text = "program 9.9" }.Matches(chrome), "every word must match");
        Check(new PendingFilter { Direction = TrafficDirection.Outbound }.Matches(chrome) && !new PendingFilter { Direction = TrafficDirection.Inbound }.Matches(chrome), "pending direction");
        Check(new PendingFilter { Direction = TrafficDirection.Inbound }.Matches(ping) && new PendingFilter { Direction = TrafficDirection.Outbound }.Matches(ping), "in + out request matches either direction");
        Check(new PendingFilter { Protocol = "ICMP" }.Matches(ping) && !new PendingFilter { Protocol = "ICMP" }.Matches(chrome), "pending protocol");
        Check(!new PendingFilter { Protocol = "ICMP" }.Matches(new PendingRequest { LastProtocol = "ICMPv6" }), "ICMP and ICMPv6 are separate filters");
        Check(!new PendingFilter { Protocol = "TCP" }.Matches(old), "request with no protocol doesn't match one");

        var allow = new AppRule { AppPath = @"C:\ok.exe", Notes = "work laptop" };
        var block = new AppRule { AppPath = @"C:\bad.exe", Action = RuleAction.Block, Direction = RuleDirection.Outbound, Enabled = false };
        Check(new RuleFilter().Matches(allow) && new RuleFilter().Matches(block), "empty rule filter shows everything");
        Check(new RuleFilter { Text = "laptop" }.Matches(allow) && !new RuleFilter { Text = "laptop" }.Matches(block), "rule search covers notes");
        Check(new RuleFilter { Action = RuleAction.Block }.Matches(block) && !new RuleFilter { Action = RuleAction.Block }.Matches(allow), "rule decision");
        Check(new RuleFilter { Enabled = false }.Matches(block) && !new RuleFilter { Enabled = true }.Matches(block), "rule state");
        Check(new RuleFilter { Direction = TrafficDirection.Inbound }.Matches(allow) && !new RuleFilter { Direction = TrafficDirection.Inbound }.Matches(block), "rule direction, with In + Out matching either");
    }

    private static void PingRules()
    {
        Check(AppPaths.RuleTarget(AppPaths.SystemApp, "ICMP") == AppPaths.PingApp, "System ICMP is a ping");
        Check(AppPaths.RuleTarget(AppPaths.SystemApp, "ICMPv6") == AppPaths.PingApp, "System ICMPv6 is a ping");
        Check(AppPaths.RuleTarget(AppPaths.SystemApp, "TCP") == AppPaths.SystemApp, "System TCP stays System");
        Check(AppPaths.RuleTarget(@"C:\a.exe", "ICMP") == @"C:\a.exe", "named app stays itself");

        var specs = RuleTranslator.ForApp(new AppRule { AppPath = AppPaths.PingApp }).ToList();
        Check(specs.Count == 4 && specs.All(x => x.AppPath == null && x.IcmpTypes != null), "ping rules are ICMP for any app");
        Check(specs.Select(x => x.Name).Distinct().Count() == 4, "ping rule names are distinct");
        Check(specs.All(x => x.Name.Contains("[")), "ping rules carry a tag");
        Check(specs.Where(x => x.Protocol == FirewallProtocols.Icmp4).All(x => x.IcmpTypes == "8:*"), "IPv4 ping is echo request only");
        Check(specs.Where(x => x.Protocol == FirewallProtocols.Icmp6).All(x => x.IcmpTypes == "128:*"), "IPv6 ping is echo request only");
        Check(RuleTranslator.ForApp(new AppRule { AppPath = AppPaths.PingApp, Direction = RuleDirection.Outbound }).All(x => x.Direction == TrafficDirection.Outbound), "ping can be outbound only");

        var b = new FakeBackend();
        var s = NewService(b);
        Wait(s.EnableAsync());
        var e = Blocked(AppPaths.SystemApp);
        e.Protocol = "ICMP";
        s.ProcessEvents(new[] { e });
        Check(s.Config.Pending.Count == 1 && s.Config.Pending[0].AppPath == AppPaths.PingApp, "blocked ping asks as Ping, not System");
        Wait(s.DecideAsync(AppPaths.PingApp, RuleAction.Allow));
        Check(s.Config.Pending.Count == 0, "accepting ping clears its request");
        Check(b.Managed.Any(x => x.Protocol == FirewallProtocols.Icmp4 && x.IcmpTypes == "8:*" && x.AppPath == null), "accepting ping installs it");
        s.ProcessEvents(new[] { e });
        Check(s.Config.Pending.Count == 0, "accepted ping doesn't ask again");
        var rule = s.Config.Rules.Single(r => r.AppPath == AppPaths.PingApp);
        Wait(s.DeleteRuleAsync(rule));
        Check(!b.Managed.Any(x => x.IcmpTypes == "8:*"), "deleting ping removes all its Windows rules");

        // Requests saved by an older version must not offer to open all of System.
        var store = new ConfigStore(null, true);
        store.Config.Pending.Add(new PendingRequest { AppPath = AppPaths.SystemApp, LastProtocol = "ICMP" });
        store.Config.Pending.Add(new PendingRequest { AppPath = @"C:\a.exe", LastProtocol = "ICMP" });
        new FirewallService(store, new FakeBackend(), RunMode.Live);
        Check(store.Config.Pending[0].AppPath == AppPaths.PingApp && store.Config.Pending[1].AppPath == @"C:\a.exe", "old System ping requests migrate");
    }

    private static void Traffic()
    {
        var start = new DateTime(2026, 11, 6, 10, 0, 3, DateTimeKind.Utc);
        var store = new ConnectionStore();
        var h = new TrafficHistory();
        Check(TrafficHistory.Floor(start).Second == 0, "time floors to the window");
        Check(!h.SampleIfDue(start, store), "first call only starts a window");
        var accepted = Blocked(@"C:\a.exe");
        accepted.Verdict = Verdict.Accepted;
        store.Add(accepted);
        store.Add(accepted);
        store.Add(Blocked(@"C:\b.exe", lport: 50001));
        Check(!h.SampleIfDue(start.AddSeconds(6), store), "no sample inside a window");
        Check(h.SampleIfDue(start.AddSeconds(7), store), "sample at the window end");
        Check(h.Samples.Count == 1 && h.Samples[0].Accepted == 2 && h.Samples[0].Blocked == 1, "counts per verdict");
        Check(h.Samples[0].TimeUtc == TrafficHistory.Floor(start), "sample carries its window start");
        h.SampleIfDue(start.AddSeconds(17), store);
        Check(h.Samples[1].Accepted == 0 && h.Samples[1].Blocked == 0, "counts reset each window");
        h.SampleIfDue(start.AddSeconds(57), store);
        Check(h.Samples.Count == 6 && h.Samples.All(x => x.Accepted + x.Blocked == 0 || x.TimeUtc == h.Samples[0].TimeUtc), "missed windows count as zero");
        for (var i = 0; i < 100; i++) h.Add(new TrafficSample());
        Check(h.Samples.Count == TrafficHistory.Capacity, "history is capped");

        var active = new ConnectionStore();
        active.ApplyActive(new[] { Open(@"C:\a.exe"), Open(@"C:\a.exe", state: "Listening", remote: "*", port: 0), Open(@"C:\a.exe", state: "Bound", proto: "UDP", remote: "*", port: 0) }, start);
        Check(active.TakeCounts().Accepted == 1, "only real connections count");

        // A socket proves nothing until its connection completes, so an app with no rule must not read as accepted.
        var rows = new ConnectionStore();
        Func<ActiveEndpoint, Verdict> after = a =>
        {
            rows.ApplyActive(new[] { a }, start);
            return rows.Query(new ConnectionFilter { HideLoopback = false }, ConnectionColumn.Time, false).Single(r => r.State == a.State).Verdict;
        };
        Check(after(Open(@"C:\l.exe", state: "Listening", remote: "*", port: 0)) == Verdict.Unknown, "listening isn't accepted");
        Check(after(Open(@"C:\u.exe", state: "Bound", proto: "UDP", remote: "*", port: 0)) == Verdict.Unknown, "bound UDP isn't accepted");
        Check(after(Open(@"C:\s.exe", state: "SYN sent", remote: "2.2.2.2")) == Verdict.Unknown, "still connecting isn't accepted");
        Check(rows.TakeCounts().Accepted == 0, "unproven sockets aren't counted on the graph");

        var flip = new ConnectionStore();
        var attempt = Blocked(@"C:\b.exe");
        attempt.LocalIp = "192.168.1.5";
        attempt.LocalPort = 50000;
        attempt.RemoteIp = "8.8.8.8";
        attempt.RemotePort = 443;
        flip.Add(attempt);
        flip.ApplyActive(new[] { Open(@"C:\b.exe", state: "SYN sent") }, start);
        var row = flip.Query(new ConnectionFilter(), ConnectionColumn.Time, false).Single();
        Check(row.Verdict == Verdict.Blocked, "a blocked attempt stays blocked while its socket retries");
        flip.ApplyActive(new ActiveEndpoint[0], start);
        Check(row.Verdict == Verdict.Blocked && row.State == "Closed", "a blocked attempt stays blocked after it ends");
        flip.TakeCounts();
        flip.ApplyActive(new[] { Open(@"C:\b.exe") }, start);
        Check(row.Verdict == Verdict.Accepted && flip.TakeCounts().Accepted == 1, "a completed connection is accepted");
        active.ApplyActive(new[] { Open(@"C:\a.exe") }, start);
        Check(active.TakeCounts().Accepted == 0, "an open connection counts once");

        Check(TrafficHistory.AxisMax(0) == 4 && TrafficHistory.AxisMax(4) == 4 && TrafficHistory.AxisMax(5) == 10, "axis steps");
        Check(TrafficHistory.AxisMax(21) == 40 && TrafficHistory.AxisMax(101) == 200 && TrafficHistory.AxisMax(3000) == 4000, "axis scales");
        Check(new[] { 3, 7, 15, 33, 77, 150, 999, 12345 }.All(v => TrafficHistory.AxisMax(v) >= v && TrafficHistory.AxisMax(v) % 2 == 0), "axis top covers the value and halves cleanly");
    }

    private static void Patterns()
    {
        var folder = new PatternRule { Pattern = @"C:\Games\*.*" };
        Check(folder.Matches(@"C:\Games\x.exe") && folder.Matches(@"c:\games\Sub\Deep\y.EXE"), "folder pattern covers subfolders, any case");
        Check(!folder.Matches(@"C:\GamesX\x.exe") && !folder.Matches(@"D:\Games\x.exe"), "folder pattern stays in its folder");
        var named = new PatternRule { Pattern = @"*\updater?.exe" };
        Check(named.Matches(@"C:\a\b\updater1.exe") && !named.Matches(@"C:\a\updater.exe"), "* and ? wildcards");
        var keyword = new PatternRule { Pattern = "steam" };
        Check(keyword.IsKeyword && keyword.Matches(@"C:\Program Files (x86)\Steam\steam.exe") && !keyword.Matches(@"C:\x\stea.exe"), "keyword matches anywhere in the path");
        Check(!keyword.Matches(AppPaths.SystemApp) && !new PatternRule { Pattern = "ping" }.Matches(AppPaths.PingApp), "patterns never cover System or Ping");
        var env = new PatternRule { Pattern = @"%SystemRoot%\Temp\*" };
        Check(env.Matches(Environment.ExpandEnvironmentVariables(@"%SystemRoot%\Temp\a.exe")), "environment variables in patterns");

        var b = new FakeBackend();
        var s = NewService(b);
        var checkUntil = DateTime.UtcNow.AddSeconds(10);
        while (s.SignatureCheck(@"C:\Games\none.exe") == null && DateTime.UtcNow < checkUntil) System.Threading.Thread.Sleep(20);
        Check(s.SignatureCheck(@"C:\Games\none.exe") == false, "a missing file doesn't count as signed");
        s.SignatureCheck = _ => true;
        Throws(() => s.SavePattern(new PatternRule { Pattern = "ab" }), "keyword under 3 letters refused");
        Throws(() => s.SavePattern(new PatternRule { Pattern = @"*\*.*" }), "match-everything pattern refused");
        Throws(() => s.SavePattern(new PatternRule { Pattern = "  " }), "empty pattern refused");

        s.ProcessEvents(new[] { Blocked(@"C:\Games\old.exe") });
        Wait(s.DecideAsync(@"C:\Games\mine.exe", RuleAction.Block));
        s.SavePattern(new PatternRule { Pattern = @"C:\Games\*.*", Action = RuleAction.Allow });
        Check(s.PatternPreview(s.Config.Patterns[0]).Count == 2, "preview lists pending and ruled apps");
        Wait(s.ApplyPatternsAsync());
        Check(s.FindRule(@"C:\Games\old.exe")?.Action == RuleAction.Allow && s.PendingCount == 0, "saving a pattern decides matching pending apps");
        Check(s.FindRule(@"C:\Games\mine.exe").Action == RuleAction.Block, "an app's own rule wins over a pattern");

        var added = s.ProcessEvents(new[] { Blocked(@"C:\Games\new\n.exe") });
        Check(added.Count == 0, "a matching new app doesn't notify");
        Wait(s.ApplyPatternsAsync());
        var made = s.FindRule(@"C:\Games\new\n.exe");
        Check(made != null && made.Action == RuleAction.Allow && made.Notes.Contains(@"C:\Games\*.*") && s.PendingCount == 0, "a matching signed app gets its own rule");

        // Accept only goes to signed apps. Unsigned stays pending; one still being checked waits.
        var signatures = new Dictionary<string, bool?>(StringComparer.OrdinalIgnoreCase) { [@"C:\Games\unsigned.exe"] = false, [@"C:\Games\slow.exe"] = null };
        s.SignatureCheck = path => signatures.TryGetValue(path, out var v) ? v : true;
        s.ProcessEvents(new[] { Blocked(@"C:\Games\unsigned.exe"), Blocked(@"C:\Games\slow.exe") });
        Wait(s.ApplyPatternsAsync());
        Check(s.FindRule(@"C:\Games\unsigned.exe") == null && s.Config.Pending.Any(p => p.AppPath == @"C:\Games\unsigned.exe"), "an unsigned app isn't accepted and stays pending");
        Check(s.FindRule(@"C:\Games\slow.exe") == null && s.Config.Pending.Any(p => p.AppPath == @"C:\Games\slow.exe"), "an app still being checked waits");
        s.ProcessEvents(new[] { Blocked(@"C:\Games\unsigned.exe") });
        Wait(s.ApplyPatternsAsync());
        Check(s.FindRule(@"C:\Games\unsigned.exe") == null, "an unsigned app isn't tried again");
        signatures[@"C:\Games\slow.exe"] = true;
        Wait(s.ApplyPatternsAsync());
        Check(s.FindRule(@"C:\Games\slow.exe")?.Action == RuleAction.Allow, "accepted once the check says signed");
        Wait(s.DecideAsync(@"C:\Games\unsigned.exe", RuleAction.Block));

        s.SavePattern(new PatternRule { Pattern = "games", Action = RuleAction.Block });
        s.ProcessEvents(new[] { Blocked(@"C:\Games\both.exe") });
        Wait(s.ApplyPatternsAsync());
        Check(s.FindRule(@"C:\Games\both.exe")?.Action == RuleAction.Block, "block pattern wins when both match");

        s.DeletePattern(s.Config.Patterns.First(p => p.Pattern == "games"));
        s.Config.Patterns[0].Enabled = false;
        s.ProcessEvents(new[] { Blocked(@"C:\Games\later.exe") });
        Wait(s.ApplyPatternsAsync());
        Check(s.FindRule(@"C:\Games\later.exe") == null && s.PendingCount == 1, "a disabled pattern does nothing");

        var store = new ConfigStore(null, true);
        store.Config.Patterns.Add(new PatternRule { Pattern = "steam", Action = RuleAction.Block });
        var json = Encoding.UTF8.GetString(ConfigStore.Serialize(store.Config));
        Check(json.Contains("\"Patterns\"") && json.Contains("steam"), "patterns are saved");
    }

    private static void Signatures()
    {
        var notepad = Environment.ExpandEnvironmentVariables(@"%SystemRoot%\System32\notepad.exe");
        var text = AppSignature.Check(notepad);
        Check(text.StartsWith("Yes"), "Windows program is signed (catalog or embedded): " + text);
        var tmp = Path.Combine(Path.GetTempPath(), "easyfw-unsigned-" + Guid.NewGuid().ToString("N") + ".exe");
        File.WriteAllBytes(tmp, File.ReadAllBytes(notepad).Take(4096).ToArray());
        try { Check(!AppSignature.Check(tmp).StartsWith("Yes"), "part of a program isn't signed: " + AppSignature.Check(tmp)); }
        finally { File.Delete(tmp); }
        var own = typeof(Tests).Assembly.Location;
        Check(AppSignature.Check(own) == "No", "unsigned build reads No: " + AppSignature.Check(own));
        Check(AppSignature.Check(@"C:\nope\missing.exe") == "File missing", "missing file");
        Check(AppSignature.Text(AppPaths.PingApp).StartsWith("Yes"), "pseudo apps count as Windows");
        var until = DateTime.UtcNow.AddSeconds(20);
        while (AppSignature.Text(notepad) == "" && DateTime.UtcNow < until) System.Threading.Thread.Sleep(20);
        Check(AppSignature.Text(notepad).StartsWith("Yes"), "background check finishes");
    }

    private static void ColumnLayouts()
    {
        var s = NewService(new FakeBackend());
        ListView NewList()
        {
            var l = new ListView { View = View.Details };
            l.Columns.Add("A", 50);
            l.Columns.Add("B", 60);
            l.Columns.Add("C", 70);
            l.CreateControl();
            var unused = l.Handle;
            return l;
        }

        var first = NewList();
        UiHelpers.RememberColumns(first, "t", s);
        Check(first.AllowColumnReorder, "columns can be dragged");
        first.Columns[1].Width = 99;
        var saved = s.Config.ColumnsFor("t");
        Check(saved != null && saved.Widths[1] == 99 && saved.Order.SequenceEqual(new[] { 0, 1, 2 }), "a width change is saved");

        s.SaveColumns("t", new[] { 2, 0, 1 }, new[] { 51, 61, 71 });
        var json = ConfigStore.Serialize(s.Config);
        var store = new ConfigStore(null, true);
        store.Config.Columns = ConfigStore.Deserialize(json).Columns;
        var s2 = new FirewallService(store, new FakeBackend(), RunMode.Live);
        var second = NewList();
        UiHelpers.RememberColumns(second, "t", s2);
        Check(second.Columns[0].DisplayIndex == 2 && second.Columns[1].DisplayIndex == 0 && second.Columns[2].DisplayIndex == 1, "saved order comes back after a restart");
        Check(second.Columns[0].Width == 51 && second.Columns[2].Width == 71, "saved widths come back");
        Check(s2.Config.ColumnsFor("t").Order.SequenceEqual(new[] { 2, 0, 1 }), "applying a layout doesn't overwrite it");

        s2.SaveColumns("t", new[] { 0, 1, 2, 3 }, new[] { 1, 2, 3, 4 });
        var third = NewList();
        UiHelpers.RememberColumns(third, "t", s2);
        Check(third.Columns[0].DisplayIndex == 0 && third.Columns[0].Width == 50, "a layout for other columns is ignored");

        s2.SaveColumns("t", new[] { 1, 1, 0 }, null);
        var fourth = NewList();
        UiHelpers.RememberColumns(fourth, "t", s2);
        Check(fourth.Columns[2].DisplayIndex == 2, "a broken layout is ignored");

        UiHelpers.ResetColumns();
        Check(second.Columns[0].DisplayIndex == 0 && second.Columns[0].Width == 50 && s2.Config.ColumnsFor("t") == null, "reset puts columns back and forgets the layout");
        foreach (var l in new[] { first, second, third, fourth }) l.Dispose();
    }

    private static void PublicIpAndLocation()
    {
        Check(PublicIp.IsPublic("8.8.8.8") && PublicIp.IsPublic("2001:4860::8888"), "public addresses are accepted");
        Check(!PublicIp.IsPublic("192.168.1.5") && !PublicIp.IsPublic("10.1") && !PublicIp.IsPublic("<html>") && !PublicIp.IsPublic(""), "LAN, short forms and junk aren't");

        var asked = new List<string>();
        var fetch = PublicIp.Fetch;
        try
        {
            PublicIp.Fetch = url =>
            {
                asked.Add(url);
                if (asked.Count == 1) throw new System.Net.WebException("down");
                return Task.FromResult(asked.Count == 2 ? "<html>error</html>" : " 8.8.4.4\n");
            };
            PublicIp.RefreshAsync().Wait();
            Check(PublicIp.Address == "8.8.4.4" && !PublicIp.Failed && asked.Count == 3, "lookup falls back to the next service and trims the answer");

            asked.Clear();
            PublicIp.Fetch = url => { asked.Add(url); return Task.FromResult("192.168.0.1"); };
            PublicIp.RefreshAsync().Wait();
            Check(PublicIp.Failed && asked.Count == PublicIp.Services.Length, "no public answer: failed after trying every service");
        }
        finally
        {
            PublicIp.Fetch = fetch;
            PublicIp.Set(null);
        }

        var cfg = new AppConfig();
        var self = RuleTranslator.SelfPath;
        try
        {
            RuleTranslator.SelfPath = @"C:\Program Files\EasyFW\EasyFW.exe";
            var rule = RuleTranslator.All(cfg).SingleOrDefault(r => r.AppPath == RuleTranslator.SelfPath);
            Check(rule != null && rule.Allow && rule.Direction == TrafficDirection.Outbound && rule.Protocol == FirewallProtocols.Tcp && rule.RemotePorts == "443",
                "EasyFW may make HTTPS calls for its public IP, nothing else");
            cfg.NoPublicIpLookup = true;
            Check(RuleTranslator.All(cfg).All(r => r.AppPath != RuleTranslator.SelfPath), "turning the lookup off removes that rule");
        }
        finally { RuleTranslator.SelfPath = self; }
        Check(RuleTranslator.All(new AppConfig()).All(r => r.AppPath == null || !r.AppPath.EndsWith("EasyFW.exe")), "no rule for EasyFW when its path isn't known");

        var cairo = WorldGeo.FindCity("eg", "cairo");
        Check(cairo != null && cairo.Name == "Cairo" && Math.Abs(cairo.Lat - 30) < 1, "cities are found, any case");
        Check(WorldGeo.CitiesOf("US").Count > 10 && WorldGeo.CitiesOf("US").Select(c => c.Name).SequenceEqual(WorldGeo.CitiesOf("US").Select(c => c.Name).OrderBy(n => n, StringComparer.CurrentCultureIgnoreCase)),
            "a country's cities are sorted by name");
        Check(WorldGeo.FindCity("US", "Ho Chi Minh City") == null && WorldGeo.FindCity("VN", "Ho Chi Minh City") != null, "city names with spaces belong to their own country");
        var badCities = WorldGeo.Countries.SelectMany(WorldGeo.CitiesOf).Where(c => !WorldGeo.TryLocate(c.Country, out _, out _) || c.Lat > WorldGeo.North || c.Lat < WorldGeo.South).ToList();
        Check(badCities.Count == 0, "every city is on the map in a known country: " + string.Join(",", badCities.Select(c => c.Name)));

        var s = NewService(new FakeBackend());
        s.SetMapHome("EG", "Alexandria");
        var loc = s.Location;
        Check(loc.Source == LocationSource.Chosen && loc.City == "Alexandria" && Math.Abs(loc.Lat - 31.2) < 0.1 && loc.Text.StartsWith("Alexandria, "), "chosen city");
        s.SetMapHome("EG", "Atlantis");
        Check(s.Location.City == null && s.Location.Country == "EG", "an unknown city means the whole country");
        s.SetMapHome(null);
        PublicIp.Set("8.8.8.8");
        try
        {
            var expected = IpInfo.CountryCode("8.8.8.8");
            Check(expected == null || s.Location.Source == LocationSource.PublicIp && s.Location.Country == expected, "public IP country comes before the Windows region");
            s.Config.NoPublicIpLookup = true;
            Check(s.Location.Source != LocationSource.PublicIp, "with the lookup off, the public IP isn't used");
        }
        finally { PublicIp.Set(null); }
    }

    private static void RuleDurationsTest()
    {
        var b = new FakeBackend();
        var s = NewService(b);
        Wait(s.EnableAsync());
        var now = new DateTime(2026, 11, 20, 12, 0, 0, DateTimeKind.Utc);
        var boot = now.AddHours(-3);
        s.Clock = () => now;
        s.BootTime = () => boot;

        Wait(s.DecideAsync(@"C:\a.exe", RuleAction.Allow, null, RuleDuration.Minutes10));
        Wait(s.DecideAsync(@"C:\b.exe", RuleAction.Allow, null, RuleDuration.UntilRestart));
        Wait(s.DecideAsync(@"C:\c.exe", RuleAction.Block, null, RuleDuration.Hour1));
        Wait(s.DecideAsync(@"C:\d.exe", RuleAction.Allow));
        var a = s.FindRule(@"C:\a.exe");
        Check(a.ExpiresUtc == now.AddMinutes(10) && a.BootUtc == null && a.IsTemporary, "10 minutes ends 10 minutes from now");
        Check(s.FindRule(@"C:\b.exe").BootUtc == boot && s.FindRule(@"C:\b.exe").ExpiresUtc == null, "until restart remembers this boot");
        Check(!s.FindRule(@"C:\d.exe").IsTemporary, "Accept Always is forever");
        Check(a.ExpiresText(now) == $"In 10 min ({now.AddMinutes(10).ToLocalTime():HH:mm})" && s.FindRule(@"C:\b.exe").ExpiresText(now) == "At restart"
              && s.FindRule(@"C:\d.exe").ExpiresText(now) == "Never", "Expires column text");
        Check(s.Evaluate(@"C:\a.exe", TrafficDirection.Outbound, 443) == Verdict.Accepted, "accepted while it lasts");

        now = now.AddMinutes(9);
        Check(Wait2(s.ExpireRulesAsync()).Count == 0 && s.Config.Rules.Count == 4, "nothing ends early");

        now = now.AddMinutes(1);
        var ended = Wait2(s.ExpireRulesAsync());
        Check(ended.Count == 1 && ended[0].AppPath == @"C:\a.exe" && s.FindRule(@"C:\a.exe") == null, "the rule ends on time");
        Check(s.Evaluate(@"C:\a.exe", TrafficDirection.Outbound, 443) == Verdict.Blocked, "and the app is blocked again");
        Check(b.Managed.All(r => r.AppPath != @"C:\a.exe"), "its Windows rules are gone");

        boot = boot.AddSeconds(70);
        Check(Wait2(s.ExpireRulesAsync()).Count == 0, "a clock change of a minute isn't a restart");
        boot = now.AddMinutes(-2);
        ended = Wait2(s.ExpireRulesAsync());
        Check(ended.Count == 1 && ended[0].AppPath == @"C:\b.exe", "until-restart ends after a restart");

        Wait(s.DecideAsync(@"C:\c.exe", RuleAction.Block));
        now = now.AddHours(2);
        Check(Wait2(s.ExpireRulesAsync()).Count == 0 && s.FindRule(@"C:\c.exe") != null && !s.FindRule(@"C:\c.exe").IsTemporary,
            "deciding again forever makes a temporary rule permanent");
        Check(s.FindRule(@"C:\d.exe") != null, "permanent rules never end");

        Wait(s.DecideAsync(@"C:\e.exe", RuleAction.Allow, null, RuleDuration.Minutes30));
        var copy = ConfigStore.Deserialize(ConfigStore.Serialize(s.Config)).Rules.Single(r => r.AppPath == @"C:\e.exe");
        Check(copy.ExpiresUtc == now.AddMinutes(30) && copy.IsTemporary, "the end time is saved");

        Check(RuleDurations.ActionText(RuleAction.Allow, RuleDuration.Forever) == "Accept Always"
              && RuleDurations.ActionText(RuleAction.Block, RuleDuration.Minutes10) == "Block for 10 min"
              && RuleDurations.ActionText(RuleAction.Allow, RuleDuration.UntilRestart) == "Accept until restart", "button names");
        Check(SystemBoot.Utc() < DateTime.UtcNow && SystemBoot.Utc() > DateTime.UtcNow.AddYears(-1), "boot time is read from Windows");
    }

    private static T Wait2<T>(Task<T> t)
    {
        Wait(t);
        return t.Result;
    }

    private static void Updates()
    {
        Check(Updater.ParseTag("v2.1.0") == new Version(2, 1, 0) && Updater.ParseTag("2.1") == new Version(2, 1, 0) && Updater.ParseTag("latest") == null, "release tags read as versions");
        string Json(string tag, bool draft = false, bool pre = false, string url = null, string digest = null) =>
            "{\"tag_name\":\"" + tag + "\",\"html_url\":\"https://github.com/" + Updater.Repo + "/releases/tag/" + tag + "\",\"draft\":" + (draft ? "true" : "false") +
            ",\"prerelease\":" + (pre ? "true" : "false") + ",\"assets\":[{\"name\":\"notes.md\",\"browser_download_url\":\"https://github.com/" + Updater.Repo + "/releases/download/x/notes.md\",\"size\":5}," +
            "{\"name\":\"EasyFW-" + tag.TrimStart('v') + "-windows.zip\",\"browser_download_url\":\"" + (url ?? "https://github.com/" + Updater.Repo + "/releases/download/" + tag + "/EasyFW-" + tag.TrimStart('v') + "-windows.zip") +
            "\",\"size\":1234" + (digest != null ? ",\"digest\":\"" + digest + "\"" : "") + ",\"extra\":1}],\"body\":\"x\"}";
        var r = Updater.Parse(Json("v2.1.0", digest: "sha256:ABCDEF"));
        Check(r != null && r.Version == new Version(2, 1, 0) && r.ZipName == "EasyFW-2.1.0-windows.zip" && r.ZipSize == 1234 && r.Sha256 == "abcdef", "GitHub's answer is read");
        Check(Updater.Parse(Json("v2.1.0", draft: true)) == null && Updater.Parse(Json("v2.1.0", pre: true)) == null, "drafts and pre-releases are skipped");
        Check(Updater.Parse(Json("v2.1.0", url: "https://evil.example/EasyFW-2.1.0-windows.zip")) == null, "a zip from anywhere but this repo is refused");
        Check(Updater.Parse(null) == null && Updater.Parse("") == null, "no release published");
        Check(Updater.IsNewer(r, "2.0.0") && !Updater.IsNewer(r, "2.1.0") && !Updater.IsNewer(r, "2.2") && !Updater.IsNewer(null, "1.0.0"), "only a newer version updates");

        var root = Path.Combine(Path.GetTempPath(), "EasyFW-update-test-" + Guid.NewGuid().ToString("N").Substring(0, 6));
        var download = Updater.Download;
        try
        {
            var exe = typeof(AppInfo).Assembly.Location;
            var zipBytes = new MemoryStream();
            using (var zip = new System.IO.Compression.ZipArchive(zipBytes, System.IO.Compression.ZipArchiveMode.Create, true))
            {
                System.IO.Compression.ZipFileExtensions.CreateEntryFromFile(zip, exe, "EasyFW.exe");
                using (var w = new StreamWriter(zip.CreateEntry("README.md").Open())) w.Write("new readme");
                using (var w = new StreamWriter(zip.CreateEntry("sub/evil.exe").Open())) w.Write("x");
                using (var w = new StreamWriter(zip.CreateEntry("../escape.txt").Open())) w.Write("x");
            }
            var bytes = zipBytes.ToArray();
            Updater.Download = (url, path) => { File.WriteAllBytes(path, bytes); return Task.CompletedTask; };
            string Sha(byte[] b) { using var sha = System.Security.Cryptography.SHA256.Create(); return string.Concat(sha.ComputeHash(b).Select(x => x.ToString("x2"))); }

            var mine = Updater.ParseTag(AppInfo.Version);
            var good = new ReleaseInfo { Version = mine, ZipUrl = "https://github.com/x", ZipSize = bytes.Length, Sha256 = Sha(bytes) };
            var staging = Updater.StageAsync(good, Path.Combine(root, "work")).GetAwaiter().GetResult();
            var staged = Directory.GetFiles(staging).Select(Path.GetFileName).OrderBy(n => n).ToList();
            Check(staged.SequenceEqual(new[] { "EasyFW.exe", "README.md" }), "only top-level files are unpacked: " + string.Join(",", staged));
            Check(!File.Exists(Path.Combine(root, "escape.txt")) && !File.Exists(Path.Combine(root, "work", "escape.txt")), "nothing escapes the folder");

            Throws(() => Updater.StageAsync(new ReleaseInfo { Version = mine, ZipUrl = "x", Sha256 = new string('0', 64) }, Path.Combine(root, "work")).GetAwaiter().GetResult(), "a checksum mismatch stops the update");
            Throws(() => Updater.StageAsync(new ReleaseInfo { Version = mine, ZipUrl = "x", ZipSize = 5 }, Path.Combine(root, "work")).GetAwaiter().GetResult(), "a size mismatch stops the update");
            Throws(() => Updater.StageAsync(new ReleaseInfo { Version = new Version(mine.Major + 1, 0, 0), ZipUrl = "x" }, Path.Combine(root, "work")).GetAwaiter().GetResult(), "an exe of another version stops the update");

            var install = Path.Combine(root, "install");
            Directory.CreateDirectory(install);
            File.WriteAllText(Path.Combine(install, "EasyFW.exe"), "old exe");
            File.WriteAllText(Path.Combine(install, "README.md"), "old readme");
            File.WriteAllText(Path.Combine(install, "config.keep"), "mine");
            staging = Updater.StageAsync(good, Path.Combine(root, "work")).GetAwaiter().GetResult();
            Updater.Install(staging, install);
            Check(File.ReadAllText(Path.Combine(install, "README.md")) == "new readme" && new FileInfo(Path.Combine(install, "EasyFW.exe")).Length == new FileInfo(exe).Length,
                "new files are in place");
            Check(File.ReadAllText(Path.Combine(install, "EasyFW.exe.old")) == "old exe" && File.ReadAllText(Path.Combine(install, "config.keep")) == "mine", "old files kept aside, others untouched");
            Updater.CleanUp(install);
            Check(!Directory.GetFiles(install, "*.old").Any(), "old files go at the next start");

            // A failure halfway puts everything back.
            var broken = Path.Combine(root, "broken");
            Directory.CreateDirectory(broken);
            File.WriteAllText(Path.Combine(broken, "EasyFW.exe"), "newer exe");
            File.WriteAllText(Path.Combine(broken, "zz.txt"), "x");
            Directory.CreateDirectory(Path.Combine(install, "zz.txt"));
            var before = File.ReadAllBytes(Path.Combine(install, "EasyFW.exe"));
            Throws(() => Updater.Install(broken, install), "a failed install reports it");
            Check(File.ReadAllBytes(Path.Combine(install, "EasyFW.exe")).SequenceEqual(before) && !File.Exists(Path.Combine(install, "EasyFW.exe.old")), "and puts the old exe back");
        }
        finally
        {
            Updater.Download = download;
            try { Directory.Delete(root, true); } catch (IOException) { }
        }

        var cfg = new AppConfig { NoPublicIpLookup = true, Updates = UpdateChoice.Auto };
        var self = RuleTranslator.SelfPath;
        try
        {
            RuleTranslator.SelfPath = @"C:\Program Files\EasyFW\EasyFW.exe";
            Check(RuleTranslator.All(cfg).Any(x => x.AppPath == RuleTranslator.SelfPath && x.RemotePorts == "443"), "automatic updates keep EasyFW's HTTPS rule");
            cfg.Updates = UpdateChoice.Off;
            Check(RuleTranslator.All(cfg).All(x => x.AppPath != RuleTranslator.SelfPath), "with updates and the public IP off, there's no rule");
        }
        finally { RuleTranslator.SelfPath = self; }
        var saved = ConfigStore.Deserialize(ConfigStore.Serialize(new AppConfig { Updates = UpdateChoice.Auto }));
        Check(saved.Updates == UpdateChoice.Auto && new AppConfig().Updates == UpdateChoice.NotAsked, "the answer is saved, and starts unasked");
    }

    private static void CountryBlocking()
    {
        var csv = "1.0.0.0,1.0.0.255,AU\n1.0.1.0,1.0.3.255,AU\n1.0.4.0,1.0.4.0,CN\n1.0.5.0,1.0.5.255,AU\n" +
                  "2001:db8::,2001:db8::ffff,AU\n2001:db8::1:0,2001:db8::1:ffff,AU\n2001:db8::2:0,2001:db8::2:ffff,CN\n";
        var db = CountryDb.Load(new MemoryStream(Encoding.ASCII.GetBytes(csv)));
        var au = db.Ranges("au");
        Check(au.SequenceEqual(new[] { "1.0.0.0-1.0.3.255", "1.0.5.0-1.0.5.255", "2001:db8::-2001:db8::1:ffff" }), "a country's ranges, neighbours joined: " + string.Join(" ", au));
        Check(db.Ranges("CN").SequenceEqual(new[] { "1.0.4.0", "2001:db8::2:0-2001:db8::2:ffff" }) && db.Ranges("XX").Count == 0, "single addresses and unknown countries");

        var ranges = RuleTranslator.CountryRanges;
        try
        {
            RuleTranslator.CountryRanges = code => Enumerable.Range(0, code == "CN" ? 2500 : 3).Select(i => $"10.{i / 256}.{i % 256}.0-10.{i / 256}.{i % 256}.255").ToList();
            var specs = RuleTranslator.CountryRules(new AppConfig { BlockedCountries = new List<string> { "CN", "RU" } });
            Check(specs.Count == 3 * 2 + 1 * 2, "big countries split into several rules, both ways");
            Check(specs.All(x => !x.Allow && x.AppPath == null && x.Name.Contains(RuleTranslator.CountryTag)), "they block every app");
            Check(specs.Where(x => x.Name.Contains(" CN ")).Sum(x => x.RemoteAddresses.Split(',').Length) == 2500 * 2, "no range is left out");

            var b = new FakeBackend();
            var s = NewService(b);
            Wait(s.EnableAsync());
            Wait(s.DecideAsync(@"C:\app.exe", RuleAction.Allow));
            s.CountryOf = ip => ip == "5.5.5.5" ? "CN" : "US";
            Check(s.Evaluate(@"C:\app.exe", TrafficDirection.Outbound, 443, "5.5.5.5") == Verdict.Accepted, "accepted before blocking");
            Wait(s.SetBlockedCountriesAsync(new[] { "cn" }));
            Check(s.Config.BlockedCountries.SequenceEqual(new[] { "CN" }) && b.Managed.Count(x => x.Name.Contains(RuleTranslator.CountryTag)) == 6, "blocking adds the country's rules");
            Check(s.Evaluate(@"C:\app.exe", TrafficDirection.Outbound, 443, "5.5.5.5") == Verdict.Blocked
                  && s.Evaluate(@"C:\app.exe", TrafficDirection.Outbound, 443, "6.6.6.6") == Verdict.Accepted, "even an accepted app can't reach a blocked country");
            var open = new ActiveEndpoint { Protocol = "TCP", State = "Established", Pid = 5, AppPath = @"C:\app.exe", Direction = TrafficDirection.Outbound, LocalIp = "192.168.1.5", RemoteIp = "5.5.5.5", RemotePort = 443 };
            Check(s.FindDisallowed(new[] { open }).Count == 1, "open connections to it are closed");
            Wait(s.ReconcileAsync(true));
            Check(b.Managed.Count(x => x.Name.Contains(RuleTranslator.CountryTag)) == 6, "a full rebuild keeps them");
            Wait(s.SetBlockedCountriesAsync(new[] { "RU" }));
            Check(b.Managed.Count(x => x.Name.Contains(RuleTranslator.CountryTag)) == 2 && b.Managed.All(x => !x.Name.Contains(" CN ")), "unblocking removes them");
        }
        finally { RuleTranslator.CountryRanges = ranges; }
    }

    private static void LockdownAndSchedules()
    {
        var clock = RuleTranslator.LocalNow;
        try
        {
            var mondayNoon = new DateTime(2026, 11, 16, 12, 0, 0);
            var now = mondayNoon;
            RuleTranslator.LocalNow = () => now;

            var work = new AppRule { ScheduleDays = 0b0111110, ScheduleFrom = 9 * 60, ScheduleTo = 17 * 60 };
            Check(work.InSchedule(mondayNoon) && !work.InSchedule(mondayNoon.AddHours(6)) && !work.InSchedule(mondayNoon.AddDays(5)), "weekday office hours");
            Check(work.ScheduleText == "Mon-Fri 09:00-17:00", "hours text: " + work.ScheduleText);
            var night = new AppRule { ScheduleDays = 1 << (int)DayOfWeek.Friday, ScheduleFrom = 22 * 60, ScheduleTo = 2 * 60 };
            var friday = new DateTime(2026, 11, 20);
            Check(night.InSchedule(friday.AddHours(23)) && night.InSchedule(friday.AddDays(1).AddHours(1)) && !night.InSchedule(friday.AddDays(1).AddHours(3))
                  && !night.InSchedule(friday.AddDays(-1).AddHours(23)), "hours past midnight belong to the day they start");
            Check(new AppRule().InSchedule(friday) && new AppRule().ScheduleText == "Any time", "no hours means any time");

            var b = new FakeBackend();
            var s = NewService(b);
            Wait(s.EnableAsync());
            Wait(s.SaveRuleAsync(new AppRule { AppPath = @"C:\keep.exe", KeepInLockdown = true }));
            Wait(s.SaveRuleAsync(new AppRule { AppPath = @"C:\other.exe" }));
            Wait(s.SaveRuleAsync(new AppRule { AppPath = @"C:\bad.exe", Action = RuleAction.Block }));
            Wait(s.SaveRuleAsync(new AppRule { AppPath = @"C:\games.exe", ScheduleDays = 0b1111111, ScheduleFrom = 18 * 60, ScheduleTo = 22 * 60 }));
            bool Has(string app) => b.Managed.Any(x => x.AppPath == app);
            Check(Has(@"C:\keep.exe") && Has(@"C:\other.exe") && Has(@"C:\bad.exe") && !Has(@"C:\games.exe"), "an app outside its hours gets no allow rule");
            Check(s.Evaluate(@"C:\games.exe", TrafficDirection.Outbound, 443) == Verdict.Blocked, "and is blocked");

            now = mondayNoon.AddHours(7);
            var switched = Wait2(s.ApplySchedulesAsync());
            Check(switched.Count == 1 && switched[0].Allowed && Has(@"C:\games.exe") && s.Evaluate(@"C:\games.exe", TrafficDirection.Outbound, 443) == Verdict.Accepted, "its hours start: allowed");
            Check(Wait2(s.ApplySchedulesAsync()).Count == 0, "nothing more until the hours change");
            now = mondayNoon.AddHours(10).AddMinutes(1);
            switched = Wait2(s.ApplySchedulesAsync());
            Check(switched.Count == 1 && !switched[0].Allowed && !Has(@"C:\games.exe"), "its hours end: blocked again");

            Wait(s.SetLockdownAsync(true));
            Check(Has(@"C:\keep.exe") && !Has(@"C:\other.exe") && Has(@"C:\bad.exe"), "lockdown keeps only the chosen apps, and block rules");
            Check(s.Evaluate(@"C:\other.exe", TrafficDirection.Outbound, 443) == Verdict.Blocked && s.Evaluate(@"C:\keep.exe", TrafficDirection.Outbound, 443) == Verdict.Accepted, "lockdown verdicts");
            Check(s.Config.Rules.Count == 4, "lockdown doesn't change the rules");
            Wait(s.SetLockdownAppsAsync(new[] { s.FindRule(@"C:\other.exe").Id }));
            Check(Has(@"C:\other.exe") && !Has(@"C:\keep.exe"), "changing lockdown apps applies at once");
            Wait(s.SetLockdownAsync(false));
            Check(Has(@"C:\keep.exe") && Has(@"C:\other.exe") && !Has(@"C:\games.exe"), "after lockdown everything is back, hours still count");
            var saved = ConfigStore.Deserialize(ConfigStore.Serialize(s.Config));
            Check(saved.Rules.Single(x => x.AppPath == @"C:\games.exe").ScheduleTo == 22 * 60 && saved.Rules.Single(x => x.AppPath == @"C:\other.exe").KeepInLockdown, "hours and lockdown choices are saved");
        }
        finally { RuleTranslator.LocalNow = clock; }
    }

    private static void PasswordsAndFloods()
    {
        var hash = Password.Hash("s3cret");
        Check(hash.StartsWith("pbkdf2-sha256:") && !hash.Contains("s3cret"), "the password itself isn't saved");
        Check(Password.Verify("s3cret", hash) && !Password.Verify("S3cret", hash) && !Password.Verify("", hash) && !Password.Verify("s3cret", "junk"), "passwords check");
        Check(Password.Hash("s3cret") != hash, "each hash is salted");
        var s = NewService(new FakeBackend());
        Check(!s.HasPassword && s.CheckPassword("anything"), "no password: anything goes");
        s.SetPassword("1234");
        Check(s.HasPassword && s.CheckPassword("1234") && !s.CheckPassword("4321"), "service checks it");
        var guard = (Guard.Service, Guard.Prompt);
        try
        {
            Guard.Service = s;
            Guard.Prompt = false;
            Guard.Lock();
            Check(!Guard.Unlock(null, "Test"), "with a password, changes are refused without it");
            s.SetPassword(null);
            Check(Guard.Unlock(null, "Test"), "removing it lets changes through");
        }
        finally { (Guard.Service, Guard.Prompt) = guard; }

        var t = new DateTime(2026, 11, 20, 12, 0, 0, DateTimeKind.Utc);
        var f = new FloodDetector();
        FirewallEvent E(DateTime at, string app = @"C:\a.exe", string ip = "8.8.8.8", TrafficDirection d = TrafficDirection.Outbound, Verdict v = Verdict.Accepted, int port = 443)
        {
            var e = Blocked(app, d, ip);
            e.TimeUtc = at;
            e.Verdict = v;
            e.LocalPort = port;
            return e;
        }
        // Five quiet minutes: a few attempts a second.
        var quietAlerts = 0;
        for (var sec = 0; sec < 300; sec++)
            quietAlerts += f.Add(Enumerable.Range(0, 3).Select(i => E(t.AddSeconds(sec), @"C:\app" + i + ".exe")), t.AddSeconds(sec)).Count;
        Check(quietAlerts == 0, "quiet traffic raises nothing");
        var now = t.AddSeconds(305);
        var burst = Enumerable.Range(0, 500).Select(i => E(now.AddMilliseconds(-i * 10), @"C:\app" + (i % 4) + ".exe")).ToList();
        var alerts = f.Add(burst, now);
        Check(alerts.Count(a => a.Kind == FloodKind.Spike) == 1, "a sudden burst raises an alert");
        Check(f.Add(burst.Take(10).Select(e => E(now.AddSeconds(1))), now.AddSeconds(1)).All(a => a.Kind != FloodKind.Spike), "and only once per 10 minutes");

        var f2 = new FloodDetector();
        var later = t.AddMinutes(20);
        var appAlerts = f2.Add(Enumerable.Range(0, 300).Select(i => E(later.AddMilliseconds(-i * 20), @"C:\Tools\miner.exe", "9.9.9." + (i % 50))), later);
        var appAlert = appAlerts.SingleOrDefault(a => a.Kind == FloodKind.AppBurst);
        Check(appAlert != null && appAlert.Title.StartsWith("miner.exe") && appAlert.Text.Contains("50 address"), "one app opening a flood of connections is named");
        var scan = f2.Add(Enumerable.Range(0, 45).Select(i => E(later.AddMilliseconds(-i * 100), null, "203.0.113.9", TrafficDirection.Inbound, Verdict.Blocked, 20 + i)), later,
            ip => ip == "203.0.113.9" ? "Testland" : null);
        var scanAlert = scan.SingleOrDefault(a => a.Kind == FloodKind.Scan);
        Check(scanAlert != null && scanAlert.Title == "Possible port scan" && scanAlert.Text.Contains("203.0.113.9 (Testland)") && scanAlert.Text.Contains("45 ports"), "a port scan names the address");
    }

    private static void BlocklistTests()
    {
        var spamhaus = "{\"cidr\":\"1.10.16.0/20\",\"sblid\":\"SBL256894\",\"rir\":\"apnic\"}\n{\"cidr\":\"2a06:e480::/29\",\"sblid\":\"SBL1\",\"rir\":\"ripenca\"}\n" +
                       "{\"type\":\"metadata\",\"timestamp\":1716425062,\"size\":82331,\"records\":1435,\"copyright\":\"(c) 2024 The Spamhaus Project SLU\"}\n";
        Check(Blocklists.Parse(spamhaus).SequenceEqual(new[] { "1.10.16.0/20", "2a06:e480::/29" }), "Spamhaus JSON lines are read, metadata skipped: " + string.Join(" ", Blocklists.Parse(spamhaus)));
        var firehol = "#\n# firehol_level1\n#\n0.0.0.0/8\n10.0.0.0/8\n1.19.0.0/16\n127.0.0.0/8\n192.168.0.0/16\n224.0.0.0/3\n1.0.0.0/4\n45.9.20.0/24\n45.9.20.0/24\n";
        Check(Blocklists.Parse(firehol).SequenceEqual(new[] { "1.19.0.0/16", "45.9.20.0/24" }), "LAN, reserved, multicast, too-wide and repeated entries are dropped");
        Check(Blocklists.Parse("# Feodo\n# comment 1.2.3.4\n162.243.103.246\n\n50.16.16.211\r\n").SequenceEqual(new[] { "162.243.103.246/32", "50.16.16.211/32" }), "plain addresses with comments");
        Check(Blocklists.Parse("1.10.16.0/20 ; SBL256894\n").Single() == "1.10.16.0/20", "the old Spamhaus text format");
        Check(!Blocklists.IsSafe("172.16.5.0/24") && !Blocklists.IsSafe("fe80::/64") && Blocklists.IsSafe("198.51.100.7/32"), "safety check");

        var specs = RuleTranslator.BlocklistRules(Enumerable.Range(0, 1500).Select(i => $"45.{i / 256}.{i % 256}.0/24").ToList());
        Check(specs.Count == 4 && specs.All(x => !x.Allow && x.AppPath == null && x.Name.Contains(Blocklists.Tag)), "blocklist rules: split, both ways, every app");

        var folder = Path.Combine(Path.GetTempPath(), "EasyFW-bl-" + Guid.NewGuid().ToString("N").Substring(0, 6));
        var fetch = Blocklists.Fetch;
        var self = RuleTranslator.SelfPath;
        try
        {
            var pages = new Dictionary<string, string>
            {
                [Blocklists.Find("feodo").Urls[0]] = "# Feodo\n198.51.100.7\n198.51.100.8\n198.51.100.9\n45.9.20.1\n45.9.20.2\n",
                [Blocklists.Find("firehol-level1").Urls[0]] = "10.0.0.0/8\n45.9.20.0/24\n203.0.113.0/24\n45.10.0.0/16\n45.11.0.0/16\n45.12.0.0/16\n",
            };
            var asked = new List<string>();
            Blocklists.Fetch = url => { asked.Add(url); return Task.FromResult(pages.TryGetValue(url, out var t) ? t : "<html>not found</html>"); };

            Check(Blocklists.DownloadAsync(Blocklists.Find("feodo"), folder).GetAwaiter().GetResult() == 5 && File.Exists(Path.Combine(folder, "feodo.txt")), "a list downloads and is kept");
            Throws(() => Blocklists.DownloadAsync(Blocklists.Find("et-compromised"), folder).GetAwaiter().GetResult(), "a broken download is refused");
            Check(!File.Exists(Path.Combine(folder, "et-compromised.txt")), "and nothing is kept for it");

            var index = BlocklistIndex.Build(Blocklists.LoadKept(new[] { "feodo", "firehol-level1" }, folder), null);
            Check(index.Count == 5 && index.Match("198.51.100.8") == "abuse.ch Feodo Tracker" && index.Match("8.8.8.8") == null, "lookups name the list");
            Check(BlocklistIndex.Build(Blocklists.LoadKept(new[] { "feodo" }, folder), new[] { "198.51.100.8", "45.9.20.0/24" }).Entries
                  .SequenceEqual(new[] { "198.51.100.7/32", "198.51.100.9/32" }), "exceptions take out anything they touch");

            RuleTranslator.SelfPath = @"C:\Program Files\EasyFW\EasyFW.exe";
            var b = new FakeBackend();
            var s = NewService(b);
            s.BlocklistFolder = folder;
            s.Config.NoPublicIpLookup = true;
            Wait(s.EnableAsync());
            Wait(s.DecideAsync(@"C:\app.exe", RuleAction.Allow));
            Check(!b.Managed.Any(x => x.AppPath == RuleTranslator.SelfPath), "no own HTTPS rule before lists are chosen");
            asked.Clear();
            var problems = Wait2(s.SetBlocklistsAsync(new[] { "feodo", "firehol-level1", "nonsense" }, new[] { "203.0.113.50", "" }));
            Check(problems == "" && asked.Count == 1 && asked[0].Contains("firehol"), "only lists not kept yet are downloaded");
            Check(s.Config.Blocklists.SequenceEqual(new[] { "feodo", "firehol-level1" }) && s.Config.BlocklistExceptions.SequenceEqual(new[] { "203.0.113.50" }), "choices are saved, unknown ids dropped");
            Check(b.Managed.Any(x => x.AppPath == RuleTranslator.SelfPath && x.RemotePorts == "443"), "EasyFW may connect to fetch the lists");
            Check(b.Managed.Count(x => x.Name.Contains(Blocklists.Tag)) == 2, "the lists are in Windows Firewall");
            Check(s.Evaluate(@"C:\app.exe", TrafficDirection.Outbound, 443, "45.10.3.4") == Verdict.Blocked
                  && s.Evaluate(@"C:\app.exe", TrafficDirection.Outbound, 443, "203.0.113.9") == Verdict.Accepted
                  && s.Evaluate(@"C:\app.exe", TrafficDirection.Outbound, 443, "8.8.8.8") == Verdict.Accepted, "listed addresses are blocked even for accepted apps; exceptions aren't");
            Check(s.FindDisallowed(new[] { new ActiveEndpoint { Protocol = "TCP", State = "Established", Pid = 5, AppPath = @"C:\app.exe", Direction = TrafficDirection.Outbound, LocalIp = "192.168.1.5", RemoteIp = "198.51.100.7", RemotePort = 443 } }).Count == 1,
                "open connections to listed addresses are closed");
            Wait(s.ReconcileAsync(true));
            Check(b.Managed.Count(x => x.Name.Contains(Blocklists.Tag)) == 2, "a full rebuild keeps the lists");
            Check(BlocklistIndex.Current.Match("45.9.20.200") != null, "the Blocklist column sees the lists");

            pages[Blocklists.Find("feodo").Urls[0]] = "nothing useful";
            problems = Wait2(s.UpdateBlocklistsAsync());
            Check(problems.Contains("Feodo") && s.Blocklist.Match("198.51.100.7") != null && s.Config.BlocklistsUpdatedUtc != null, "a failed update keeps the last good copy");

            Wait2(s.SetBlocklistsAsync(new string[0], new string[0]));
            Check(!b.Managed.Any(x => x.Name.Contains(Blocklists.Tag)) && s.Evaluate(@"C:\app.exe", TrafficDirection.Outbound, 443, "45.10.3.4") == Verdict.Accepted, "no lists, no blocking");
            Check(!b.Managed.Any(x => x.AppPath == RuleTranslator.SelfPath), "and EasyFW's own HTTPS rule goes too");
            Throws(() => Wait2(s.SetBlocklistsAsync(new[] { "feodo" }, new[] { "not an address" })), "a bad exception is refused");
        }
        finally
        {
            Blocklists.Fetch = fetch;
            RuleTranslator.SelfPath = self;
            BlocklistIndex.Current = BlocklistIndex.Empty;
            try { Directory.Delete(folder, true); } catch (IOException) { }
        }
    }

    internal static List<ActiveEndpoint> SampleEndpoints() => new List<ActiveEndpoint>
    {
        new ActiveEndpoint { Protocol = "TCP", State = "Listening", LocalIp = "0.0.0.0", LocalPort = 3389, Pid = 1100, ProcessName = "svchost.exe", AppPath = @"C:\Windows\System32\svchost.exe" },
        new ActiveEndpoint { Protocol = "TCP", State = "Listening", LocalIp = "::", LocalPort = 3389, Pid = 1100, ProcessName = "svchost.exe", AppPath = @"C:\Windows\System32\svchost.exe" },
        new ActiveEndpoint { Protocol = "TCP", State = "Listening", LocalIp = "0.0.0.0", LocalPort = 445, Pid = 4, ProcessName = "System", AppPath = AppPaths.SystemApp },
        new ActiveEndpoint { Protocol = "TCP", State = "Listening", LocalIp = "0.0.0.0", LocalPort = 5900, Pid = 2200, ProcessName = "tvnserver.exe", AppPath = @"C:\Program Files\TightVNC\tvnserver.exe" },
        new ActiveEndpoint { Protocol = "TCP", State = "Listening", LocalIp = "127.0.0.1", LocalPort = 14147, Pid = 3300, ProcessName = "filezilla-server.exe", AppPath = @"C:\Program Files\FileZilla Server\filezilla-server.exe" },
        new ActiveEndpoint { Protocol = "TCP", State = "Listening", LocalIp = "0.0.0.0", LocalPort = 49668, Pid = 700, ProcessName = "lsass.exe", AppPath = @"C:\Windows\System32\lsass.exe" },
        new ActiveEndpoint { Protocol = "UDP", State = "Bound", LocalIp = "0.0.0.0", LocalPort = 5353, Pid = 1500, ProcessName = "svchost.exe", AppPath = @"C:\Windows\System32\svchost.exe", RemoteIp = "*" },
        new ActiveEndpoint { Protocol = "UDP", State = "Bound", LocalIp = "0.0.0.0", LocalPort = 68, Pid = 1600, ProcessName = "svchost.exe", AppPath = @"C:\Windows\System32\svchost.exe", RemoteIp = "*" },
        new ActiveEndpoint { Protocol = "TCP", State = "Established", LocalIp = "192.168.1.5", LocalPort = 5900, RemoteIp = "192.168.1.20", RemotePort = 51000, Pid = 2200, ProcessName = "tvnserver.exe", AppPath = @"C:\Program Files\TightVNC\tvnserver.exe" },
        new ActiveEndpoint { Protocol = "TCP", State = "Established", LocalIp = "192.168.1.5", LocalPort = 5900, RemoteIp = "192.168.1.31", RemotePort = 51001, Pid = 2200, ProcessName = "tvnserver.exe", AppPath = @"C:\Program Files\TightVNC\tvnserver.exe" },
        new ActiveEndpoint { Protocol = "TCP", State = "Established", LocalIp = "127.0.0.1", LocalPort = 14147, RemoteIp = "127.0.0.1", RemotePort = 52000, Pid = 3300, ProcessName = "filezilla-server.exe" },
        new ActiveEndpoint { Protocol = "TCP", State = "Established", LocalIp = "192.168.1.5", LocalPort = 50123, RemoteIp = "142.250.1.1", RemotePort = 443, Pid = 4000, ProcessName = "browser.exe" },
    };

    internal static List<FirewallEvent> SamplePortEvents()
    {
        var now = DateTime.UtcNow;
        FirewallEvent In(string ip, int port, Verdict v, string app, int ago) => new FirewallEvent
        {
            TimeUtc = now.AddMinutes(-ago), Verdict = v, Direction = TrafficDirection.Inbound, Protocol = "TCP", LocalIp = "192.168.1.5", LocalPort = port, RemoteIp = ip, RemotePort = 40000, AppPath = app
        };
        return new List<FirewallEvent>
        {
            In("185.220.101.4", 3389, Verdict.Blocked, @"C:\Windows\System32\svchost.exe", 3),
            In("185.220.101.4", 3389, Verdict.Blocked, @"C:\Windows\System32\svchost.exe", 2),
            In("45.9.20.11", 3389, Verdict.Blocked, @"C:\Windows\System32\svchost.exe", 20),
            In("192.168.1.20", 5900, Verdict.Accepted, @"C:\Program Files\TightVNC\tvnserver.exe", 1),
            In("192.168.1.44", 5900, Verdict.Blocked, @"C:\Program Files\TightVNC\tvnserver.exe", 9),
            In("192.168.1.44", 445, Verdict.Blocked, AppPaths.SystemApp, 5),
            In("192.168.1.20", 9999, Verdict.Blocked, @"C:\x.exe", 1),
        };
    }

    private static void PortsAndShares()
    {
        var rows = PortsView.Build(SampleEndpoints(), SamplePortEvents());
        var rdp = rows.Single(r => r.Port == 3389);
        Check(rows.Count == 7, "one row per program and port, IPv4 and IPv6 together: " + rows.Count);
        Check(rdp.Binds.SequenceEqual(new[] { "0.0.0.0", "::" }) && rdp.ScopeText == "All networks" && rdp.Service == "Remote Desktop", "binds, scope and service name");
        Check(rdp.Visitors["185.220.101.4"].Blocked == 2 && rdp.Visitors.Count == 2 && rdp.ConnectedNow.Count == 0, "attempts in the last hour per address");
        var vnc = rows.Single(r => r.Port == 5900);
        Check(vnc.ConnectedNow.SequenceEqual(new[] { "192.168.1.20", "192.168.1.31" }) && vnc.Visitors["192.168.1.20"].ConnectedNow && vnc.Visitors["192.168.1.20"].Accepted == 1
              && vnc.Visitors["192.168.1.44"].Blocked == 1, "who's connected now and who tried");
        var fz = rows.Single(r => r.Port == 14147);
        Check(fz.LocalOnly && fz.ScopeText == "This PC only" && fz.ConnectedNow.Count == 0 && rows.Last() == fz, "loopback-only ports can't be reached, and list last");
        Check(rows.Single(r => r.Port == 49668).Service == "Dynamic (Windows RPC)" && rows.Single(r => r.Port == 5353).Service == "mDNS (Bonjour)", "port names");
        Check(!rows.Any(r => r.Port == 50123), "outgoing connections aren't open ports");
        Check(PortNames.Name("TCP", 1234, "app.exe") == "" && PortNames.Name("UDP", 68, null) == "DHCP", "unknown and UDP names");
    }

    private static void BandwidthTests()
    {
        var m = new BandwidthMeter();
        var t = new DateTime(2026, 11, 21, 10, 0, 0, DateTimeKind.Utc);
        (string, string) Resolve(int pid) => pid == 1 ? (@"C:\b\browser.exe", "browser.exe") : pid == 2 ? (@"C:\n\nas.exe", "nas.exe") : (null, null);
        m.Sample(t, Resolve);
        System.Threading.Tasks.Parallel.For(0, 1000, i => m.Add(1, "8.8.8.8", false, 125));
        m.Add(1, "8.8.8.8", true, 12_500);
        m.Add(1, "10.20.30.40", false, 1_000);
        m.Add(2, "192.168.1.20", false, 250_000);
        m.Add(2, "192.168.1.20", true, 2_500);
        m.Add(2, "239.255.255.250", true, 500);
        m.Add(3, "127.0.0.1", false, 9_999_999);
        m.Add(2, "192.168.1.20", false, 0);
        m.Sample(t.AddSeconds(2), Resolve);
        var browser = m.Apps.Single(a => a.Name == "browser.exe");
        var nas = m.Apps.Single(a => a.Name == "nas.exe");
        Check(Math.Abs(browser.InternetDown - (125_000 + 1_000) * 8 / 2.0) < 0.01 && Math.Abs(browser.InternetUp - 12_500 * 8 / 2.0) < 0.01 && browser.LanDown == 0,
            "bytes from many threads become bits per second; a private address off the LAN counts as internet");
        Check(Math.Abs(nas.LanDown - 1_000_000) < 0.01 && Math.Abs(nas.LanUp - (2_500 + 500) * 4) < 0.01 && nas.InternetDown == 0, "the adapters' subnet and local discovery are LAN");
        Check(m.Apps.Count == 2 && m.Apps[0] == nas, "this PC talking to itself is left out; busiest first");
        Check(Math.Abs(m.Now.Down - (126_000 + 250_000) * 4) < 0.01 && Math.Abs(m.Now.InternetUp - 50_000) < 0.01 && Math.Abs(m.Now.LanDown - 1_000_000) < 0.01, "totals for the PC, internet and LAN");
        m.Sample(t.AddSeconds(3), Resolve);
        Check(m.Now.Down == 0 && browser.Down == 0 && browser.TotalDown == 126_000 && nas.TotalUp == 3_000, "rates drop to zero when quiet; totals stay");
        for (var i = 0; i < BandwidthMeter.HistorySeconds + 50; i++) m.Sample(t.AddSeconds(4 + i), Resolve);
        Check(m.History.Count == BandwidthMeter.HistorySeconds, "the graph keeps 10 minutes");
        Check(BandwidthMeter.Text(12_400_000) == "12.4 Mb/s" && BandwidthMeter.Text(830_000) == "830 kb/s" && BandwidthMeter.Text(0) == "0 b/s" && BandwidthMeter.Text(1.5e9) == "1.50 Gb/s",
            "rate text");
        Check(BandwidthMeter.Bytes(126_000) == "123 KB" && BandwidthMeter.Bytes(3L << 30) == "3.0 GB", "size text");

        // One event of each kind, laid out as Windows hands it over (64-bit EVENT_RECORD).
        var record = System.Runtime.InteropServices.Marshal.AllocHGlobal(112);
        var data = System.Runtime.InteropServices.Marshal.AllocHGlobal(64);
        try
        {
            void Event(ushort id, byte[] payload)
            {
                for (var i = 0; i < 112; i++) System.Runtime.InteropServices.Marshal.WriteByte(record, i, 0);
                System.Runtime.InteropServices.Marshal.WriteInt16(record, 40, (short)id);
                System.Runtime.InteropServices.Marshal.WriteInt16(record, 86, (short)payload.Length);
                System.Runtime.InteropServices.Marshal.Copy(payload, 0, data, payload.Length);
                System.Runtime.InteropServices.Marshal.WriteIntPtr(record, 96, data);
            }
            byte[] V4(int pid, int size, byte[] d, byte[] s) => BitConverter.GetBytes(pid).Concat(BitConverter.GetBytes(size)).Concat(d).Concat(s).Concat(new byte[] { 1, 187, 200, 0 }).ToArray();
            var local = new HashSet<string> { "192.168.1.5", "2001:db8::5" };

            Event(10, V4(4321, 1460, new byte[] { 8, 8, 8, 8 }, new byte[] { 192, 168, 1, 5 }));
            Check(EasyFW.Platform.NetTrace.TryParse(record, local, out var pid, out var remote, out var sent, out var size) && pid == 4321 && size == 1460 && remote == "8.8.8.8" && sent,
                "TCP sent over IPv4");
            Event(43, V4(77, 512, new byte[] { 192, 168, 1, 5 }, new byte[] { 192, 168, 1, 20 }));
            Check(EasyFW.Platform.NetTrace.TryParse(record, local, out pid, out remote, out sent, out size) && remote == "192.168.1.20" && !sent && size == 512,
                "UDP received; the remote end is whichever isn't this PC");
            var v6 = BitConverter.GetBytes(9).Concat(BitConverter.GetBytes(100)).Concat(System.Net.IPAddress.Parse("2606:4700::1111").GetAddressBytes())
                .Concat(System.Net.IPAddress.Parse("2001:db8::5").GetAddressBytes()).Concat(new byte[] { 0, 80, 1, 2 }).ToArray();
            Event(27, v6);
            Check(EasyFW.Platform.NetTrace.TryParse(record, local, out pid, out remote, out sent, out size) && remote == "2606:4700::1111" && !sent && pid == 9, "TCP received over IPv6");
            Event(12, V4(1, 0, new byte[] { 8, 8, 8, 8 }, new byte[] { 192, 168, 1, 5 }));
            Check(!EasyFW.Platform.NetTrace.TryParse(record, local, out _, out _, out _, out _), "connects and other events carry no data");
            Event(10, new byte[8]);
            Check(!EasyFW.Platform.NetTrace.TryParse(record, local, out _, out _, out _, out _), "a short event is skipped");
        }
        finally
        {
            System.Runtime.InteropServices.Marshal.FreeHGlobal(record);
            System.Runtime.InteropServices.Marshal.FreeHGlobal(data);
        }

        // Without administrator rights Windows refuses the session: that must be reported, not thrown.
        var meter = new BandwidthMeter();
        using (var trace = new EasyFW.Platform.NetTrace(meter))
        {
            trace.Start();
            var elevated = new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            Check(elevated ? meter.Running || meter.Problem != null : meter.Problem != null && !meter.Running, "starting reports its problem: " + (meter.Problem ?? "running"));
        }
    }

    private static void WorldMap()
    {
        var places = new (double Lon, double Lat, bool Land, string Name)[]
        {
            (10, 50, true, "Germany"), (-100, 40, true, "the US"), (135, -25, true, "Australia"), (20, 0, true, "the Congo"), (78, 22, true, "India"),
            (-55, -10, true, "Brazil"), (100, 60, true, "Siberia"), (31, 27, true, "Egypt"), (-2, 53, true, "Britain"),
            (-30, 30, false, "the Atlantic"), (0, 0, false, "the Gulf of Guinea"), (-140, 10, false, "the Pacific"), (34, 43, false, "the Black Sea"),
            (51, 42, false, "the Caspian"), (88, -20, false, "the Indian Ocean"), (18, 35, false, "the Mediterranean"), (20, 58, false, "the Baltic"),
        };
        foreach (var p in places)
        {
            Check(WorldGeo.IsLand(p.Lon, p.Lat) == p.Land, $"map: {p.Name} is {(p.Land ? "land" : "sea")}");
            Check(WorldGeo.IsLandFast(p.Lon, p.Lat) == p.Land, $"map grid: {p.Name} is {(p.Land ? "land" : "sea")}");
        }
        Check(WorldGeo.TryLocate("us", out var lat, out var lon) && lat > 25 && lat < 50 && lon < -70, "countries have a place, any case");
        Check(!WorldGeo.TryLocate("LAN", out _, out _) && !WorldGeo.TryLocate(null, out _, out _), "LAN and unknown have none");
        Check(WorldGeo.Nearest(51, 10) == "DE" && WorldGeo.Nearest(-34, 151) == "AU", "nearest country to a point");
        var misplaced = WorldGeo.Countries.Where(c => WorldGeo.TryLocate(c, out var a, out var o) && (a > WorldGeo.North || a < WorldGeo.South)).ToList();
        Check(misplaced.Count == 0, "every country is on the map: " + string.Join(",", misplaced));

        var now = DateTime.UtcNow;
        string Country(string ip) => ip.StartsWith("192.168.") ? "LAN" : ip.StartsWith("1.") ? "US" : ip.StartsWith("2.") ? "CN" : ip.StartsWith("3.") ? "ZZ-unknown" : null;
        FirewallEvent E(string ip, Verdict v, TrafficDirection d, double minutesAgo, string app = @"C:\a.exe")
        {
            var e = Blocked(app, d, ip);
            e.Verdict = v;
            e.TimeUtc = now.AddMinutes(-minutesAgo);
            return e;
        }
        var events = new List<FirewallEvent>
        {
            E("1.0.0.1", Verdict.Accepted, TrafficDirection.Outbound, 1),
            E("1.0.0.2", Verdict.Accepted, TrafficDirection.Outbound, 2, @"C:\b.exe"),
            E("1.0.0.1", Verdict.Blocked, TrafficDirection.Inbound, 3),
            E("2.0.0.1", Verdict.Blocked, TrafficDirection.Inbound, 1),
            E("2.0.0.1", Verdict.Accepted, TrafficDirection.Inbound, 1),
            E("192.168.1.9", Verdict.Accepted, TrafficDirection.Outbound, 1),
            E("3.0.0.1", Verdict.Accepted, TrafficDirection.Outbound, 1),
            E("9.0.0.1", Verdict.Accepted, TrafficDirection.Outbound, 1),
            E("1.0.0.1", Verdict.Accepted, TrafficDirection.Outbound, 20),
            E("127.0.0.1", Verdict.Accepted, TrafficDirection.Outbound, 1),
        };
        var open = new List<ConnectionEntry>
        {
            new ConnectionEntry { RemoteIp = "1.0.0.9", LocalIp = "192.168.1.5", Direction = TrafficDirection.Outbound, IsActive = true, AppPath = @"C:\a.exe" },
            new ConnectionEntry { RemoteIp = "2.0.0.9", LocalIp = "192.168.1.5", Direction = TrafficDirection.Inbound, IsActive = true },
            new ConnectionEntry { RemoteIp = "2.0.0.8", LocalIp = "192.168.1.5", Direction = TrafficDirection.Inbound, IsActive = false },
        };
        var snap = GeoTraffic.Build(events, open, now.AddMinutes(-5), now, true, Country);
        var us = snap.Countries.Single(c => c.Country == "US");
        var cn = snap.Countries.Single(c => c.Country == "CN");
        Check(snap.Countries.Count == 2 && snap.Countries[0] == us, "countries busiest first");
        Check(us.OutAccepted == 2 && us.InBlocked == 1 && us.ActiveOut == 1 && us.Out == 3 && us.Total == 4, "a country counts out, in, blocked and open");
        Check(cn.InBlocked == 1 && cn.InAccepted == 1 && cn.ActiveIn == 1 && cn.Active == 1, "closed connections aren't open");
        Check(snap.Lan == 1 && snap.Unknown == 2, "LAN and unplaced addresses are counted aside, loopback is ignored");
        Check(us.Ips.Count == 3 && us.TopApps(1).Single() == "a.exe", "addresses and busiest app");
        Check(snap.Out == 3 && snap.In == 2 && snap.Blocked == 2 && snap.Active == 2, "totals");

        var back = GeoTraffic.Build(events, null, now.AddMinutes(-25), now.AddMinutes(-15), false, Country);
        Check(back.Countries.Single().OutAccepted == 1 && back.Active == 0 && !back.Live, "looking back takes only that window");

        var tl = GeoTraffic.Timeline(events, now, TimeSpan.FromMinutes(30), 30, Country);
        Check(tl.Length == 30 && tl.Sum(b => b.Total) == 8, "timeline leaves out LAN and loopback");
        Check(tl[29].Total >= 1 && tl[10].Out == 1, "timeline puts each attempt in its minute");
        Check(tl.Sum(b => b.Blocked) == 2 && tl.Sum(b => b.In) == 1, "timeline splits blocked, in and out");

        var s = NewService(new FakeBackend());
        s.SetMapHome("jp");
        Check(s.MapHome == "JP", "chosen location");
        s.SetMapHome("nowhere");
        Check(s.MapHome == (WorldGeo.HomeFromWindows() ?? "DE"), "an unknown location falls back to the Windows region");
    }

    private static void HistoryAndInternet()
    {
        Check(NetRanges.IsInternet("8.8.8.8") && NetRanges.IsInternet("2001:4860::8888"), "public addresses are internet");
        Check(!NetRanges.IsInternet("192.168.1.9") && !NetRanges.IsInternet("10.0.0.1") && !NetRanges.IsInternet("127.0.0.1")
              && !NetRanges.IsInternet("224.0.0.251") && !NetRanges.IsInternet("fe80::1") && !NetRanges.IsInternet("") && !NetRanges.IsInternet("*"), "LAN, loopback and multicast aren't");
        Check(NetRanges.Allows(false, LanAccess.All, null, "192.168.1.9") && !NetRanges.Allows(false, LanAccess.All, null, "8.8.8.8")
              && NetRanges.Allows(false, LanAccess.All, null, "192.168.1.9") && NetRanges.Allows(true, LanAccess.None, null, "8.8.8.8")
              && !NetRanges.Allows(true, LanAccess.None, null, "192.168.1.9"), "cached range checks still answer right");

        var h = new EventHistory(5);
        var now = DateTime.UtcNow;
        var old = Blocked(@"C:\a.exe");
        old.TimeUtc = now.AddMinutes(-61);
        h.Add(old);
        for (var i = 0; i < 3; i++) h.Add(Blocked(@"C:\a.exe"));
        h.Add(Blocked(@"C:\b.exe"));
        var ping = Blocked(AppPaths.SystemApp);
        ping.Protocol = "ICMP";
        h.Add(ping);
        Check(h.ForApp(@"C:\A.exe", now).Count == 3, "history keeps the last hour, any case");
        Check(h.ForApp(AppPaths.PingApp, now).Count == 1, "pings are found under Ping (ICMP)");
        Check(h.Count == 5, "history is capped");

        var s = NewService(new FakeBackend());
        var lan = Blocked(@"C:\lan.exe", remote: "192.168.1.20");
        var net = Blocked(@"C:\net.exe");
        net.Verdict = Verdict.Accepted;
        s.ProcessEvents(new[] { lan, net });
        Check(!s.UsesInternet(@"C:\lan.exe") && s.UsesInternet(@"C:\NET.exe"), "internet use is tracked per app, accepted or blocked");
        Check(s.Config.InternetApps.Count == 1 && s.History.ForApp(@"C:\lan.exe", DateTime.UtcNow).Count == 1, "saved and logged");
        var store = new ConfigStore(null, true);
        store.Config.InternetApps.Add(@"C:\x.exe");
        Check(new FirewallService(store, new FakeBackend(), RunMode.Live).UsesInternet(@"c:\x.exe"), "internet use survives a restart");
    }

    private static void Pending()
    {
        var b = new FakeBackend();
        var s = NewService(b);
        var added = s.ProcessEvents(new[] { Blocked(@"C:\a.exe"), Blocked(@"C:\A.EXE", lport: 50001) });
        Check(added.Count == 1 && s.PendingCount == 1, "one request per app, case-insensitive");
        Check(s.Config.Pending[0].Attempts == 2, "attempts counted");
        Check(s.ProcessEvents(new[] { Blocked(@"C:\a.exe") }).Count == 0, "no repeat notification");
        Check(s.ProcessEvents(new[] { Blocked(@"C:\lo.exe", remote: "127.0.0.1") }).Count == 0, "loopback doesn't prompt");
        Check(s.ProcessEvents(new[] { Blocked("") }).Count == 0, "unknown app doesn't prompt");
        var acc = Blocked(@"C:\acc.exe");
        acc.Verdict = Verdict.Accepted;
        Check(s.ProcessEvents(new[] { acc }).Count == 0, "accepted traffic doesn't prompt");

        s.ProcessEvents(new[] { Blocked(@"C:\b.exe", TrafficDirection.Inbound) });
        Check(s.Config.Pending.Single(p => p.AppPath == @"C:\b.exe").DirectionText == "Inbound", "direction tracked");
        s.Dismiss(@"C:\b.exe");
        Check(s.ProcessEvents(new[] { Blocked(@"C:\b.exe") }).Count == 0 && s.PendingCount == 1, "dismissed stays quiet this session");

        Wait(s.DecideAsync(@"C:\a.exe", RuleAction.Allow));
        Check(s.PendingCount == 0, "decision clears the request");
        Check(s.FindRule(@"C:\A.exe").Action == RuleAction.Allow, "accept creates rule");
        Check(s.ProcessEvents(new[] { Blocked(@"C:\a.exe") }).Count == 0, "decided app doesn't prompt again");
    }

    private static void Rules()
    {
        var b = new FakeBackend();
        var s = NewService(b);
        Wait(s.EnableAsync());
        Wait(s.DecideAsync(@"C:\a.exe", RuleAction.Allow));
        Check(b.Managed.Count(x => x.AppPath == @"C:\a.exe" && x.Allow) == 2, "accept applied live");
        Check(s.Evaluate(@"C:\a.exe", TrafficDirection.Outbound, 443) == Verdict.Accepted, "evaluate accepted");
        Check(s.Evaluate(@"C:\other.exe", TrafficDirection.Outbound, 443) == Verdict.Blocked, "unapproved blocked by default");

        Wait(s.DecideAsync(@"C:\a.exe", RuleAction.Block));
        Check(s.Config.Rules.Count == 1, "one rule per app");
        Check(b.Managed.Count(x => x.AppPath == @"C:\a.exe") == 2 && b.Managed.Where(x => x.AppPath == @"C:\a.exe").All(x => !x.Allow), "change replaces the Windows rules");

        var edit = s.Config.Rules[0].Clone();
        edit.Direction = RuleDirection.Outbound;
        edit.Action = RuleAction.Allow;
        Wait(s.SaveRuleAsync(edit));
        Check(b.Managed.Count(x => x.AppPath == @"C:\a.exe") == 1, "edit narrows direction");
        Check(s.Evaluate(@"C:\a.exe", TrafficDirection.Inbound, 443) == Verdict.Blocked, "uncovered direction stays blocked");
        Check(s.ProcessEvents(new[] { Blocked(@"C:\a.exe", TrafficDirection.Inbound) }).Count == 1, "uncovered direction can still ask");
        Check(s.ProcessEvents(new[] { Blocked(@"C:\a.exe", TrafficDirection.Outbound) }).Count == 0 && s.PendingCount == 1, "covered direction doesn't");

        var off = s.Config.Rules[0].Clone();
        off.Enabled = false;
        Wait(s.SaveRuleAsync(off));
        Check(!b.Managed.Any(x => x.AppPath == @"C:\a.exe"), "disabling removes the Windows rule");
        Check(s.Evaluate(@"C:\a.exe", TrafficDirection.Outbound, 443) == Verdict.Blocked, "disabled accept doesn't allow");

        Wait(s.DeleteRuleAsync(s.Config.Rules[0]));
        Check(s.Config.Rules.Count == 0 && !b.Managed.Any(x => x.AppPath == @"C:\a.exe"), "delete removes everywhere");
        Throws(() => Wait(s.SaveRuleAsync(new AppRule { AppPath = "  " })), "empty path rejected");

        var failing = new FakeBackend();
        var s2 = NewService(failing);
        Wait(s2.EnableAsync());
        failing.FailOn = "add";
        Throws(() => Wait(s2.DecideAsync(@"C:\x.exe", RuleAction.Allow)), "backend failure surfaces");
        Check(s2.Config.Rules.Count == 0, "failed rule isn't saved");

        var offline = new FakeBackend();
        var s3 = NewService(offline);
        Wait(s3.DecideAsync(@"C:\x.exe", RuleAction.Allow));
        Check(s3.Config.Rules.Count == 1 && offline.Managed.Count == 0, "protection off stores without touching Windows");
    }

    /// <summary>Exercises the real COM and table APIs. Writes current values only, and refuses to run them if elevated.</summary>
    // Stops at the text: calling the clipboard here would overwrite whatever the user has copied.
    private static void Copying()
    {
        Check(UiHelpers.RowsText(new[] { new[] { "a", "b" } }) == "a\tb", "one row is tab-separated");
        Check(UiHelpers.RowsText(new[] { new[] { "a", "" }, new[] { "c", "d" } }) == "a\t" + Environment.NewLine + "c\td", "rows take a line each and keep empty cells");
        Check(UiHelpers.RowsText(new string[0][]) == "", "no rows, no text");
        Check(System.Text.RegularExpressions.Regex.IsMatch(AppInfo.Version, @"^\d+\.\d+\.\d+$"), "version reads as major.minor.patch");
        Check(UiHelpers.CopyLabel(1) == "Copy row" && UiHelpers.CopyLabel(3) == "Copy 3 rows", "menu says how many");
    }

    private static void PendingPorts()
    {
        var s = NewService(new FakeBackend());
        s.ProcessEvents(new[] { Blocked(@"C:\out.exe") });
        var o = s.Config.Pending.Single();
        Check(o.LastSourcePort == 50000 && o.LastDestPort == 443, "going out: this PC is the source");
        Check(o.LastRemoteIp == "8.8.8.8", "remote IP has no port");
        Check(new PendingFilter { Text = "50000" }.Matches(o) && new PendingFilter { Text = "443" }.Matches(o) && !new PendingFilter { Text = "9999" }.Matches(o), "search covers both ports");

        s.ProcessEvents(new[] { Blocked(@"C:\in.exe", TrafficDirection.Inbound, lport: 8080) });
        var i = s.Config.Pending.Single(p => p.AppPath == @"C:\in.exe");
        Check(i.LastSourcePort == 443 && i.LastDestPort == 8080, "coming in: the far end is the source");

        s.ProcessEvents(new[] { Blocked(@"C:\out.exe", lport: 50001) });
        Check(o.LastSourcePort == 50001, "ports follow the latest attempt");

        Check(new PendingRequest { LastRemote = "2001:db8::1:443" }.LastRemoteIp == "2001:db8::1", "IPv6 remote keeps its colons");
        Check(new PendingRequest().LastRemoteIp == "", "no attempt, no IP");

        var store = new ConfigStore(null, true);
        store.Config.Pending.Add(new PendingRequest { AppPath = @"C:\a.exe", SawOutbound = true, LastRemote = "1.2.3.4:443" });
        store.Config.Pending.Add(new PendingRequest { AppPath = @"C:\b.exe", SawInbound = true, LastRemote = "1.2.3.4:5555" });
        store.Config.Pending.Add(new PendingRequest { AppPath = @"C:\c.exe", SawInbound = true, SawOutbound = true, LastRemote = "1.2.3.4:80" });
        store.Config.Pending.Add(new PendingRequest { AppPath = @"C:\d.exe", SawOutbound = true });
        new FirewallService(store, new FakeBackend(), RunMode.Live);
        var saved = store.Config.Pending;
        Check(saved[0].LastDestPort == 443 && saved[0].LastSourcePort == 0, "saved outgoing request gets its destination port");
        Check(saved[1].LastSourcePort == 5555 && saved[1].LastDestPort == 0, "saved incoming request gets its source port");
        Check(saved[2].LastSourcePort == 0 && saved[2].LastDestPort == 0, "saved request of unknown direction isn't guessed");
        Check(saved[3].LastSourcePort == 0 && saved[3].LastDestPort == 0, "saved request with no attempt stays empty");

        var outbound = new ConnectionEntry { Direction = TrafficDirection.Outbound, LocalPort = 50000, RemotePort = 443 };
        Check(outbound.SourcePort == 50000 && outbound.DestPort == 443, "connection going out");
        var incoming = new ConnectionEntry { Direction = TrafficDirection.Inbound, LocalPort = 8080, RemotePort = 50000 };
        Check(incoming.SourcePort == 50000 && incoming.DestPort == 8080, "connection coming in");
        var unknown = new ConnectionEntry { Direction = TrafficDirection.Unknown, LocalPort = 50000, RemotePort = 443 };
        Check(unknown.DestPort == 443, "unknown direction reads as going out, as rules do");

        var conns = new ConnectionStore();
        conns.Add(Blocked(@"C:\x.exe", remote: "1.1.1.1", lport: 3));
        conns.Add(Blocked(@"C:\x.exe", TrafficDirection.Inbound, remote: "1.1.1.2", lport: 1));
        var bySource = conns.Query(new ConnectionFilter(), ConnectionColumn.SourcePort, true);
        Check(bySource[0].SourcePort == 3 && bySource[1].SourcePort == 443, "sorts by source port");
        var byDest = conns.Query(new ConnectionFilter(), ConnectionColumn.DestPort, true);
        Check(byDest[0].DestPort == 1 && byDest[1].DestPort == 443, "sorts by destination port");
    }

    private static void OldName()
    {
        Check(RuleTranslator.Group == "EasyFW" && RuleTranslator.IsManagedGroup("EasyFW"), "new rule group");
        Check(RuleTranslator.IsManagedGroup("HomeFW"), "old rules aren't treated as foreign");
        Check(!RuleTranslator.IsManagedGroup("Remote Desktop") && !RuleTranslator.IsManagedGroup(null), "other rules are still foreign");

        var data = Path.Combine(Path.GetTempPath(), "EasyFW-test-" + Guid.NewGuid().ToString("N"));
        var oldFolder = Path.Combine(data, "HomeFW");
        var newFolder = Path.Combine(data, "EasyFW");
        try
        {
            Directory.CreateDirectory(data);
            Check(!ConfigStore.MoveLegacyFolder(data), "nothing to move on a fresh PC");

            Directory.CreateDirectory(oldFolder);
            File.WriteAllText(Path.Combine(oldFolder, "config.json"), "old");
            File.WriteAllText(Path.Combine(oldFolder, "homefw.log"), "log");
            Check(ConfigStore.MoveLegacyFolder(data), "old folder moves");
            Check(!Directory.Exists(oldFolder) && File.ReadAllText(Path.Combine(newFolder, "config.json")) == "old", "rules are in the new folder");
            Check(!ConfigStore.MoveLegacyFolder(data), "moves only once");

            Directory.CreateDirectory(oldFolder);
            File.WriteAllText(Path.Combine(oldFolder, "config.json"), "stale");
            Check(!ConfigStore.MoveLegacyFolder(data) && File.ReadAllText(Path.Combine(newFolder, "config.json")) == "old", "never overwrites EasyFW's rules");

            File.Delete(Path.Combine(newFolder, "config.json"));
            Check(ConfigStore.MoveLegacyFolder(data) && File.ReadAllText(Path.Combine(newFolder, "config.json")) == "stale", "new folder with no rules takes the old ones");
        }
        finally { if (Directory.Exists(data)) Directory.Delete(data, true); }
    }

    private static void Startup()
    {
        var exe = File.ReadAllBytes(typeof(Program).Assembly.Location);
        Check(Encoding.ASCII.GetString(exe).Contains("level=\"requireAdministrator\""), "the exe requires administrator rights");

        // Every launch has administrator rights now, so only the flag can keep this mode from enforcing.
        var monitor = Program.BuildReal(true);
        Check(monitor.Service.Mode == RunMode.MonitorOnly && !monitor.Service.CanEnforce, "monitor-only never enforces");
        Check(monitor.CloseConnection == null && monitor.Events == null, "monitor-only closes nothing and reads no log");
        Check(!monitor.Service.NeedsRestoreOnExit, "monitor-only changes nothing on exit");
    }

    private static void Ports()
    {
        Check(PortList.Normalize("443, 80 ;8000 - 8100") == "80,443,8000-8100", "ports are tidied and sorted");
        Check(PortList.Normalize("80,80,79-81,82") == "79-82", "overlapping ports merge");
        Check(PortList.Normalize("  ") == null && PortList.Normalize(null) == null, "empty means no list");
        Check(PortList.Normalize("1,65535") == "1,65535", "port limits are valid");
        foreach (var bad in new[] { "0", "65536", "abc", "90-80", "-5", "80-", "1-2-3", "80.5" })
            Throws(() => PortList.Normalize(bad), "bad port rejected: " + bad);
        Check(PortList.Contains("80,8000-8100", 8050) && PortList.Contains("80,8000-8100", 80) && !PortList.Contains("80,8000-8100", 81), "contains");

        const string app = @"C:\a.exe";
        var accept = RuleTranslator.ForApp(new AppRule { AppPath = app, Ports = "80,443", Direction = RuleDirection.Outbound }).ToList();
        Check(accept.Count == 2 && accept.All(x => x.Allow && x.AppPath == app), "accept on ports makes one allow rule per protocol, with no allow-all");
        Check(accept.Select(x => x.Protocol).OrderBy(p => p).SequenceEqual(new[] { FirewallProtocols.Tcp, FirewallProtocols.Udp }), "TCP and UDP");
        Check(accept.All(x => x.RemotePorts == "80,443" && x.LocalPorts == null), "outgoing uses the remote port");
        var incoming = RuleTranslator.ForApp(new AppRule { AppPath = app, Ports = "80", Direction = RuleDirection.Inbound }).ToList();
        Check(incoming.All(x => x.LocalPorts == "80" && x.RemotePorts == null), "incoming uses the local port");

        var block = RuleTranslator.ForApp(new AppRule { AppPath = app, Action = RuleAction.Block, Ports = "25", Direction = RuleDirection.Outbound }).ToList();
        Check(block.Count == 3 && block.Take(2).All(x => !x.Allow && x.RemotePorts == "25"), "block on ports shuts those ports first");
        Check(block[2].Allow && block[2].RemotePorts == null && block[2].Protocol == FirewallProtocols.Any, "block on ports opens the rest last");

        var both = new AppRule { AppPath = app, Action = RuleAction.Block, Ports = "25" };
        var bothSpecs = RuleTranslator.ForApp(both).ToList();
        Check(bothSpecs.Count == 6 && bothSpecs.Select(x => x.Name).Distinct().Count() == 6, "rule names stay unique");
        Check(bothSpecs.All(x => x.Name.Contains(RuleTranslator.Tag(both))), "every rule can be removed with its app rule");
        foreach (var spec in accept.Concat(block).Concat(incoming)) WindowsFirewallBackend.BuildRule(spec);
        Check(true, "Windows accepts the port rules");

        var b = new FakeBackend();
        var s = NewService(b);
        Wait(s.EnableAsync());
        Wait(s.DecideAsync(app, RuleAction.Allow, "443"));
        Check(s.Evaluate(app, TrafficDirection.Outbound, 443) == Verdict.Accepted && s.Evaluate(app, TrafficDirection.Outbound, 80) == Verdict.Blocked, "accept on ports allows only them");
        Check(s.FindDisallowed(new[] { Open(app, port: 443) }).Count == 0, "connection on an accepted port stays open");
        Check(s.FindDisallowed(new[] { Open(app, port: 80) }).Count == 1, "connection on another port is closed");
        var inbound = Open(app, TrafficDirection.Inbound, port: 5000);
        inbound.LocalPort = 443;
        Check(s.FindDisallowed(new[] { inbound }).Count == 0, "incoming connection is judged on the local port");
        Check(s.ProcessEvents(new[] { Blocked(app) }).Count == 0 && s.PendingCount == 0, "a decided app doesn't ask again");

        Wait(s.DecideAsync(app, RuleAction.Block, "25"));
        Check(s.Evaluate(app, TrafficDirection.Outbound, 25) == Verdict.Blocked && s.Evaluate(app, TrafficDirection.Outbound, 80) == Verdict.Accepted, "block on ports stops only them");
        Check(b.Managed.Count(x => x.AppPath == app) == 6, "changing a decision replaces its firewall rules");
        Check(s.FindDisallowed(new[] { Open(app, port: 25) }).Count == 1 && s.FindDisallowed(new[] { Open(app, port: 80) }).Count == 0, "open connections follow block on ports");

        Wait(s.DecideAsync(app, RuleAction.Block));
        Check(!s.FindRule(app).HasPorts && s.Evaluate(app, TrafficDirection.Outbound, 80) == Verdict.Blocked, "Block Always clears ports");
        Wait(s.DecideAsync(app, RuleAction.Allow, " 443 , 80 "));
        Check(s.FindRule(app).Ports == "80,443", "ports are saved tidy");
        Check(s.FindRule(app).PortsText == "Only 80,443", "accept wording");
        Throws(() => Wait(s.DecideAsync(app, RuleAction.Allow, "nope")), "bad ports refused");
        Check(s.FindRule(app).Ports == "80,443", "refused change leaves the rule alone");
        Throws(() => Wait(s.DecideAsync(AppPaths.PingApp, RuleAction.Allow, "80")), "ping can't have ports");
        Check(new AppRule { Action = RuleAction.Block, Ports = "25" }.PortsText == "All except 25" && new AppRule().PortsText == "All", "ports wording");

        var saved = ConfigStore.Deserialize(ConfigStore.Serialize(new AppConfig { Rules = { new AppRule { AppPath = app, Ports = "80" } } }));
        Check(saved.Rules[0].Ports == "80", "ports are saved in config");
        var older = ConfigStore.Deserialize(Encoding.UTF8.GetBytes("{\"Rules\":[{\"AppPath\":\"C:\\\\a.exe\",\"Action\":0,\"Direction\":0,\"Enabled\":true}]}"));
        Check(!older.Rules[0].HasPorts && older.Rules[0].AllowsPort(80), "older config means all ports");
    }

    private static void RuleFiles()
    {
        byte[] Json(string value) => Encoding.UTF8.GetBytes(value);
        var source = new AppRule { AppPath = @"C:\a.exe", Action = RuleAction.Block, Direction = RuleDirection.Outbound, Ports = "80,443", Notes = "note", Enabled = false };
        var ping = new AppRule { AppPath = AppPaths.PingApp };
        var bytes = RuleTransfer.Export(new[] { source, ping });
        var text = Encoding.UTF8.GetString(bytes);
        Check(!text.Contains("Snapshot") && !text.Contains("ProtectionEnabled"), "export has only rules");

        var back = RuleTransfer.Parse(bytes);
        Check(back.Count == 2 && back[1].AppPath == AppPaths.PingApp, "all rules come back");
        var r = back[0];
        Check(r.AppPath == source.AppPath && r.Action == source.Action && r.Direction == source.Direction && r.Ports == "80,443" && r.Notes == "note" && !r.Enabled, "rule details survive");
        Check(r.Id != source.Id && !string.IsNullOrEmpty(r.Id), "imported rule gets a new id");

        var withBom = new byte[] { 0xEF, 0xBB, 0xBF }.Concat(bytes).ToArray();
        Check(RuleTransfer.Parse(withBom).Count == 2, "file saved by Notepad with a BOM loads");
        Check(RuleTransfer.Parse(ConfigStore.Serialize(new AppConfig { Rules = { source }, ProtectionEnabled = true, Snapshot = new WindowsSnapshot() })).Count == 1, "a config backup loads as rules");
        var crafted = RuleTransfer.Parse(Json("{\"Rules\":[{\"Id\":\"essential\",\"AppPath\":\"C:\\\\x.exe\",\"Action\":0,\"Direction\":0,\"Enabled\":true}]}")).Single();
        Check(crafted.Id != "essential", "a crafted id can't reach firewall rule names");
        var twice = RuleTransfer.Parse(RuleTransfer.Export(new[] { new AppRule { AppPath = @"C:\a.exe" }, new AppRule { AppPath = @"c:\A.EXE", Action = RuleAction.Block } }));
        Check(twice.Count == 1 && twice[0].Action == RuleAction.Block, "same app twice keeps the last");

        foreach (var (name, json) in new[]
        {
            ("not JSON", "hello"), ("wrong shape", "[1,2]"), ("no rules", "{}"),
            ("relative path", "{\"Rules\":[{\"AppPath\":\"a.exe\",\"Action\":0,\"Direction\":0}]}"),
            ("no path", "{\"Rules\":[{\"Action\":0,\"Direction\":0}]}"),
            ("bad action", "{\"Rules\":[{\"AppPath\":\"C:\\\\a.exe\",\"Action\":9,\"Direction\":0}]}"),
            ("bad direction", "{\"Rules\":[{\"AppPath\":\"C:\\\\a.exe\",\"Action\":0,\"Direction\":9}]}"),
            ("bad ports", "{\"Rules\":[{\"AppPath\":\"C:\\\\a.exe\",\"Action\":0,\"Direction\":0,\"Ports\":\"80;rm\"}]}"),
            ("ping with ports", "{\"Rules\":[{\"AppPath\":\"Ping (ICMP)\",\"Action\":0,\"Direction\":0,\"Ports\":\"80\"}]}")
        })
        {
            try { RuleTransfer.Parse(Json(json)); Check(false, "should refuse: " + name); }
            catch (InvalidDataException) { Check(true, name); }
        }

        var b = new FakeBackend();
        var s = NewService(b);
        Wait(s.EnableAsync());
        Wait(s.DecideAsync(@"C:\keep.exe", RuleAction.Allow));
        Wait(s.DecideAsync(@"C:\same.exe", RuleAction.Allow));
        s.ProcessEvents(new[] { Blocked(@"C:\new.exe") });
        Check(s.PendingCount == 1, "request waiting before import");
        var import = new List<AppRule> { new AppRule { AppPath = @"C:\same.exe", Action = RuleAction.Block }, new AppRule { AppPath = @"C:\new.exe", Ports = "443" } };
        Wait(s.ImportRulesAsync(import));
        Check(s.Config.Rules.Count == 3 && s.FindRule(@"C:\keep.exe") != null, "import keeps other rules");
        Check(s.FindRule(@"C:\same.exe").Action == RuleAction.Block, "import replaces the same app's rule");
        Check(b.Managed.Count(x => x.AppPath == @"C:\same.exe") == 2 && b.Managed.Where(x => x.AppPath == @"C:\same.exe").All(x => !x.Allow), "firewall matches the replaced rule");
        Check(b.Managed.Any(x => x.AppPath == @"C:\new.exe" && x.RemotePorts == "443"), "imported rule reaches the firewall");
        Check(s.PendingCount == 0, "import answers a waiting request");
        Check(!s.IsBusy, "import finishes");

        var failing = new FakeBackend();
        var f = NewService(failing);
        Wait(f.EnableAsync());
        Wait(f.DecideAsync(@"C:\keep.exe", RuleAction.Allow));
        failing.FailOn = "add";
        Throws(() => Wait(f.ImportRulesAsync(new List<AppRule> { new AppRule { AppPath = @"C:\bad.exe" } })), "import failure surfaces");
        Check(f.FindRule(@"C:\bad.exe") == null && f.Config.Rules.Count == 1, "failed import changes no rules");
        Check(!f.IsBusy, "failed import finishes");

        var offBackend = new FakeBackend();
        var off = NewService(offBackend);
        Wait(off.ImportRulesAsync(new List<AppRule> { new AppRule { AppPath = @"C:\x.exe" } }));
        Check(off.Config.Rules.Count == 1 && offBackend.Managed.Count == 0, "import while off only saves");
        Throws(() => Wait(new FirewallService(new ConfigStore(null, true), new FakeBackend(), RunMode.MonitorOnly).ImportRulesAsync(new List<AppRule>())), "monitor-only can't import");
    }

    private static void Network()
    {
        Check(NetRanges.TryNormalize("192.168.1.77/24", out var c1) && c1 == "192.168.1.0/24", "host bits are cleared");
        Check(NetRanges.TryNormalize(" 10.0.0.5 ", out var c2) && c2 == "10.0.0.5/32", "a bare address is one host");
        Check(NetRanges.TryNormalize("fd12:3456::1/64", out var c3) && c3 == "fd12:3456::/64", "IPv6 subnet");
        foreach (var bad in new[] { "", "hello", "10.1/16", "192.168.1.0/33", "192.168.1.0/-1", "192.168.1.0/", "fe80::1%3/64", "1.2.3.4/24/1" })
            Check(!NetRanges.TryNormalize(bad, out _), "refuses subnet " + bad);

        // The tests' LAN is 192.168.1.0/24 (Wi-Fi) and 10.0.0.0/24 (Ethernet).
        Check(NetRanges.IsLan("192.168.1.5") && NetRanges.IsLan("10.0.0.40") && NetRanges.IsLan("169.254.3.3"), "the adapters' subnets and link-local are LAN");
        Check(!NetRanges.IsLan("10.20.30.40") && !NetRanges.IsLan("172.31.0.1") && !NetRanges.IsLan("192.168.2.1") && !NetRanges.IsLan("fd00::5"),
            "other private addresses, such as across a VPN, aren't LAN");
        Check(NetRanges.IsInternet("10.20.30.40") && NetRanges.IsInternet("fd00::5") && !NetRanges.IsInternet("10.0.0.40") && !NetRanges.IsInternet("127.0.0.1"), "and count as internet");
        Check(NetRanges.IsLan("239.255.255.250") && NetRanges.IsLan("255.255.255.255") && NetRanges.IsLan("fe80::1"), "discovery and link-local IPv6 are LAN");
        Check(!NetRanges.IsPublicAddress("10.20.30.40") && NetRanges.IsPublicAddress("8.8.8.8"), "the strict public test doesn't follow the network");
        Check(!NetRanges.IsLan("8.8.8.8") && !NetRanges.IsLan("172.32.0.1") && !NetRanges.IsLan("2001:4860::8888"), "public addresses aren't LAN");

        var lanOnly = new AppRule { AppPath = @"C:\nas.exe", NoInternet = true };
        Check(lanOnly.LimitsNetwork && lanOnly.NetworkText == "LAN only", "LAN only");
        Check(lanOnly.AllowsAddress("192.168.1.9") && !lanOnly.AllowsAddress("8.8.8.8") && !lanOnly.AllowsAddress("2001:4860::8888"), "LAN only keeps off the internet");
        Check(lanOnly.AllowsAddress("::ffff:192.168.1.9") && !lanOnly.AllowsAddress("::ffff:8.8.8.8"), "IPv4 written as IPv6 reads as IPv4");
        Check(lanOnly.AllowsAddress("*"), "an address that can't be read is left to the firewall");
        var addresses = lanOnly.RemoteAddresses;
        Check(addresses.Contains("192.168.1.0-192.168.1.255") && addresses.Contains("10.0.0.0-10.0.0.255") && addresses.Contains("fe80::-febf:")
              && !addresses.Contains("10.255.255.255") && !addresses.Contains("8.8."), "LAN ranges for Windows: " + addresses);

        var internetOnly = new AppRule { AppPath = @"C:\web.exe", Lan = LanAccess.None };
        Check(internetOnly.NetworkText == "Internet only" && internetOnly.AllowsAddress("8.8.8.8") && internetOnly.AllowsAddress("2001:4860::8888"), "internet only reaches the internet");
        Check(!internetOnly.AllowsAddress("192.168.1.9") && !internetOnly.AllowsAddress("239.255.255.250") && !internetOnly.AllowsAddress("fe80::5")
              && internetOnly.AllowsAddress("10.20.30.40"), "internet only stays off the LAN");
        Check(internetOnly.RemoteAddresses.StartsWith("1.0.0.0-9.255.255.255,10.0.1.0-126.255.255.255,") && internetOnly.RemoteAddresses.EndsWith(",fec0::-feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            "internet ranges for Windows: " + internetOnly.RemoteAddresses);

        Check(NetRanges.IsLanAdapter(System.Net.NetworkInformation.NetworkInterfaceType.Wireless80211, "Wi-Fi", "Intel Wi-Fi 6 AX201")
              && NetRanges.IsLanAdapter(System.Net.NetworkInformation.NetworkInterfaceType.Ethernet, "Ethernet", "Realtek PCIe GbE")
              && !NetRanges.IsLanAdapter(System.Net.NetworkInformation.NetworkInterfaceType.Ethernet, "vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter")
              && !NetRanges.IsLanAdapter(System.Net.NetworkInformation.NetworkInterfaceType.Ethernet, "Ethernet 2", "TAP-Windows Adapter V9")
              && !NetRanges.IsLanAdapter(System.Net.NetworkInformation.NetworkInterfaceType.Ppp, "VPN", "WAN Miniport")
              && !NetRanges.IsLanAdapter(System.Net.NetworkInformation.NetworkInterfaceType.Loopback, "Loopback", ""), "only real Ethernet and Wi-Fi adapters make the LAN");

        var source = NetRanges.AdapterSource;
        var before = NetRanges.Version;
        try
        {
            NetRanges.AdapterSource = () => new List<(string, string)> { ("192.168.50.0/24", "Wi-Fi") };
            NetRanges.Refresh();
            Check(NetRanges.Version != before && NetRanges.IsLan("192.168.50.7") && !NetRanges.IsLan("192.168.1.5") && NetRanges.IsInternet("192.168.1.5"), "joining another network moves the LAN");
            Check(lanOnly.AllowsAddress("192.168.50.7") && !lanOnly.AllowsAddress("192.168.1.5"), "rules follow it");
        }
        finally
        {
            NetRanges.AdapterSource = source;
            NetRanges.Refresh();
        }

        var some = new AppRule { AppPath = @"C:\cam.exe", NoInternet = true, Lan = LanAccess.Selected, LanSubnets = new List<string> { "192.168.1.0/24" } };
        Check(some.AllowsAddress("192.168.1.50") && !some.AllowsAddress("192.168.2.50") && !some.AllowsAddress("8.8.8.8") && some.AllowsAddress("239.255.255.250"), "only the chosen subnet, plus discovery");
        Check(some.NetworkText == "Only 192.168.1.0/24", "subnet wording");
        var mixed = new AppRule { AppPath = @"C:\m.exe", Lan = LanAccess.Selected, LanSubnets = new List<string> { "192.168.1.0/24" } };
        Check(mixed.AllowsAddress("8.8.8.8") && mixed.AllowsAddress("192.168.1.3") && !mixed.AllowsAddress("10.0.0.3") && mixed.NetworkText == "Internet + 192.168.1.0/24", "internet plus one subnet");

        var open = new AppRule { AppPath = @"C:\o.exe" };
        Check(!open.LimitsNetwork && open.RemoteAddresses == null && open.AllowsAddress("8.8.8.8") && open.NetworkText == "Internet + LAN", "default is unlimited");
        var block = new AppRule { AppPath = @"C:\b.exe", Action = RuleAction.Block, NoInternet = true };
        Check(!block.LimitsNetwork && block.RemoteAddresses == null && block.NetworkText == "-", "block rules don't limit addresses");

        var tidy = new AppRule { Lan = LanAccess.Selected, LanSubnets = new List<string> { "192.168.1.9/24", " 192.168.1.0/24 ", "" } };
        tidy.NormalizeNetwork();
        Check(tidy.LanSubnets.SequenceEqual(new[] { "192.168.1.0/24" }), "subnets are tidied and listed once");
        Throws(() => new AppRule { Lan = LanAccess.Selected, LanSubnets = new List<string> { "nope" } }.NormalizeNetwork(), "bad subnet refused");
        Throws(() => new AppRule { Lan = LanAccess.Selected }.NormalizeNetwork(), "only-these-subnets needs one");
        Throws(() => new AppRule { NoInternet = true, Lan = LanAccess.None }.NormalizeNetwork(), "no internet and no LAN refused");
        Throws(() => new AppRule { Lan = (LanAccess)9 }.NormalizeNetwork(), "unknown LAN choice refused");
        var cleared = new AppRule { Action = RuleAction.Block, NoInternet = true, Lan = LanAccess.Selected, LanSubnets = new List<string> { "x" } };
        cleared.NormalizeNetwork();
        Check(!cleared.NoInternet && cleared.Lan == LanAccess.All && cleared.LanSubnets == null, "block rule has its network choices cleared");
        var all = new AppRule { Lan = LanAccess.All, LanSubnets = new List<string> { "10.0.0.0/8" } };
        all.NormalizeNetwork();
        Check(all.LanSubnets == null, "subnets are kept only for only-these-subnets");
        var copy = some.Clone();
        copy.LanSubnets.Add("10.0.0.0/8");
        Check(some.LanSubnets.Count == 1, "a copy doesn't share its subnet list");

        var specs = RuleTranslator.ForApp(lanOnly).ToList();
        Check(specs.Count == 2 && specs.All(x => x.RemoteAddresses == addresses), "both directions carry the LAN limit");
        Check(specs[0].Description.Contains("LAN only"), "rule description names the limit");
        var portSpecs = RuleTranslator.ForApp(new AppRule { AppPath = @"C:\nas.exe", NoInternet = true, Ports = "445" }).ToList();
        Check(portSpecs.Count == 4 && portSpecs.All(x => x.RemoteAddresses == addresses), "port rules carry the limit too");
        var blockPorts = RuleTranslator.ForApp(new AppRule { AppPath = @"C:\b.exe", Action = RuleAction.Block, Ports = "25" }).ToList();
        Check(blockPorts.All(x => x.RemoteAddresses == null), "block rules apply to every address");
        var pingSpecs = RuleTranslator.ForApp(new AppRule { AppPath = AppPaths.PingApp, NoInternet = true }).ToList();
        Check(pingSpecs.All(x => x.RemoteAddresses != null), "ping can be kept to the LAN");
        var v6 = RuleTranslator.ForApp(new AppRule { AppPath = @"C:\v6.exe", NoInternet = true, Lan = LanAccess.Selected, LanSubnets = new List<string> { "fd00::/64", "192.168.1.20/32" } }).ToList();
        try
        {
            foreach (var spec in specs.Concat(portSpecs).Concat(pingSpecs).Concat(v6).Concat(RuleTranslator.ForApp(internetOnly)).Concat(RuleTranslator.ForApp(mixed)))
                WindowsFirewallBackend.BuildRule(spec);
            Check(true, "Windows accepts the address ranges");
        }
        catch (Exception ex) { Check(false, "Windows accepts the address ranges: " + (ex.InnerException ?? ex).Message); }

        var b = new FakeBackend();
        var s = NewService(b);
        Wait(s.EnableAsync());
        Wait(s.SaveRuleAsync(new AppRule { AppPath = @"C:\nas.exe", NoInternet = true }));
        Check(b.Managed.Where(x => x.AppPath == @"C:\nas.exe").All(x => x.RemoteAddresses == addresses), "saved rule reaches the firewall with its limit");
        Check(s.Evaluate(@"C:\nas.exe", TrafficDirection.Outbound, 445, "192.168.1.9") == Verdict.Accepted && s.Evaluate(@"C:\nas.exe", TrafficDirection.Outbound, 443, "8.8.8.8") == Verdict.Blocked, "evaluate follows the LAN limit");
        Check(s.Evaluate(@"C:\nas.exe", TrafficDirection.Outbound, 443) == Verdict.Accepted, "no address, no address check");
        Check(s.FindDisallowed(new[] { Open(@"C:\nas.exe", remote: "8.8.8.8") }).Count == 1 && s.FindDisallowed(new[] { Open(@"C:\nas.exe", remote: "192.168.1.9") }).Count == 0, "open internet connection of a LAN-only app is closed");
        Throws(() => Wait(s.SaveRuleAsync(new AppRule { AppPath = @"C:\x.exe", NoInternet = true, Lan = LanAccess.None })), "service refuses no network at all");
        Check(s.FindRule(@"C:\x.exe") == null, "refused rule isn't saved");
        Wait(s.DecideAsync(@"C:\nas.exe", RuleAction.Block));
        Check(!s.FindRule(@"C:\nas.exe").LimitsNetwork && b.Managed.Where(x => x.AppPath == @"C:\nas.exe").All(x => x.RemoteAddresses == null), "switching to block clears the limit");

        var saved = ConfigStore.Deserialize(ConfigStore.Serialize(new AppConfig { Rules = { some } })).Rules[0];
        Check(saved.NoInternet && saved.Lan == LanAccess.Selected && saved.LanSubnets.SequenceEqual(some.LanSubnets), "network choices are saved");
        var older = ConfigStore.Deserialize(Encoding.UTF8.GetBytes("{\"Rules\":[{\"AppPath\":\"C:\\\\a.exe\",\"Action\":0,\"Direction\":0,\"Enabled\":true}]}")).Rules[0];
        Check(!older.LimitsNetwork && older.AllowsAddress("8.8.8.8") && older.AllowsAddress("192.168.1.1"), "older config means internet and LAN");
        var moved = RuleTransfer.Parse(RuleTransfer.Export(new[] { some })).Single();
        Check(moved.NoInternet && moved.Lan == LanAccess.Selected && moved.LanSubnets.Single() == "192.168.1.0/24", "network choices export and import");
        foreach (var (name, json) in new[]
        {
            ("bad subnet", "{\"Rules\":[{\"AppPath\":\"C:\\\\a.exe\",\"Action\":0,\"Direction\":0,\"Lan\":1,\"LanSubnets\":[\"10.1/8\"]}]}"),
            ("no network", "{\"Rules\":[{\"AppPath\":\"C:\\\\a.exe\",\"Action\":0,\"Direction\":0,\"NoInternet\":true,\"Lan\":2}]}"),
            ("bad LAN choice", "{\"Rules\":[{\"AppPath\":\"C:\\\\a.exe\",\"Action\":0,\"Direction\":0,\"Lan\":7}]}")
        })
        {
            try { RuleTransfer.Parse(Encoding.UTF8.GetBytes(json)); Check(false, "file should be refused: " + name); }
            catch (InvalidDataException) { Check(true, "file refused: " + name); }
        }
        Check(new RuleFilter { Text = "LAN only" }.Matches(lanOnly), "rules search covers the network column");

        var local = NetRanges.LocalSubnets();
        Check(local.All(x => NetRanges.TryNormalize(x.Cidr, out var n) && n == x.Cidr && !string.IsNullOrEmpty(x.Adapter)), "this PC's subnets read cleanly");
    }

    private static void TopFlows()
    {
        var store = new ConnectionStore();
        for (var i = 0; i < 5; i++) store.Add(Blocked(@"C:\a.exe", lport: 50000 + i));
        store.Add(Blocked(@"C:\a.exe", remote: "1.1.1.1"));
        for (var i = 0; i < 4; i++)
        {
            var e = Blocked(@"C:\b.exe", remote: "9.9.9.9", lport: 51000 + i);
            if (i < 3) e.Verdict = Verdict.Accepted;
            store.Add(e);
        }
        for (var i = 0; i < 10; i++)
        {
            var e = Blocked(@"C:\c.exe", remote: "127.0.0.1", lport: 52000 + i);
            e.Verdict = Verdict.Accepted;
            store.Add(e);
        }

        var flows = store.Flows;
        var top = flows.Top(new FlowFilter(), FlowRank.Total, 60, 10, DateTime.UtcNow, out var matching);
        Check(matching == 3 && top.Count == 3, "connections group by app, address and port, whatever the local port");
        Check(top[0].AppPath == @"C:\a.exe" && top[0].RemoteIp == "8.8.8.8" && top[0].DestPort == 443 && top[0].Blocked == 5 && top[0].Total == 5, "busiest first");
        Check(top[1].AppPath == @"C:\b.exe" && top[1].Accepted == 3 && top[1].Blocked == 1, "accepted and blocked count in one group");
        Check(flows.Top(new FlowFilter(), FlowRank.Accepted, 60, 10, DateTime.UtcNow, out _).Single().AppPath == @"C:\b.exe", "rank by accepted leaves out groups with none");
        Check(flows.Top(new FlowFilter(), FlowRank.Blocked, 60, 10, DateTime.UtcNow, out _).Select(f => f.Blocked).SequenceEqual(new long[] { 5, 1, 1 }), "rank by blocked");
        Check(flows.Top(new FlowFilter { Status = Verdict.Blocked }, FlowRank.Total, 60, 10, DateTime.UtcNow, out _).Count == 3, "blocked filter keeps groups with any blocked");
        Check(flows.Top(new FlowFilter { Status = Verdict.Accepted }, FlowRank.Total, 60, 10, DateTime.UtcNow, out _).Count == 1, "accepted filter");
        Check(flows.Top(new FlowFilter { HideLoopback = false }, FlowRank.Total, 60, 10, DateTime.UtcNow, out _)[0].RemoteIp == "127.0.0.1", "loopback shows when asked");
        Check(flows.Top(new FlowFilter { Text = "1.1.1.1" }, FlowRank.Total, 60, 10, DateTime.UtcNow, out _).Single().Total == 1, "search");
        Check(flows.Top(new FlowFilter(), FlowRank.Total, 60, 1, DateTime.UtcNow, out var all).Count == 1 && all == 3, "the limit keeps the count of every match");

        store.Add(Blocked(@"C:\srv.exe", TrafficDirection.Inbound, remote: "5.5.5.5", lport: 3389));
        Check(flows.Top(new FlowFilter { Text = "srv" }, FlowRank.Total, 60, 10, DateTime.UtcNow, out _).Single().DestPort == 3389, "incoming groups by this PC's port");

        store.Clear();
        Check(flows.Count > 0, "clearing the connection history keeps the counts");
        flows.Clear();
        Check(flows.Count == 0 && flows.Top(new FlowFilter(), FlowRank.Total, 60, 10, DateTime.UtcNow, out _).Count == 0, "reset counts");

        var polled = new ConnectionStore();
        var live = Open(@"C:\p.exe", remote: "4.4.4.4");
        var listen = Open(@"C:\p.exe", state: "Listening", remote: "*", port: 0);
        polled.ApplyActive(new[] { live, listen }, DateTime.UtcNow);
        polled.ApplyActive(new[] { live, listen }, DateTime.UtcNow);
        var only = polled.Flows.Top(new FlowFilter(), FlowRank.Total, 60, 10, DateTime.UtcNow, out _);
        Check(only.Count == 1 && only[0].Accepted == 1 && only[0].RemoteIp == "4.4.4.4", "an open connection counts once, and listeners not at all");

        var now = new DateTime(2026, 11, 12, 10, 30, 20, DateTimeKind.Utc);
        var timed = new FlowStats();
        void At(int minutesAgo, string remote, Verdict v) => timed.Record(@"C:\t.exe", "t.exe", TrafficDirection.Outbound, "TCP", remote, 443, v, now.AddMinutes(-minutesAgo));
        At(0, "1.1.1.1", Verdict.Blocked);
        At(9, "1.1.1.1", Verdict.Blocked);
        At(10, "1.1.1.1", Verdict.Blocked);
        At(25, "1.1.1.1", Verdict.Accepted);
        At(45, "1.1.1.1", Verdict.Accepted);
        At(50, "2.2.2.2", Verdict.Blocked);
        At(90, "3.3.3.3", Verdict.Blocked);
        long CountIn(int minutes, string remote) =>
            timed.Top(new FlowFilter { Text = remote }, FlowRank.Total, minutes, 10, now, out _).Select(f => f.Total).DefaultIfEmpty(0).Single();
        Check(CountIn(10, "1.1.1.1") == 2, "last 10 minutes counts only those minutes");
        Check(CountIn(30, "1.1.1.1") == 4 && CountIn(60, "1.1.1.1") == 5, "longer periods count more");
        Check(CountIn(10, "2.2.2.2") == 0 && CountIn(60, "2.2.2.2") == 1, "a group with nothing in the period is left out");
        Check(CountIn(60, "3.3.3.3") == 0, "nothing older than an hour counts");
        var hour = timed.Top(new FlowFilter(), FlowRank.Total, 60, 10, now, out var inHour);
        Check(inHour == 2 && hour[0].Accepted == 2 && hour[0].Blocked == 3, "accepted and blocked are split within the period");
        Check(timed.Top(new FlowFilter { Status = Verdict.Accepted }, FlowRank.Total, 10, 10, now, out _).Count == 0, "accepted filter looks at the period only");
        Check(timed.Top(new FlowFilter(), FlowRank.Total, 60, 10, now.AddMinutes(61), out _).Count == 0, "counts age out as time passes");
        At(-60, "1.1.1.1", Verdict.Blocked);
        Check(timed.Top(new FlowFilter { Text = "1.1.1.1" }, FlowRank.Total, 60, 10, now.AddMinutes(60), out _).Single().Total == 1, "a minute an hour later replaces the old one");

        var small = new FlowStats(10);
        for (var i = 0; i < 12; i++) small.Record(@"C:\x.exe", "x.exe", TrafficDirection.Outbound, "TCP", "8.8.8." + i, 443, Verdict.Blocked, DateTime.UtcNow.AddSeconds(i));
        Check(small.Count <= 10, "the oldest groups go past capacity");
        small.Record(@"C:\x.exe", "x.exe", TrafficDirection.Outbound, "TCP", "8.8.4.4", 443, Verdict.Unknown, DateTime.UtcNow);
        Check(small.Top(new FlowFilter { Text = "8.8.4.4" }, FlowRank.Total, 60, 10, DateTime.UtcNow, out _).Count == 0, "unjudged sockets aren't counted");
    }

    private static CountryDb Db(string csv) => CountryDb.Load(new MemoryStream(Encoding.ASCII.GetBytes(csv)));

    private static void Lookups()
    {
        var db = Db("0.0.0.0,0.255.255.255,ZZ\n1.0.0.0,1.0.0.255,AU\n8.8.8.0,8.8.8.255,US\n2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US\n");
        Check(db.Count == 4, "sample database loads");
        Check(db.Find(System.Net.IPAddress.Parse("8.8.8.8")) == "US" && db.Find(System.Net.IPAddress.Parse("1.0.0.0")) == "AU" && db.Find(System.Net.IPAddress.Parse("1.0.0.255")) == "AU", "IPv4 ranges, ends included");
        Check(db.Find(System.Net.IPAddress.Parse("1.0.1.0")) == null && db.Find(System.Net.IPAddress.Parse("9.9.9.9")) == null, "gaps and addresses past the end are unknown");
        Check(db.Find(System.Net.IPAddress.Parse("2001:4860:4860::8888")) == "US" && db.Find(System.Net.IPAddress.Parse("2a00::1")) == null, "IPv6 ranges");
        Check(db.Find(System.Net.IPAddress.Parse("::ffff:8.8.8.8")) == "US", "IPv4 written as IPv6");
        foreach (var (name, csv) in new[] { ("unsorted", "8.8.8.0,8.8.8.255,US\n1.0.0.0,1.0.0.255,AU\n"), ("malformed", "1.0.0.0,AU\n"), ("mixed families", "1.0.0.0,::1,AU\n") })
        {
            try { Db(csv); Check(false, "database should be refused: " + name); }
            catch (InvalidDataException) { Check(true, "database refused: " + name); }
        }

        IpInfo.SetCountries(db);
        Check(IpInfo.CountryCode("8.8.8.8") == "US" && IpInfo.CountryText("8.8.8.8") == "United States", "country name");
        Check(IpInfo.CountryText("192.168.1.9") == "Local network" && IpInfo.CountryText("127.0.0.1") == "This PC" && IpInfo.CountryCode("192.168.1.9") == "LAN", "local addresses");
        Check(IpInfo.CountryText("0.0.0.1") == "" && IpInfo.CountryText("*") == "" && IpInfo.CountryText(null) == "" && IpInfo.CountryText("9.9.9.9") == "", "unknown shows nothing");
        Check(IpInfo.CountryName("EG") == "Egypt" && IpInfo.CountryName("EU") == "European Union" && IpInfo.CountryName("QQ") == "QQ", "names from codes");

        var real = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, IpInfo.FileName);
        Check(File.Exists(real), "country file is copied beside the exe");
        if (File.Exists(real))
        {
            using var file = File.OpenRead(real);
            using var gzip = new System.IO.Compression.GZipStream(file, System.IO.Compression.CompressionMode.Decompress);
            var full = CountryDb.Load(gzip);
            Check(full.Count == 732796, "the whole DB-IP file loads");
            // Rows from the November 2026 file: 8.8.236.0-8.8.239.255 CA, 8.8.240.0-8.10.5.255 US, 2001:4800::/? US, 2001:4860:: to 2001:4860:1bff:... CA.
            Check(full.Find(System.Net.IPAddress.Parse("8.8.236.1")) == "CA" && full.Find(System.Net.IPAddress.Parse("8.9.0.1")) == "US", "real IPv4 lookups");
            Check(full.Find(System.Net.IPAddress.Parse("2001:4800::1")) == "US" && full.Find(System.Net.IPAddress.Parse("2001:4860::1")) == "CA", "real IPv6 lookups");
            IpInfo.SetCountries(full);
        }

        var resolver = IpInfo.Resolver;
        try
        {
            var asked = new System.Collections.Concurrent.ConcurrentBag<string>();
            IpInfo.Resolver = a =>
            {
                asked.Add(a.ToString());
                if (a.ToString() == "10.0.0.66") throw new System.Net.Sockets.SocketException();
                return "host-" + a;
            };
            IpInfo.ClearNames();
            Check(IpInfo.HostName("8.8.4.4") == "", "a name isn't known straight away");
            IpInfo.HostName("10.0.0.66");
            IpInfo.HostName("8.8.4.4");
            var until = DateTime.UtcNow.AddSeconds(5);
            while ((IpInfo.HostName("8.8.4.4") == "" || !asked.Contains("10.0.0.66")) && DateTime.UtcNow < until) System.Threading.Thread.Sleep(10);
            System.Threading.Thread.Sleep(50);
            Check(IpInfo.HostName("8.8.4.4") == "host-8.8.4.4", "name arrives from the background");
            Check(asked.Count(x => x == "8.8.4.4") == 1, "each address is looked up once");
            Check(IpInfo.HostName("10.0.0.66") == "", "a failed lookup shows nothing");
            Check(IpInfo.HostName("*") == "" && IpInfo.HostName("0.0.0.0") == "" && IpInfo.HostName("") == "", "wildcards aren't looked up");
            Check(IpInfo.HostName("9.9.9.9", false) == "" && !asked.Contains("9.9.9.9"), "a cached-only read doesn't look up");
        }
        finally
        {
            IpInfo.Resolver = resolver;
            IpInfo.ClearNames();
        }

        Check(Flags.For("us") is Image us && us.Width == 16 && us.Height == 11, "flag from the sprite");
        Check(Flags.For("EG") != null && Flags.For("ch").Width == 11 && Flags.For("zz") == null && Flags.For(null) == null, "flag lookups");
        Check(Flags.Codes.All(c => Flags.For(c) != null), "every flag in the layout fits the sprite");
    }

    private static void PrintAvastPaths()
    {
        foreach (var name in new[] { "AvastSvc", "aswidsagent", "aswToolsSvc", "aswEngSrv" })
        {
            foreach (var p in System.Diagnostics.Process.GetProcessesByName(name))
                Console.WriteLine($"  {name} pid {p.Id}: {DevicePaths.ToDosPath(ProcessInfoCache.ImagePathWithoutHandle(p.Id))}");
        }
    }

    private static int Probe()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var elevated = new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        Console.WriteLine("elevated: " + elevated);
        var b = new WindowsFirewallBackend();
        var info = b.GetPolicyInfo();
        Console.WriteLine("group policy overrides: " + info.GroupPolicyOverrides);
        var snap = b.CaptureState();
        Console.WriteLine($"defaults in={string.Join(",", snap.DefaultInbound)} out={string.Join(",", snap.DefaultOutbound)} enabled={string.Join(",", snap.FirewallEnabled)} audit={snap.AuditSetting}");
        Console.WriteLine("block default active: " + b.IsBlockDefaultActive());
        Console.WriteLine("foreign allow rules: " + b.ListForeignAllowRules().Count);
        Console.WriteLine("managed rules present: " + b.HasManagedRules());

        var specs = RuleTranslator.All(new AppConfig());
        specs.AddRange(RuleTranslator.ForApp(new AppRule { AppPath = @"C:\Program Files\x\a.exe", Action = RuleAction.Block }));
        specs.AddRange(RuleTranslator.ForApp(new AppRule { AppPath = AppPaths.SystemApp, Action = RuleAction.Allow }));
        foreach (var spec in specs) WindowsFirewallBackend.BuildRule(spec);
        Console.WriteLine($"built {specs.Count} rule objects with no COM errors");

        if (!elevated)
        {
            // Same values as current, and Windows refuses anyway. Proves the property-put dispatch binds.
            snap.AuditSetting = "unknown";
            try
            {
                b.RestoreState(snap);
                Console.WriteLine("write: unexpectedly allowed");
            }
            catch (Exception ex)
            {
                var inner = ex.InnerException ?? ex;
                Console.WriteLine("write unelevated -> " + inner.GetType().Name + ": " + inner.Message.Trim());
            }
        }

        var active = new ActiveConnectionReader().Read();
        Console.WriteLine($"active: {active.Count} ({active.Count(a => a.Protocol == "TCP")} tcp, {active.Count(a => a.State == "Established")} established, {active.Count(a => a.State == "Listening")} listening)");
        foreach (var a in active.Where(x => x.State == "Established" && !IpText.IsLoopback(x.RemoteIp)).Take(3))
            Console.WriteLine($"  {a.ProcessName} {a.LocalIp}:{a.LocalPort} -> {a.RemoteIp}:{a.RemotePort} pid={a.Pid} {a.Direction}");
        foreach (var a in active.Where(x => x.State == "Listening").Take(3))
            Console.WriteLine($"  listen {a.ProcessName} {a.LocalIp}:{a.LocalPort} pid={a.Pid}");
        return 0;
    }

    private static void Snap(Control form, string path)
    {
        Application.DoEvents();
        using var bmp = new Bitmap(form.Width, form.Height);
        form.DrawToBitmap(bmp, new Rectangle(0, 0, form.Width, form.Height));
        bmp.Save(path);
    }

    private static void Offscreen(Form f)
    {
        f.StartPosition = FormStartPosition.Manual;
        f.Location = new Point(-4000, 0);
        f.ShowInTaskbar = false;
    }

    /// <summary>Renders each screen off-screen in demo mode, so no real window or input is involved.</summary>
    private static int Shots(string dir)
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Directory.CreateDirectory(dir);
        var env = Program.BuildDemo();
        var service = env.Service;

        using (var wizard = new SetupWizardForm(service, DemoTraffic.ActiveSample))
        {
            Offscreen(wizard);
            wizard.Show();
            for (var i = 0; i < 3; i++)
            {
                wizard.Go(i);
                Snap(wizard, Path.Combine(dir, $"wizard{i + 1}.png"));
            }
            wizard.Hide();
        }

        using (var live = new FirewallNoticeForm(RunMode.Live, false))
        {
            Offscreen(live);
            live.Show();
            Snap(live, Path.Combine(dir, "notice.png"));
        }

        Wait(service.EnableAsync());
        service.Config.SetupCompleted = true;
        using var form = new MainForm(service, () => Task.CompletedTask, () => { });
        Offscreen(form);
        form.Show();

        var demo = (DemoTraffic)env.Events;
        var queue = new List<FirewallEvent>();
        demo.Start(queue.Add);
        demo.Stop();
        for (var i = 0; i < 40; i++) demo.EmitOne();
        service.ProcessEvents(queue);
        queue.Clear();
        Wait(service.DecideAsync(@"C:\Program Files\Browser\browser.exe", RuleAction.Allow));
        Wait(service.DecideAsync(@"C:\Games\GameLauncher\launcher.exe", RuleAction.Block));
        for (var i = 0; i < 30; i++) demo.EmitOne();
        service.ProcessEvents(queue);
        service.Connections.ApplyActive(DemoTraffic.ActiveSample(), DateTime.UtcNow);

        // A shape with peaks and quiet spells, to judge the graph at full width.
        var now = TrafficHistory.Floor(DateTime.UtcNow);
        for (var i = 0; i < TrafficHistory.Capacity; i++)
        {
            service.Traffic.Add(new TrafficSample
            {
                TimeUtc = now.AddSeconds((i - TrafficHistory.Capacity) * TrafficHistory.IntervalSeconds),
                Accepted = (int)(26 + 22 * Math.Sin(i / 5.0) + 18 * Math.Exp(-Math.Pow(i - 38, 2) / 8.0)),
                Blocked = (int)(12 + 9 * Math.Cos(i / 3.5) + 30 * Math.Exp(-Math.Pow(i - 20, 2) / 12.0))
            });
        }

        Wait(service.SaveRuleAsync(new AppRule { AppPath = @"C:\Tools\Sync\sync.exe", Ports = "443,8000-8100" }));
        Wait(service.SaveRuleAsync(new AppRule { AppPath = @"C:\Tools\Mail\mail.exe", Action = RuleAction.Block, Ports = "25" }));
        var lanApp = new AppRule { AppPath = @"C:\Tools\SyncAgent\syncagent.exe", NoInternet = true, Lan = LanAccess.Selected, LanSubnets = new List<string> { "192.168.1.0/24" } };
        Wait(service.SaveRuleAsync(lanApp));
        Wait(service.DecideAsync(@"C:\Tools\Chat\chat.exe", RuleAction.Allow, null, RuleDuration.Minutes30));
        Wait(service.DecideAsync(@"C:\Tools\Remote\remote.exe", RuleAction.Allow, null, RuleDuration.UntilRestart));
        Wait(service.SaveRuleAsync(new AppRule { AppPath = @"C:\Games\Arcade\arcade.exe", ScheduleDays = 0b1000001, ScheduleFrom = 10 * 60, ScheduleTo = 20 * 60, KeepInLockdown = false }));
        service.Config.Rules.First(r => r.AppPath.EndsWith("browser.exe")).KeepInLockdown = true;
        queue.Clear();
        for (var i = 0; i < 60; i++) demo.EmitOne();
        service.ProcessEvents(queue);
        // Countries load and names resolve in the background. Wait for them, so the shots show the columns filled in.
        var ready = DateTime.UtcNow.AddSeconds(30);
        while (!IpInfo.CountriesLoaded && DateTime.UtcNow < ready) { Application.DoEvents(); System.Threading.Thread.Sleep(50); }
        var ips = service.Connections.Query(new ConnectionFilter(), ConnectionColumn.Time, false).Select(c => c.RemoteIp).Distinct().ToList();
        foreach (var ip in ips) IpInfo.HostName(ip);
        ready = DateTime.UtcNow.AddSeconds(10);
        while (ips.Any(ip => IpInfo.HostName(ip, false) == "") && DateTime.UtcNow < ready) { Application.DoEvents(); System.Threading.Thread.Sleep(50); }
        form.RefreshStatus();
        form.ShowConnections();
        Snap(form, Path.Combine(dir, "connections.png"));
        form.ShowTop();
        form.RefreshLive();
        Snap(form, Path.Combine(dir, "top.png"));
        form.ShowRequests();
        ready = DateTime.UtcNow.AddSeconds(10);
        while (service.Config.Rules.Any(r => AppSignature.Text(r.AppPath) == "") && DateTime.UtcNow < ready) { Application.DoEvents(); System.Threading.Thread.Sleep(50); }
        form.RefreshLive();
        Snap(form, Path.Combine(dir, "rules.png"));
        var rulesTab = form.GetType().GetFields(System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
            .Select(f => f.GetValue(form)).OfType<RulesTab>().First();
        service.Config.Pending.Add(new PendingRequest { AppPath = @"C:\Tools\Printer\printsvc.exe", SawInbound = true, LastRemote = "192.168.1.20:5353", LastProtocol = "UDP", Attempts = 4, FirstSeenUtc = DateTime.UtcNow, LastSeenUtc = DateTime.UtcNow });
        typeof(RulesTab).GetMethod("SortPendingBy", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance).Invoke(rulesTab, new object[] { 4 });
        Snap(form, Path.Combine(dir, "rules-sorted.png"));
        // Half an hour of traffic from around the world, for the map and its timeline.
        var world = new[] { "8.8.8.8", "13.107.4.50", "93.184.216.34", "77.88.8.8", "114.114.114.114", "210.130.1.1", "168.126.63.1", "200.160.2.3",
                            "196.25.1.1", "62.210.0.1", "194.25.0.60", "1.1.1.1", "185.60.216.35", "103.21.244.1", "41.231.53.1", "189.38.95.95" };
        var rnd = new Random(7);
        var apps = new[] { @"C:\Program Files\Browser\browser.exe", @"C:\Windows\System32\svchost.exe", @"C:\Tools\Sync\sync.exe", @"C:\Games\GameLauncher\launcher.exe" };
        var t0 = DateTime.UtcNow;
        var past = new List<FirewallEvent>();
        for (var i = 0; i < 1400; i++)
        {
            var ip = world[(int)(Math.Pow(rnd.NextDouble(), 1.8) * world.Length)];
            var roll = rnd.NextDouble();
            past.Add(new FirewallEvent
            {
                TimeUtc = t0.AddSeconds(-rnd.Next(0, 1800) * (0.4 + 0.6 * rnd.NextDouble())), AppPath = apps[rnd.Next(apps.Length)], Protocol = "TCP",
                Verdict = roll < 0.18 ? Verdict.Blocked : Verdict.Accepted,
                Direction = roll < 0.12 || (roll > 0.8 && roll < 0.92) ? TrafficDirection.Inbound : TrafficDirection.Outbound,
                LocalIp = "192.168.1.5", LocalPort = 50000 + i, RemoteIp = ip, RemotePort = 443
            });
        }
        foreach (var e in past.OrderBy(e => e.TimeUtc)) service.History.Add(e);
        WorldMapTab.AskForLocation = false;
        PublicIp.Set("194.25.0.60");
        service.SetMapHome(null);
        form.ShowMap();
        form.RefreshLive();
        Snap(form, Path.Combine(dir, "map.png"));
        var mapTab = form.GetType().GetFields(System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
            .Select(f => f.GetValue(form)).OfType<WorldMapTab>().First();
        mapTab.WindowMinutes = 15;
        mapTab.Offset = 12;
        Snap(form, Path.Combine(dir, "map-replay.png"));
        using (var where = new LocationForm(service.Location, PublicIp.Address, PublicIp.Country))
        {
            Offscreen(where);
            where.Show();
            Snap(where, Path.Combine(dir, "location.png"));
        }
        Snap(form, Path.Combine(dir, "header-ip.png"));
        using (var c = new CountryBlockForm(new[] { "CN", "RU" })) { Offscreen(c); c.Show(); Snap(c, Path.Combine(dir, "countries.png")); }
        using (var l = new LockdownForm(service.Config.Rules, true)) { Offscreen(l); l.Show(); Snap(l, Path.Combine(dir, "lockdown.png")); }
        service.LastEndpoints = SampleEndpoints();
        foreach (var e in SamplePortEvents()) service.History.Add(e);
        PortsTab.ShareReader = () =>
        {
            var music = new ShareInfo { Name = "Music", Path = @"D:\Music", Type = "Folder", Description = "Family music" };
            music.Users.Add(new ShareUser { Computer = "192.168.1.31", User = @"LIVINGROOM\tv", Files = 2 });
            return new List<ShareInfo>
            {
                music,
                new ShareInfo { Name = "Scans", Path = @"C:\Users\Public\Scans", Type = "Folder" },
                new ShareInfo { Name = "C$", Path = @"C:\", Type = "Folder", Description = "Default share", IsAdmin = true },
                new ShareInfo { Name = "IPC$", Path = "", Type = "Remote control (IPC)", Description = "Remote IPC", IsAdmin = true },
            };
        };
        form.ShowPorts();
        form.RefreshLive();
        for (var i = 0; i < 20; i++) { Application.DoEvents(); System.Threading.Thread.Sleep(50); }
        form.RefreshLive();
        Snap(form, Path.Combine(dir, "ports-tab.png"));
        {
            var meter = service.Bandwidth;
            meter.Running = true;
            var rr = new Random(11);
            var start = DateTime.UtcNow.AddSeconds(-120);
            (string, string) Who(int pid) => pid == 1 ? (@"C:\Program Files\Browser\browser.exe", "browser.exe") : pid == 2 ? (@"C:\Tools\Sync\sync.exe", "sync.exe")
                : pid == 3 ? (@"C:\Program Files\TightVNC\tvnserver.exe", "tvnserver.exe") : pid == 4 ? (@"C:\Tools\Backup\backup.exe", "backup.exe") : (@"C:\Windows\System32\svchost.exe", "svchost.exe");
            meter.Sample(start, Who);
            for (var sec = 1; sec <= 120; sec++)
            {
                var wave = 1 + Math.Sin(sec / 9.0);
                meter.Add(1, "142.250.180.14", false, (int)(700_000 * wave + rr.Next(200_000)));
                meter.Add(1, "142.250.180.14", true, 30_000 + rr.Next(20_000));
                meter.Add(2, "192.168.1.20", false, sec > 40 && sec < 95 ? 2_200_000 + rr.Next(400_000) : 20_000);
                meter.Add(3, "192.168.1.31", true, 600_000 + rr.Next(500_000));
                meter.Add(4, "93.184.216.34", true, sec > 70 ? 350_000 + rr.Next(100_000) : 0);
                meter.Add(5, "13.107.4.50", false, 15_000 + rr.Next(10_000));
                meter.Sample(start.AddSeconds(sec), Who);
            }
        }
        form.ShowBandwidth();
        form.RefreshLive();
        Snap(form, Path.Combine(dir, "bandwidth.png"));
        using (var bl = new BlocklistForm(service)) { Offscreen(bl); bl.Show(); Snap(bl, Path.Combine(dir, "blocklists.png")); }
        using (var pw = new PasswordSetForm(service)) { Offscreen(pw); pw.Show(); Snap(pw, Path.Combine(dir, "password.png")); }
        using (var ed = new RuleEditForm(service.Config.Rules.First(r => r.AppPath.EndsWith("arcade.exe")))) { Offscreen(ed); ed.Show(); Snap(ed, Path.Combine(dir, "edit-hours.png")); }
        Wait(service.SetLockdownAsync(true));
        form.RefreshStatus();
        form.ShowRequests();
        form.RefreshLive();
        Snap(form, Path.Combine(dir, "lockdown-on.png"));
        Wait(service.SetLockdownAsync(false));
        mapTab.Offset = 0;
        mapTab.WindowMinutes = 5;


        service.SavePattern(new PatternRule { Pattern = @"C:\Games\*.*", Action = RuleAction.Allow, Notes = "Everything in the games folder" });
        service.SavePattern(new PatternRule { Pattern = "updater", Action = RuleAction.Block });
        using (var patterns = new PatternsForm(service))
        {
            Offscreen(patterns);
            patterns.Show();
            Snap(patterns, Path.Combine(dir, "patterns.png"));
        }
        using (var patternEdit = new PatternEditForm(service, service.Config.Patterns[0]))
        {
            Offscreen(patternEdit);
            patternEdit.Show();
            Snap(patternEdit, Path.Combine(dir, "pattern-edit.png"));
        }
        var busiest = service.Connections.Query(new ConnectionFilter(), ConnectionColumn.Hits, false).First();
        using (var log = new AppLogForm(service, AppPaths.RuleTarget(busiest.AppPath, busiest.Protocol)))
        {
            Offscreen(log);
            log.Show();
            Snap(log, Path.Combine(dir, "applog.png"));
        }
        // Time and Status moved right, Country first, so the first column and the flag column are both out of place.
        service.SaveColumns("applog", new[] { 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 0 }, null);
        using (var moved = new AppLogForm(service, AppPaths.RuleTarget(busiest.AppPath, busiest.Protocol)))
        {
            Offscreen(moved);
            moved.Show();
            Snap(moved, Path.Combine(dir, "applog-reordered.png"));
        }

        using (var edit = new RuleEditForm(service.FindRule(lanApp.AppPath)))
        {
            Offscreen(edit);
            edit.Show();
            Snap(edit, Path.Combine(dir, "edit.png"));
        }
        using (var exit = new ExitChoiceForm())
        {
            Offscreen(exit);
            exit.Show();
            Snap(exit, Path.Combine(dir, "exit.png"));
        }
        using (var about = new AboutForm())
        {
            Offscreen(about);
            about.Show();
            Snap(about, Path.Combine(dir, "about.png"));
        }
        using (var ports = new PortsForm("chrome.exe", RuleAction.Block, "443"))
        {
            Offscreen(ports);
            ports.Show();
            Snap(ports, Path.Combine(dir, "ports.png"));
        }
        foreach (IconFactory.TrayState st in Enum.GetValues(typeof(IconFactory.TrayState)))
            using (var bmp = IconFactory.Shield(64, st)) bmp.Save(Path.Combine(dir, $"icon_{st}.png"));
        form.AllowClose = true;
        return 0;
    }
}
