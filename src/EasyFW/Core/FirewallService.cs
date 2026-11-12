using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace EasyFW.Core
{
    /// <summary>
    /// Owns config, pending requests and rule state. Called on the UI thread; backend work runs on the
    /// thread pool behind a gate, since COM rule enumeration is slow enough to freeze the window.
    /// </summary>
    public sealed class FirewallService
    {
        private readonly ConfigStore _store;
        private readonly IFirewallBackend _backend;
        private readonly SemaphoreSlim _gate = new SemaphoreSlim(1, 1);
        private readonly HashSet<string> _dismissed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private bool _dirty;
        private DateTime _lastSaveUtc;
        private volatile string _activity;

        public FirewallService(ConfigStore store, IFirewallBackend backend, RunMode mode)
        {
            _store = store;
            _backend = backend;
            Mode = mode;
            // Requests saved before pings had their own entry. Accepting these would open all of System.
            foreach (var p in Config.Pending)
            {
                p.AppPath = AppPaths.RuleTarget(p.AppPath, p.LastProtocol);
                p.FillPortsFromLastRemote();
            }
        }

        public RunMode Mode { get; }
        public bool CanEnforce => Mode != RunMode.MonitorOnly;
        public AppConfig Config => _store.Config;
        public ConnectionStore Connections { get; } = new ConnectionStore();
        public TrafficHistory Traffic { get; } = new TrafficHistory();
        public bool IsEnabled => Config.ProtectionEnabled;
        public int PendingCount => Config.Pending.Count;

        /// <summary>Set while protection is being switched, which takes minutes on a PC with many rules.</summary>
        public string ActivityTitle { get; private set; }
        /// <summary>What the switch is doing right now. Updated from the backend thread, so the UI polls it.</summary>
        public string Activity => _activity;
        public bool IsBusy => _activity != null;
        public bool CanChange => CanEnforce && !IsBusy;
        /// <summary>Exiting stops protection. A snapshot alone means an earlier switch never finished, which needs undoing too.</summary>
        public bool NeedsRestoreOnExit => CanEnforce && (IsEnabled || Config.Snapshot != null);

        /// <summary>Raised on any change to protection state, rules, or pending requests.</summary>
        public event Action Changed;

        private void RaiseChanged() => Changed?.Invoke();

        public void SaveConfig()
        {
            _store.Save();
            _dirty = false;
            _lastSaveUtc = DateTime.UtcNow;
        }

        public string PolicyWarning()
        {
            if (Mode != RunMode.Live) return null;
            try
            {
                var info = _backend.GetPolicyInfo();
                return info.GroupPolicyOverrides ? info.Message : null;
            }
            catch (Exception ex)
            {
                return "Could not read Windows Firewall policy: " + ex.Message;
            }
        }

        private async Task OnBackend(Action work)
        {
            await _gate.WaitAsync();
            try { await Task.Run(work); }
            finally { _gate.Release(); }
        }

        private async Task WithActivity(string title, Func<Task> work)
        {
            ActivityTitle = title;
            _activity = "Reading Windows Firewall rules";
            RaiseChanged();
            try { await work(); }
            finally
            {
                ActivityTitle = null;
                _activity = null;
                RaiseChanged();
            }
        }

        private Action<int, int> Progress(string label) => (done, total) =>
        {
            if (_activity != null) _activity = $"{label}: {done} of {total}";
        };

        private void RequireEnforce()
        {
            if (!CanEnforce) throw new InvalidOperationException("EasyFW doesn't change the firewall in monitor-only mode.");
        }

        public async Task EnableAsync()
        {
            RequireEnforce();
            if (IsEnabled) return;
            await WithActivity("Turning protection on", ApplyProtectionAsync);
        }

        private async Task ApplyProtectionAsync()
        {
            var cfg = Config;
            var specs = RuleTranslator.All(cfg);
            await OnBackend(() =>
            {
                var info = _backend.GetPolicyInfo();
                if (info.GroupPolicyOverrides) throw new InvalidOperationException(info.Message);
                // The snapshot goes to disk before anything changes, so a crash at any step can be undone.
                if (cfg.Snapshot == null)
                {
                    cfg.Snapshot = CaptureOriginalState();
                    _store.Save();
                }
                try
                {
                    DisableForeignRules(cfg);
                    _backend.RemoveManagedRules(null);
                    _backend.AddManagedRules(specs);
                    // Rules first: the moment defaults flip, approved traffic must already have a path.
                    _backend.ApplyBlockDefaults();
                    _backend.EnableAudit();
                }
                catch (Exception ex)
                {
                    Log.Write("Enable failed, rolling back: " + ex);
                    _activity = "Undoing the changes";
                    try
                    {
                        RestoreWindows(cfg);
                        _store.Save();
                    }
                    catch (Exception restoreEx)
                    {
                        Log.Write("Rollback failed, snapshot kept for retry: " + restoreEx);
                    }
                    throw;
                }
            });
            cfg.ProtectionEnabled = true;
            SaveConfig();
        }

        public async Task DisableAsync()
        {
            RequireEnforce();
            var cfg = Config;
            await WithActivity("Turning protection off", async () =>
            {
                await OnBackend(() => RestoreWindows(cfg));
                cfg.ProtectionEnabled = false;
                SaveConfig();
            });
        }

        /// <summary>
        /// EasyFW rules already present mean config was lost while enforcing. What Windows reports now is
        /// EasyFW's own block policy, and "restoring" that later would leave the user locked out.
        /// </summary>
        private WindowsSnapshot CaptureOriginalState()
        {
            if (!_backend.HasManagedRules()) return _backend.CaptureState();
            Log.Write("Found EasyFW rules with no snapshot; falling back to stock Windows defaults for restore.");
            return WindowsSnapshot.StockDefaults();
        }

        private List<string> DisableForeignRules(AppConfig cfg)
        {
            var keys = _backend.ListForeignAllowRules();
            if (keys.Count == 0) return keys;
            // Recorded before they are switched off, so a crash can't orphan a disabled rule.
            cfg.Snapshot.DisabledRuleKeys.AddRange(keys.Where(k => !cfg.Snapshot.DisabledRuleKeys.Contains(k)).ToList());
            _store.Save();
            _backend.SetRulesEnabled(keys, false, Progress("Switching off existing allow rules"));
            return keys;
        }

        /// <summary>Clears the snapshot only after a clean restore, so a partial failure can be retried.</summary>
        private void RestoreWindows(AppConfig cfg)
        {
            if (cfg.Snapshot == null && !_backend.HasManagedRules()) return;
            var snapshot = cfg.Snapshot ?? WindowsSnapshot.StockDefaults();
            _backend.RestoreState(snapshot);
            _backend.SetRulesEnabled(snapshot.DisabledRuleKeys, true, Progress("Switching existing allow rules back on"));
            _backend.RemoveManagedRules(null);
            cfg.Snapshot = null;
        }

        /// <summary>Re-applies enforcement when an installer or tool has weakened it. Runs at startup and once a minute.</summary>
        /// <returns>Number of rules newly switched off.</returns>
        public async Task<int> ReconcileAsync(bool rebuildRules)
        {
            // A check queued behind a turn-off would run after it and block everything again.
            if (!CanEnforce || !IsEnabled || IsBusy) return 0;
            var cfg = Config;
            var specs = RuleTranslator.All(cfg);
            var count = 0;
            await OnBackend(() =>
            {
                if (cfg.Snapshot == null)
                {
                    cfg.Snapshot = CaptureOriginalState();
                    _store.Save();
                }
                count = DisableForeignRules(cfg).Count;
                if (rebuildRules)
                {
                    _backend.RemoveManagedRules(null);
                    _backend.AddManagedRules(specs);
                }
                if (!_backend.IsBlockDefaultActive())
                {
                    Log.Write("Default-block policy was changed externally; re-applying.");
                    _backend.ApplyBlockDefaults();
                }
                // An interrupted turn-off may have put the audit setting back, which would hide every blocked attempt.
                if (rebuildRules) _backend.EnableAudit();
            });
            if (count > 0) Log.Write($"Disabled {count} allow rule(s) added outside EasyFW.");
            return count;
        }

        public AppRule FindRule(string appPath) =>
            Config.Rules.FirstOrDefault(r => AppPaths.Same(r.AppPath, appPath));

        public async Task SaveRuleAsync(AppRule rule)
        {
            RequireEnforce();
            rule.AppPath = AppPaths.Normalize(rule.AppPath);
            if (string.IsNullOrEmpty(rule.AppPath)) throw new ArgumentException("An application is required.");
            rule.Ports = PortList.Normalize(rule.Ports);
            if (rule.HasPorts && AppPaths.Same(rule.AppPath, AppPaths.PingApp)) throw new ArgumentException("Pings don't use ports, so a ping rule can't be limited to certain ports.");
            rule.NormalizeNetwork();

            // One rule per app: saving over another app's path replaces that rule.
            var replaced = Config.Rules.Where(r => r.Id == rule.Id || AppPaths.Same(r.AppPath, rule.AppPath)).ToList();
            if (IsEnabled)
            {
                var specs = RuleTranslator.ForApp(rule).ToList();
                await OnBackend(() =>
                {
                    foreach (var old in replaced) _backend.RemoveManagedRules(RuleTranslator.Tag(old));
                    _backend.AddManagedRules(specs);
                });
            }
            foreach (var old in replaced) Config.Rules.Remove(old);
            Config.Rules.Add(rule);
            ClearCoveredPending(rule);
            SaveConfig();
            RaiseChanged();
        }

        /// <summary>Adds the rules to the existing ones. A rule for an app that already has one replaces it.</summary>
        public async Task ImportRulesAsync(IReadOnlyCollection<AppRule> rules)
        {
            RequireEnforce();
            var replaced = Config.Rules.Where(r => rules.Any(n => AppPaths.Same(n.AppPath, r.AppPath))).ToList();
            await WithActivity("Importing rules", async () =>
            {
                if (IsEnabled)
                {
                    var previous = RuleTranslator.All(Config);
                    var specs = rules.SelectMany(RuleTranslator.ForApp).ToList();
                    await OnBackend(() => ReplaceManagedRules(replaced, specs, previous));
                }
                foreach (var old in replaced) Config.Rules.Remove(old);
                foreach (var rule in rules)
                {
                    Config.Rules.Add(rule);
                    ClearCoveredPending(rule);
                }
                SaveConfig();
            });
        }

        private void ReplaceManagedRules(List<AppRule> replaced, List<FirewallRuleSpec> specs, List<FirewallRuleSpec> previous)
        {
            try
            {
                _activity = "Updating Windows Firewall rules";
                foreach (var old in replaced) _backend.RemoveManagedRules(RuleTranslator.Tag(old));
                _backend.AddManagedRules(specs);
            }
            catch (Exception)
            {
                // A partial import would leave allow rules in Windows that no saved rule accounts for.
                try
                {
                    _backend.RemoveManagedRules(null);
                    _backend.AddManagedRules(previous);
                }
                catch (Exception undoEx) { Log.Write("Could not undo a failed import: " + undoEx); }
                throw;
            }
        }

        public async Task DeleteRuleAsync(AppRule rule)
        {
            RequireEnforce();
            if (IsEnabled) await OnBackend(() => _backend.RemoveManagedRules(RuleTranslator.Tag(rule)));
            Config.Rules.RemoveAll(r => r.Id == rule.Id);
            _dismissed.Remove(rule.AppPath);
            SaveConfig();
            RaiseChanged();
        }

        /// <param name="ports">Null decides for all ports, and clears any ports set earlier.</param>
        public Task DecideAsync(string appPath, RuleAction action, string ports = null)
        {
            var rule = FindRule(appPath)?.Clone() ?? new AppRule { AppPath = appPath };
            rule.Action = action;
            rule.Ports = ports;
            rule.Direction = RuleDirection.Both;
            rule.Enabled = true;
            return SaveRuleAsync(rule);
        }

        public void Dismiss(string appPath)
        {
            _dismissed.Add(appPath);
            Config.Pending.RemoveAll(p => AppPaths.Same(p.AppPath, appPath));
            _dirty = true;
            RaiseChanged();
        }

        private void ClearCoveredPending(AppRule rule)
        {
            var pending = Config.Pending.FirstOrDefault(p => AppPaths.Same(p.AppPath, rule.AppPath));
            if (pending == null) return;
            if (rule.Covers(TrafficDirection.Inbound)) pending.SawInbound = false;
            if (rule.Covers(TrafficDirection.Outbound)) pending.SawOutbound = false;
            if (!pending.SawInbound && !pending.SawOutbound) Config.Pending.Remove(pending);
        }

        /// <summary>What the current policy does with an app's traffic on a port, to or from a remote address.</summary>
        /// <param name="remoteIp">Null skips the internet and LAN limits.</param>
        public Verdict Evaluate(string appPath, TrafficDirection direction, int port, string remoteIp = null)
        {
            if (!IsEnabled) return Verdict.Accepted;
            var rule = FindRule(appPath);
            return rule != null && rule.Enabled && rule.Covers(direction) && rule.AllowsPort(port) && (remoteIp == null || rule.AllowsAddress(remoteIp))
                ? Verdict.Accepted : Verdict.Blocked;
        }

        /// <summary>
        /// Open connections the current rules don't allow. Windows Firewall only judges new connections, so these would otherwise carry on.
        /// Loopback is left alone because the firewall doesn't filter it, and connections with no known program can't be given a rule.
        /// </summary>
        public List<ActiveEndpoint> FindDisallowed(IEnumerable<ActiveEndpoint> active)
        {
            if (!IsEnabled || IsBusy) return new List<ActiveEndpoint>();
            return active.Where(e => e.Protocol == "TCP" && e.State == "Established"
                    && e.Pid != 0 && !string.IsNullOrEmpty(e.AppPath)
                    && !IpText.IsLoopback(e.LocalIp) && !IpText.IsLoopback(e.RemoteIp)
                    && !IsEssentialConnection(e)
                    && Evaluate(e.AppPath, e.Direction, e.Direction == TrafficDirection.Inbound ? e.LocalPort : e.RemotePort, e.RemoteIp) == Verdict.Blocked)
                .ToList();
        }

        private bool IsEssentialConnection(ActiveEndpoint e) =>
            Config.AllowEssentials && AppPaths.IsSharedServiceHost(e.AppPath) && (e.RemotePort == 53 || e.RemotePort == 80);

        /// <summary>Records connections EasyFW has just closed, the same way as any other blocked attempt.</summary>
        public List<PendingRequest> ReportClosed(IEnumerable<ActiveEndpoint> closed) =>
            ProcessEvents(closed.Select(e => new FirewallEvent
            {
                TimeUtc = DateTime.UtcNow, Verdict = Verdict.Blocked, Pid = e.Pid, AppPath = e.AppPath, Direction = e.Direction,
                Protocol = e.Protocol, LocalIp = e.LocalIp, LocalPort = e.LocalPort, RemoteIp = e.RemoteIp, RemotePort = e.RemotePort
            }));

        /// <returns>Requests from applications seen for the first time, for notification.</returns>
        public List<PendingRequest> ProcessEvents(IEnumerable<FirewallEvent> events)
        {
            var added = new List<PendingRequest>();
            var any = false;
            foreach (var e in events)
            {
                Connections.Add(e);
                if (e.Verdict != Verdict.Blocked || e.IsLoopback || string.IsNullOrEmpty(e.AppPath)) continue;
                var target = AppPaths.RuleTarget(e.AppPath, e.Protocol);
                if (_dismissed.Contains(target)) continue;
                // Disabled rules count too: the user has already made a decision about this app.
                var rule = FindRule(target);
                if (rule != null && rule.Covers(e.Direction)) continue;

                var p = Config.Pending.FirstOrDefault(x => AppPaths.Same(x.AppPath, target));
                if (p == null)
                {
                    p = new PendingRequest { AppPath = target, FirstSeenUtc = e.TimeUtc };
                    Config.Pending.Add(p);
                    added.Add(p);
                }
                p.LastSeenUtc = e.TimeUtc;
                p.Attempts++;
                p.LastRemote = $"{e.RemoteIp}:{e.RemotePort}";
                var inbound = e.Direction == TrafficDirection.Inbound;
                p.LastSourcePort = inbound ? e.RemotePort : e.LocalPort;
                p.LastDestPort = inbound ? e.LocalPort : e.RemotePort;
                p.LastProtocol = e.Protocol;
                if (e.Direction == TrafficDirection.Inbound) p.SawInbound = true;
                else p.SawOutbound = true;
                any = true;
            }
            if (any)
            {
                _dirty = true;
                RaiseChanged();
            }
            return added;
        }

        /// <summary>Batches saves of attempt counters, which can change many times a second.</summary>
        public void FlushIfDirty()
        {
            if (!_dirty || (DateTime.UtcNow - _lastSaveUtc).TotalSeconds < 5) return;
            try { SaveConfig(); }
            catch (Exception ex) { Log.Write("Save failed: " + ex.Message); }
        }
    }
}
