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
            _internetApps.UnionWith(Config.InternetApps);
            QueuePatternMatches();
        }

        private readonly HashSet<string> _internetApps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        /// <summary>Apps a pattern rule has decided for, waiting for their own rule to be saved.</summary>
        private readonly Dictionary<string, PatternRule> _patternQueue = new Dictionary<string, PatternRule>(StringComparer.OrdinalIgnoreCase);
        private bool _applyingPatterns;

        /// <summary>The last hour of connection attempts, for an app's log.</summary>
        public EventHistory History { get; } = new EventHistory();

        /// <summary>Whether the app has been seen connecting, or trying to connect, to an internet address.</summary>
        public bool UsesInternet(string ruleTarget) => _internetApps.Contains(ruleTarget ?? "");

        private void NoteInternet(FirewallEvent e)
        {
            if (string.IsNullOrEmpty(e.AppPath) || !NetRanges.IsInternet(e.RemoteIp)) return;
            var target = AppPaths.RuleTarget(e.AppPath, e.Protocol);
            if (!_internetApps.Add(target)) return;
            Config.InternetApps.Add(target);
            _dirty = true;
        }

        /// <summary>Remembers a list's column order and widths. Saved with the next batched save.</summary>
        public void SaveColumns(string list, int[] order, int[] widths)
        {
            Config.Columns ??= new List<ColumnLayout>();
            Config.Columns.RemoveAll(c => c.List == list);
            if (order != null) Config.Columns.Add(new ColumnLayout { List = list, Order = order, Widths = widths });
            _dirty = true;
        }

        /// <summary>
        /// Where the world map puts this PC: the place the user chose, else the country of the public IP,
        /// else the Windows region, else Germany so the map still draws.
        /// </summary>
        public MapLocation Location
        {
            get
            {
                if (WorldGeo.TryLocate(Config.MapHome, out var lat, out var lon))
                {
                    var city = WorldGeo.FindCity(Config.MapHome, Config.MapCity);
                    return new MapLocation(Config.MapHome.ToUpperInvariant(), city?.Name, city?.Lat ?? lat, city?.Lon ?? lon, LocationSource.Chosen);
                }
                var ip = Config.NoPublicIpLookup ? null : PublicIp.Country;
                if (WorldGeo.TryLocate(ip, out lat, out lon)) return new MapLocation(ip.ToUpperInvariant(), null, lat, lon, LocationSource.PublicIp);
                var region = WorldGeo.HomeFromWindows();
                if (WorldGeo.TryLocate(region, out lat, out lon)) return new MapLocation(region, null, lat, lon, LocationSource.Windows);
                WorldGeo.TryLocate("DE", out lat, out lon);
                return new MapLocation("DE", null, lat, lon, LocationSource.Guess);
            }
        }

        public string MapHome => Location.Country;

        /// <param name="country">Null to go back to finding it out.</param>
        public void SetMapHome(string country, string city = null)
        {
            Config.MapHome = country;
            Config.MapCity = country == null ? null : city;
            _dirty = true;
        }

        /// <summary>Whether a program has a valid digital signature: null while still being checked. Swappable for tests.</summary>
        public Func<string, bool?> SignatureCheck { get; set; } = EasyFW.Platform.AppSignature.IsSigned;

        /// <summary>Apps an Accept pattern matched but couldn't accept, because they aren't signed. They stay pending for the user.</summary>
        private readonly HashSet<string> _unsigned = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// The first enabled pattern that covers the app. Block patterns go first, so an app matching both stays blocked.
        /// Accept patterns skip apps already found to be unsigned.
        /// </summary>
        public PatternRule MatchingPattern(string appPath) =>
            Config.Patterns.Where(p => p.Enabled && p.Matches(appPath) && (p.Action == RuleAction.Block || !_unsigned.Contains(appPath)))
                .OrderBy(p => p.Action == RuleAction.Block ? 0 : 1).FirstOrDefault();

        /// <summary>Pending apps that a pattern now covers get its decision on the next tick.</summary>
        private void QueuePatternMatches()
        {
            foreach (var p in Config.Pending)
            {
                if (FindRule(p.AppPath) != null) continue;
                var pattern = MatchingPattern(p.AppPath);
                if (pattern != null) _patternQueue[p.AppPath] = pattern;
            }
        }

        /// <summary>Gives each app a pattern has matched a rule of its own. Called once a second; does nothing while busy.</summary>
        /// <returns>How many rules were added.</returns>
        public async Task<int> ApplyPatternsAsync()
        {
            if (_patternQueue.Count == 0 || _applyingPatterns || !CanChange) return 0;
            _applyingPatterns = true;
            var count = 0;
            try
            {
                foreach (var item in _patternQueue.ToList())
                {
                    // The user may have decided by hand, or changed the pattern, since it was queued.
                    if (FindRule(item.Key) != null || !Config.Patterns.Contains(item.Value) || !item.Value.Enabled || !item.Value.Matches(item.Key))
                    {
                        _patternQueue.Remove(item.Key);
                        continue;
                    }
                    // Accept patterns only accept apps with a valid digital signature. The check runs in the background,
                    // so an app stays queued until it's done. An unsigned app stays a pending request for the user to decide.
                    if (item.Value.Action == RuleAction.Allow)
                    {
                        var signed = SignatureCheck(item.Key);
                        if (signed == null) continue;
                        if (signed == false)
                        {
                            _patternQueue.Remove(item.Key);
                            _unsigned.Add(item.Key);
                            Log.Write($"Pattern {item.Value.Pattern} matched {item.Key}, but it isn't signed, so it was left for you to decide.");
                            RaiseChanged();
                            continue;
                        }
                    }
                    _patternQueue.Remove(item.Key);
                    var rule = new AppRule
                    {
                        AppPath = item.Key, Action = item.Value.Action, Direction = RuleDirection.Both, Enabled = true,
                        Notes = $"From pattern {item.Value.Pattern}"
                    };
                    try
                    {
                        await SaveRuleAsync(rule);
                        count++;
                        Log.Write($"Pattern {item.Value.Pattern} added a {(rule.Action == RuleAction.Allow ? "Accept" : "Block")} Always rule for {item.Key}.");
                    }
                    catch (Exception ex) { Log.Write($"Pattern {item.Value.Pattern} could not add a rule for {item.Key}: {ex.Message}"); }
                }
            }
            finally { _applyingPatterns = false; }
            return count;
        }

        public void SavePattern(PatternRule pattern)
        {
            pattern.Pattern = (pattern.Pattern ?? "").Trim().Trim('"');
            if (pattern.Pattern.Length == 0) throw new ArgumentException("Enter a path pattern or a keyword.");
            if (pattern.IsKeyword && pattern.Pattern.Length < 3) throw new ArgumentException("A keyword needs at least 3 letters, or it would match almost every app.");
            if (pattern.Pattern.Trim('*', '.', '?', '\\').Length == 0) throw new ArgumentException("That pattern matches every app. Name a folder or a keyword.");
            Config.Patterns.RemoveAll(p => p.Id == pattern.Id);
            Config.Patterns.Add(pattern);
            QueuePatternMatches();
            SaveConfig();
            RaiseChanged();
        }

        public void DeletePattern(PatternRule pattern)
        {
            Config.Patterns.RemoveAll(p => p.Id == pattern.Id);
            foreach (var key in _patternQueue.Where(x => x.Value.Id == pattern.Id).Select(x => x.Key).ToList()) _patternQueue.Remove(key);
            SaveConfig();
            RaiseChanged();
        }

        /// <summary>Apps with a request or a rule that the pattern covers, to show what it would catch.</summary>
        public List<string> PatternPreview(PatternRule pattern) =>
            Config.Pending.Select(p => p.AppPath).Concat(Config.Rules.Select(r => r.AppPath))
                .Where(pattern.Matches).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        public RunMode Mode { get; }
        public bool CanEnforce => Mode != RunMode.MonitorOnly;
        public AppConfig Config => _store.Config;
        public ConnectionStore Connections { get; } = new ConnectionStore();
        /// <summary>Data rates per app, internet and LAN.</summary>
        public BandwidthMeter Bandwidth { get; } = new BandwidthMeter();
        /// <summary>Every endpoint from the last poll, listening ports included. Read on the UI thread.</summary>
        public List<ActiveEndpoint> LastEndpoints { get; set; } = new List<ActiveEndpoint>();
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
                    _backend.AddManagedRules(specs.Concat(RuleTranslator.CountryRules(cfg)).Concat(RuleTranslator.BlocklistRules(Blocklist.Entries)));
                    NoteEffects();
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
                    _backend.AddManagedRules(specs.Concat(RuleTranslator.CountryRules(cfg)).Concat(RuleTranslator.BlocklistRules(Blocklist.Entries)));
                    NoteEffects();
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
                var specs = RuleTranslator.ForAppNow(rule, Config).ToList();
                _effect[rule.Id] = RuleTranslator.InEffect(rule, Config, RuleTranslator.LocalNow());
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
                    var specs = rules.SelectMany(r => RuleTranslator.ForAppNow(r, Config)).ToList();
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
                    _backend.AddManagedRules(previous.Concat(RuleTranslator.CountryRules(Config)).Concat(RuleTranslator.BlocklistRules(Blocklist.Entries)));
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
        /// <param name="duration">How long the decision lasts. Afterwards the rule is deleted and the app asks again.</param>
        public Task DecideAsync(string appPath, RuleAction action, string ports = null, RuleDuration duration = RuleDuration.Forever)
        {
            var rule = FindRule(appPath)?.Clone() ?? new AppRule { AppPath = appPath };
            rule.Action = action;
            rule.Ports = ports;
            rule.Direction = RuleDirection.Both;
            rule.Enabled = true;
            rule.SetDuration(duration, Clock(), BootTime());
            return SaveRuleAsync(rule);
        }

        /// <summary>Swappable for tests.</summary>
        public Func<DateTime> Clock { get; set; } = () => DateTime.UtcNow;

        /// <summary>When Windows started. Swappable for tests.</summary>
        public Func<DateTime> BootTime { get; set; } = SystemBoot.Utc;

        /// <summary>Deletes rules whose time is up. Called every second; does nothing when none are due.</summary>
        /// <returns>The rules that ended.</returns>
        public async Task<List<AppRule>> ExpireRulesAsync()
        {
            if (!CanChange || IsBusy) return new List<AppRule>();
            var now = Clock();
            var boot = BootTime();
            var due = Config.Rules.Where(r => r.HasExpired(now, boot)).ToList();
            foreach (var rule in due)
            {
                Log.Write($"Rule for {rule.AppPath} ended ({rule.ExpiresText(now)}). The app is blocked again and will ask.");
                await DeleteRuleAsync(rule);
            }
            return due;
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
            if (remoteIp != null && Blocklist.Match(remoteIp) != null) return Verdict.Blocked;
            if (remoteIp != null && Config.BlockedCountries.Count > 0 && CountryOf(remoteIp) is string code && Config.BlockedCountries.Contains(code)) return Verdict.Blocked;
            var rule = FindRule(appPath);
            return rule != null && RuleTranslator.InEffect(rule, Config, RuleTranslator.LocalNow()) && rule.Covers(direction) && rule.AllowsPort(port) && (remoteIp == null || rule.AllowsAddress(remoteIp))
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
                    && !IsOwnConnection(e)
                    && Evaluate(e.AppPath, e.Direction, e.Direction == TrafficDirection.Inbound ? e.LocalPort : e.RemotePort, e.RemoteIp) == Verdict.Blocked)
                .ToList();
        }

        private bool IsOwnConnection(ActiveEndpoint e) =>
            Config.NeedsOwnConnection && e.RemotePort == 443 && !string.IsNullOrEmpty(RuleTranslator.SelfPath) && AppPaths.Same(e.AppPath, RuleTranslator.SelfPath);

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
                History.Add(e);
                NoteInternet(e);
                if (e.Verdict != Verdict.Blocked || e.IsLoopback || string.IsNullOrEmpty(e.AppPath)) continue;
                var target = AppPaths.RuleTarget(e.AppPath, e.Protocol);
                if (_dismissed.Contains(target)) continue;
                // Disabled rules count too: the user has already made a decision about this app.
                var rule = FindRule(target);
                if (rule != null && rule.Covers(e.Direction)) continue;
                // A Block pattern decides at once. An Accept pattern still lists the app, without a notification,
                // because it's only accepted once its signature checks out; an unsigned app stays here for the user.
                var byPattern = false;
                if (rule == null && Config.Patterns.Count > 0)
                {
                    if (!_patternQueue.TryGetValue(target, out var pattern))
                    {
                        pattern = MatchingPattern(target);
                        if (pattern != null) _patternQueue[target] = pattern;
                    }
                    if (pattern?.Action == RuleAction.Block) continue;
                    byPattern = pattern != null;
                }

                var p = Config.Pending.FirstOrDefault(x => AppPaths.Same(x.AppPath, target));
                if (p == null)
                {
                    p = new PendingRequest { AppPath = target, FirstSeenUtc = e.TimeUtc };
                    Config.Pending.Add(p);
                    if (!byPattern) added.Add(p);
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
        /// <summary>Where blocklists are kept. Null in tests unless set.</summary>
        public string BlocklistFolder { get; set; }

        /// <summary>The addresses on the chosen blocklists, from the kept copies.</summary>
        public BlocklistIndex Blocklist { get; private set; } = BlocklistIndex.Empty;

        /// <summary>Reads the kept lists into <see cref="Blocklist"/>. No download.</summary>
        public void LoadBlocklists()
        {
            Blocklist = Config.Blocklists.Count == 0 ? BlocklistIndex.Empty
                : BlocklistIndex.Build(Blocklists.LoadKept(Config.Blocklists, BlocklistFolder), Config.BlocklistExceptions);
            BlocklistIndex.Current = Blocklist;
        }

        /// <summary>Puts the current lists into Windows Firewall.</summary>
        public async Task ApplyBlocklistsAsync()
        {
            LoadBlocklists();
            if (IsEnabled && CanEnforce)
            {
                var specs = RuleTranslator.BlocklistRules(Blocklist.Entries);
                await OnBackend(() =>
                {
                    _backend.RemoveManagedRules(Blocklists.Tag);
                    _backend.AddManagedRules(specs);
                });
            }
            Log.Write($"Blocklists in force: {Blocklist.Count:N0} entries from {string.Join(", ", Config.Blocklists)}.");
            RaiseChanged();
        }

        /// <summary>Chooses the lists and exceptions, downloads lists not kept yet, and applies them.</summary>
        /// <returns>Problems with downloads, one per line, or empty.</returns>
        public async Task<string> SetBlocklistsAsync(IEnumerable<string> ids, IEnumerable<string> exceptions)
        {
            RequireEnforce();
            var hadConnection = Config.NeedsOwnConnection;
            Config.Blocklists = ids.Where(id => Blocklists.Find(id) != null).Distinct().ToList();
            Config.BlocklistExceptions = exceptions.Select(e => e.Trim()).Where(e => e.Length > 0).Distinct().ToList();
            var bad = Config.BlocklistExceptions.Where(e => !NetRanges.TryNormalize(e, out _)).ToList();
            if (bad.Count > 0) throw new FormatException($"\"{bad[0]}\" isn't an address or subnet. Use a form like 203.0.113.5 or 203.0.113.0/24.");
            SaveConfig();
            // EasyFW needs its own HTTPS rule to download the lists.
            if (!hadConnection && Config.NeedsOwnConnection) await ReconcileAsync(true);
            var missing = Config.Blocklists.Where(id => Blocklists.KeptTimeUtc(id, BlocklistFolder) == null).ToList();
            var problems = missing.Count > 0 ? await DownloadBlocklistsAsync(missing) : "";
            await ApplyBlocklistsAsync();
            if (hadConnection && !Config.NeedsOwnConnection) await ReconcileAsync(true);
            return problems;
        }

        /// <summary>Downloads the chosen lists again and applies them. A list that fails keeps its last copy.</summary>
        public async Task<string> UpdateBlocklistsAsync()
        {
            if (Config.Blocklists.Count == 0) return "";
            var problems = await DownloadBlocklistsAsync(Config.Blocklists);
            Config.BlocklistsUpdatedUtc = DateTime.UtcNow;
            MarkDirty();
            if (CanEnforce) await ApplyBlocklistsAsync();
            return problems;
        }

        private async Task<string> DownloadBlocklistsAsync(IEnumerable<string> ids)
        {
            var problems = new List<string>();
            foreach (var source in ids.Select(Blocklists.Find).Where(s => s != null))
            {
                try
                {
                    var n = await Blocklists.DownloadAsync(source, BlocklistFolder ?? Blocklists.DefaultFolder);
                    Log.Write($"Blocklist {source.Name}: {n:N0} entries.");
                }
                catch (Exception ex) when (!(ex is OutOfMemoryException))
                {
                    Log.Write($"Blocklist {source.Name} didn't download: {ex.Message}");
                    problems.Add($"{source.Name}: {ex.Message}");
                }
            }
            return string.Join("\n", problems);
        }

        /// <summary>Country of an address, swappable for tests.</summary>
        public Func<string, string> CountryOf { get; set; } = IpInfo.CountryCode;

        /// <summary>Whether each rule's Windows rules were in place when last applied, by rule id. Schedules compare against it.</summary>
        private readonly Dictionary<string, bool> _effect = new Dictionary<string, bool>();

        /// <summary>The LAN that the Windows rules were last built for.</summary>
        private int _lanVersion = -1;

        /// <summary>
        /// Rules limited to the LAN name its addresses, so they're rebuilt when the PC joins another network. Called every tick.
        /// </summary>
        public async Task ApplyLanChangeAsync()
        {
            var version = NetRanges.Version;
            if (version == _lanVersion || !IsEnabled || !CanChange) return;
            var needed = _lanVersion >= 0 && Config.Rules.Any(r => r.Enabled && r.LimitsNetwork);
            _lanVersion = version;
            if (!needed) return;
            Log.Write("The local network changed (" + NetRanges.LanText + "). Rebuilding rules with LAN limits.");
            await ReconcileAsync(true);
        }

        private void NoteEffects()
        {
            _lanVersion = NetRanges.Version;
            var now = RuleTranslator.LocalNow();
            _effect.Clear();
            foreach (var r in Config.Rules) _effect[r.Id] = RuleTranslator.InEffect(r, Config, now);
        }

        /// <summary>Blocks all traffic with these countries, for every app, replacing the earlier list.</summary>
        public async Task SetBlockedCountriesAsync(IEnumerable<string> countries)
        {
            RequireEnforce();
            var list = countries.Select(c => c.ToUpperInvariant()).Distinct().OrderBy(c => c).ToList();
            await WithActivity("Updating blocked countries", async () =>
            {
                var cfg = Config;
                cfg.BlockedCountries = list;
                if (IsEnabled)
                    await OnBackend(() =>
                    {
                        _backend.RemoveManagedRules(RuleTranslator.CountryTag);
                        _backend.AddManagedRules(RuleTranslator.CountryRules(cfg));
                    });
                SaveConfig();
            });
            Log.Write(list.Count == 0 ? "No countries blocked." : "Blocked countries: " + string.Join(", ", list));
            RaiseChanged();
        }

        /// <summary>During a lockdown only plain block rules and accept rules marked to keep working stay in force.</summary>
        public async Task SetLockdownAsync(bool on)
        {
            RequireEnforce();
            if (Config.Lockdown == on) return;
            Config.Lockdown = on;
            SaveConfig();
            Log.Write(on ? "Lockdown on: only apps chosen for lockdown may connect." : "Lockdown off.");
            await ReconcileAsync(true);
            RaiseChanged();
        }

        /// <summary>Marks which accept rules keep working during a lockdown, and applies it now if one is on.</summary>
        public async Task SetLockdownAppsAsync(IEnumerable<string> ruleIds)
        {
            RequireEnforce();
            var keep = new HashSet<string>(ruleIds);
            foreach (var r in Config.Rules) r.KeepInLockdown = keep.Contains(r.Id);
            SaveConfig();
            if (Config.Lockdown) await ReconcileAsync(true);
            RaiseChanged();
        }

        /// <summary>Opens and closes apps whose hours have started or ended. Called every tick; does nothing between changes.</summary>
        /// <returns>The rules switched, and whether each is now allowed.</returns>
        public async Task<List<(AppRule Rule, bool Allowed)>> ApplySchedulesAsync()
        {
            var switched = new List<(AppRule, bool)>();
            if (!IsEnabled || !CanChange) return switched;
            var now = RuleTranslator.LocalNow();
            foreach (var rule in Config.Rules.Where(r => r.HasSchedule).ToList())
            {
                var on = RuleTranslator.InEffect(rule, Config, now);
                if (_effect.TryGetValue(rule.Id, out var was) && was == on) continue;
                var known = _effect.ContainsKey(rule.Id);
                _effect[rule.Id] = on;
                if (!known) continue;
                var specs = on ? RuleTranslator.ForApp(rule).ToList() : new List<FirewallRuleSpec>();
                await OnBackend(() =>
                {
                    _backend.RemoveManagedRules(RuleTranslator.Tag(rule));
                    _backend.AddManagedRules(specs);
                });
                Log.Write($"Schedule: {rule.DisplayName} is {(on ? "allowed" : "blocked")} now ({rule.ScheduleText}).");
                switched.Add((rule, on));
            }
            if (switched.Count > 0) RaiseChanged();
            return switched;
        }

        public bool HasPassword => !string.IsNullOrEmpty(Config.PasswordHash);

        public bool CheckPassword(string password) => !HasPassword || Password.Verify(password, Config.PasswordHash);

        /// <param name="password">Null or empty removes the password.</param>
        public void SetPassword(string password)
        {
            Config.PasswordHash = string.IsNullOrEmpty(password) ? null : Password.Hash(password);
            SaveConfig();
            Log.Write(HasPassword ? "Password protection set." : "Password protection removed.");
        }

        /// <summary>For settings changed outside the service: saved on the next tick.</summary>
        public void MarkDirty() => _dirty = true;

        public void FlushIfDirty()
        {
            if (!_dirty || (DateTime.UtcNow - _lastSaveUtc).TotalSeconds < 5) return;
            try { SaveConfig(); }
            catch (Exception ex) { Log.Write("Save failed: " + ex.Message); }
        }
    }
}
