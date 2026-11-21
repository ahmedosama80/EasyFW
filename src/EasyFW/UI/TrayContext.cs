using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using EasyFW.Core;
using Timer = System.Windows.Forms.Timer;

namespace EasyFW.UI
{
    /// <summary>The app's lifetime owner: tray icon, the one-second pump, and the main window.</summary>
    public sealed class TrayContext : ApplicationContext
    {
        private readonly AppEnvironment _env;
        private readonly FirewallService _service;
        private readonly NotifyIcon _tray;
        private readonly ToolStripMenuItem _statusItem, _pendingItem, _toggleItem;
        private readonly HashSet<string> _closeFailures = new HashSet<string>();
        private readonly MainForm _form;
        private readonly Timer _tick = new Timer { Interval = 1000 };
        private readonly ConcurrentQueue<FirewallEvent> _queue = new ConcurrentQueue<FirewallEvent>();
        private readonly RegisteredWaitHandle _showWait;
        private readonly EventWaitHandle _showSignal;
        private bool _polling;
        private bool _toggling;
        private bool _exiting;
        private bool _balloonOpensRequests;
        private DateTime _nextReconcileUtc = DateTime.UtcNow.AddMinutes(1);
        private IconFactory.TrayState? _shownState;
        /// <summary>The first lookup waits for startup to put EasyFW's own allow rule in place.</summary>
        private DateTime _nextPublicIpUtc = DateTime.UtcNow.AddSeconds(8);

        public TrayContext(AppEnvironment env, bool startInTray, EventWaitHandle showSignal)
        {
            _env = env;
            _service = env.Service;
            _showSignal = showSignal;
            _form = new MainForm(env.Service, ToggleAsync, ExitApp);
            _form.SetSetupSource(env.PollActive);
            _form.CheckUpdatesRequested = () => CheckForUpdatesAsync(true);
            _form.HiddenToTray += () => ShowBalloon("EasyFW is still running", "Protection stays on. Right-click the shield in the tray and choose Exit to stop it.", ToolTipIcon.Info, false);
            // Forces the window handle so a second launch can signal this one while it's hidden.
            _ = _form.Handle;

            _statusItem = new ToolStripMenuItem { Enabled = false };
            _pendingItem = new ToolStripMenuItem("", null, (_, __) => _form.ShowRequests());
            _toggleItem = new ToolStripMenuItem("", null, async (_, __) => await ToggleAsync());
            var menu = new ContextMenuStrip();
            menu.Items.Add(_statusItem);
            menu.Items.Add(_pendingItem);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Open EasyFW", null, (_, __) => _form.ShowConnections()).Font = new System.Drawing.Font(menu.Font, System.Drawing.FontStyle.Bold);
            menu.Items.Add(_toggleItem);
            _lockdownItem = new ToolStripMenuItem("Lockdown", null, async (_, __) => await LockdownForm.ToggleAsync(_form.Visible ? (IWin32Window)_form : null, _service));
            menu.Items.Add(_lockdownItem);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Exit", null, (_, __) => ExitApp());

            _tray = new NotifyIcon { ContextMenuStrip = menu, Visible = true };
            _tray.MouseClick += (_, e) => { if (e.Button == MouseButtons.Left) _form.ShowConnections(); };
            _tray.BalloonTipClicked += (_, __) =>
            {
                if (_balloonOpensRequests) _form.ShowRequests();
                else _form.ShowConnections();
            };

            _service.Changed += OnServiceChanged;
            OnServiceChanged();

            if (showSignal != null)
            {
                _showWait = ThreadPool.RegisterWaitForSingleObject(showSignal, (_, __) =>
                {
                    if (_form.IsHandleCreated) _form.BeginInvoke((Action)_form.ShowConnections);
                }, null, Timeout.Infinite, false);
            }

            StartEvents();
            if (_service.Mode != RunMode.Demo)
            {
                _netTrace = new EasyFW.Platform.NetTrace(_service.Bandwidth);
                try { _netTrace.Start(); }
                catch (Exception ex) { Log.Write("Network trace failed to start: " + ex); _service.Bandwidth.Problem = ex.Message; }
            }
            // A new network usually means a new public address.
            System.Net.NetworkInformation.NetworkChange.NetworkAddressChanged += OnNetworkChanged;
            _tick.Tick += async (_, __) => await TickAsync();
            _tick.Start();

            // One-shot so the wizard runs inside the message loop.
            var starter = new Timer { Interval = 50 };
            starter.Tick += async (_, __) =>
            {
                starter.Stop();
                starter.Dispose();
                await StartupAsync(startInTray);
            };
            starter.Start();
        }

        private void StartEvents()
        {
            try { _env.Events?.Start(_queue.Enqueue); }
            catch (Exception ex)
            {
                Log.Write("Could not watch the Security log: " + ex.Message);
                ShowBalloon("Can't see blocked attempts", "EasyFW couldn't read the Windows Security log. Rules still apply.", ToolTipIcon.Warning, false);
            }
        }

        private async Task StartupAsync(bool startInTray)
        {
            var needsSetup = !_service.Config.SetupCompleted && _service.CanEnforce;
            if (!startInTray || needsSetup) _form.ShowConnections();
            // Started first so the notice can't delay blocking.
            var enforcing = EnforceAtStartAsync();
            ShowLicenseNotice();
            if (!startInTray && !_service.Config.HideFirewallNotice) _form.ShowFirewallNotice();
            await enforcing;
            if (needsSetup) await _form.RunSetupAsync(_env.PollActive);
            await AskAboutUpdatesOnceAsync();
        }

        private void ShowLicenseNotice()
        {
            var text = $"{AppInfo.NonCommercial}\n\nFor a commercial license, contact {AppInfo.Email}.";
            // Started at logon the window stays hidden, and a dialog owned by a hidden window can sit behind others.
            if (_form.Visible) MessageBox.Show(_form, text, "EasyFW", MessageBoxButtons.OK, MessageBoxIcon.Information);
            else MessageBox.Show(text, "EasyFW", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        /// <summary>Blocking starts with the app. An enable that was interrupted earlier just finishes here.</summary>
        private async Task EnforceAtStartAsync()
        {
            try
            {
                if (_service.IsEnabled) await _service.ReconcileAsync(true);
                else if (_service.CanEnforce) await _service.EnableAsync();
            }
            catch (Exception ex)
            {
                Log.Write("Startup enforcement failed: " + ex);
                ShowBalloon("Protection may be incomplete", ex.Message, ToolTipIcon.Error, false);
            }
        }

        /// <summary>Applies the rules to connections already open, which Windows Firewall leaves running.</summary>
        private async Task CloseDisallowedAsync(List<ActiveEndpoint> active)
        {
            if (_env.CloseConnection == null) return;
            var targets = _service.FindDisallowed(active);
            if (targets.Count == 0) return;
            var closed = await Task.Run(() => targets.Where(_env.CloseConnection).ToList());
            foreach (var failed in targets.Except(closed))
            {
                if (_closeFailures.Add($"{failed.LocalIp}:{failed.LocalPort}-{failed.RemoteIp}:{failed.RemotePort}"))
                    Log.Write($"Could not close {failed.ProcessName} {failed.LocalIp}:{failed.LocalPort} to {failed.RemoteIp}:{failed.RemotePort}.");
            }
            if (closed.Count == 0) return;
            active.RemoveAll(closed.Contains);
            NotifyNew(_service.ReportClosed(closed));
        }

        private DateTime _nextUpdateUtc = DateTime.UtcNow.AddMinutes(2);
        private bool _updating;
        private ToolStripMenuItem _lockdownItem;
        private readonly FloodDetector _floods = new FloodDetector();
        private EasyFW.Platform.NetTrace _netTrace;
        private readonly EasyFW.Platform.ProcessInfoCache _rateProcesses = new EasyFW.Platform.ProcessInfoCache();
        private readonly Random _demoRates = new Random(3);

        /// <summary>Counts this second's bytes into rates. In the demo, made-up traffic stands in for Windows' network events.</summary>
        private void SampleBandwidth()
        {
            var meter = _service.Bandwidth;
            if (_service.Mode == RunMode.Demo)
            {
                meter.Running = true;
                void Feed(int pid, string ip, int down, int up)
                {
                    meter.Add(pid, ip, false, (int)(down * (0.5 + _demoRates.NextDouble())));
                    meter.Add(pid, ip, true, (int)(up * (0.5 + _demoRates.NextDouble())));
                }
                Feed(101, "142.250.180.14", 900_000, 40_000);
                Feed(102, "13.107.4.50", 120_000, 30_000);
                Feed(103, "192.168.1.20", 2_400_000, 60_000);
                Feed(104, "93.184.216.34", 20_000, 300_000);
                Feed(105, "192.168.1.31", 5_000, 1_500_000);
            }
            meter.Sample(DateTime.UtcNow, pid =>
            {
                if (_service.Mode == RunMode.Demo)
                    return pid == 101 ? (@"C:\Program Files\Browserrowser.exe", "browser.exe") : pid == 102 ? (@"C:\Windows\System32\svchost.exe", "svchost.exe")
                        : pid == 103 ? (@"C:\Tools\Sync\sync.exe", "sync.exe") : pid == 104 ? (@"C:\Tools\Backupackup.exe", "backup.exe") : (@"C:\Program Files\TightVNC	vnserver.exe", "tvnserver.exe");
                _rateProcesses.Resolve(pid, out var name, out var path);
                return (path, name);
            });
        }
        private DateTime _nextBlocklistUtc = DateTime.UtcNow.AddMinutes(3);
        private bool _updatingBlocklists;
        /// <summary>App and address pairs already reported, so one bad contact gives one notice an hour.</summary>
        private readonly Dictionary<string, DateTime> _threatSeen = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);

        /// <summary>Tells the user when an app talks to, or is reached from, an address on a blocklist.</summary>
        private void ReportThreats(List<FirewallEvent> batch)
        {
            if (_service.Blocklist.Count == 0) return;
            var now = DateTime.UtcNow;
            foreach (var e in batch)
            {
                var list = _service.Blocklist.Match(e.RemoteIp);
                if (list == null) continue;
                var key = (e.AppPath ?? "") + "|" + e.RemoteIp;
                if (_threatSeen.TryGetValue(key, out var last) && now - last < TimeSpan.FromHours(1)) continue;
                if (_threatSeen.Count > 5000) _threatSeen.Clear();
                _threatSeen[key] = now;
                var app = string.IsNullOrEmpty(e.AppPath) ? "Something" : AppPaths.DisplayName(e.AppPath);
                var text = e.Direction == TrafficDirection.Inbound
                    ? $"{e.RemoteIp} ({IpInfo.CountryText(e.RemoteIp)}), on {list}, tried to reach {app}. It was blocked."
                    : $"{app} tried to reach {e.RemoteIp} ({IpInfo.CountryText(e.RemoteIp)}), which is on {list}. It was blocked.";
                Log.Write("Blocklist hit: " + text);
                ShowBalloon("Known bad address", text, ToolTipIcon.Warning, false);
            }
        }

        private async Task UpdateBlocklistsQuietlyAsync()
        {
            if (_updatingBlocklists) return;
            _updatingBlocklists = true;
            try
            {
                var problems = await _service.UpdateBlocklistsAsync();
                if (problems.Length > 0) _nextBlocklistUtc = DateTime.UtcNow.AddHours(3);
            }
            catch (Exception ex)
            {
                Log.Write("Blocklist update failed: " + ex.Message);
                _nextBlocklistUtc = DateTime.UtcNow.AddHours(3);
            }
            finally { _updatingBlocklists = false; }
        }

        private bool CanUpdate => _service.Mode == RunMode.Live && _service.CanEnforce;

        /// <summary>Asks the first time EasyFW starts after updates were added, and never again.</summary>
        private async Task AskAboutUpdatesOnceAsync()
        {
            try { Updater.CleanUp(System.IO.Path.GetDirectoryName(Program.ExePath)); }
            catch (Exception ex) { Log.Write("Couldn't clean up after an update: " + ex.Message); }
            if (!CanUpdate || _service.Config.Updates != UpdateChoice.NotAsked) return;
            var text = "Keep EasyFW up to date automatically?\n\n" +
                       $"Once a day EasyFW checks github.com/{Updater.Repo} for a new release. When there is one, it downloads it, checks it, " +
                       "installs it and restarts itself. Protection stays on the whole time.\n\n" +
                       "To do this, EasyFW lets its own program open HTTPS connections (port 443) to the internet. Nothing about this PC is sent.\n\n" +
                       "You can change this later in Options.";
            var answer = _form.Visible
                ? MessageBox.Show(_form, text, "Automatic updates", MessageBoxButtons.YesNo, MessageBoxIcon.Question)
                : MessageBox.Show(text, "Automatic updates", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            await _form.SetUpdatesAsync(answer == DialogResult.Yes ? UpdateChoice.Auto : UpdateChoice.Off);
            if (answer == DialogResult.Yes) _nextUpdateUtc = DateTime.UtcNow.AddSeconds(15);
        }

        /// <param name="manual">From the menu: says what it found and asks before installing. Otherwise it installs on its own.</param>
        private async Task CheckForUpdatesAsync(bool manual)
        {
            if (_updating) return;
            if (!CanUpdate)
            {
                if (manual) MessageBox.Show(_form, "Updates work only in a normal start of EasyFW, not in demo or monitor-only mode.", "Check for updates");
                return;
            }
            if (manual && _service.IsEnabled && !_service.Config.NeedsOwnConnection)
            {
                MessageBox.Show(_form, "EasyFW isn't allowed to connect to the internet, so it can't reach GitHub. Turn on Options > Automatic updates first.", "Check for updates");
                return;
            }
            _updating = true;
            try
            {
                var release = await Task.Run(Updater.LatestAsync);
                _service.Config.LastUpdateCheckUtc = DateTime.UtcNow;
                _service.MarkDirty();
                if (!Updater.IsNewer(release, AppInfo.Version))
                {
                    if (manual)
                        MessageBox.Show(_form, release == null
                            ? $"No release of EasyFW is published on GitHub yet. You have {AppInfo.Version}."
                            : $"You have the latest version, {AppInfo.Version}.", "Check for updates", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                if (manual && MessageBox.Show(_form, $"EasyFW {release.Version} is available. You have {AppInfo.Version}.\n\nInstall it now? EasyFW restarts, and protection stays on.",
                        "Check for updates", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
                if (!manual) ShowBalloon("Updating EasyFW", $"Installing version {release.Version}. EasyFW restarts in a moment, and protection stays on.", ToolTipIcon.Info, false);

                var work = System.IO.Path.Combine(ConfigStore.DefaultFolder, "update");
                var staging = await Updater.StageAsync(release, work);
                while (_service.IsBusy) await Task.Delay(500);
                var exe = Program.ExePath;
                var dir = System.IO.Path.GetDirectoryName(exe);
                await Task.Run(() => Updater.Install(staging, dir));
                Log.Write($"Updated from {AppInfo.Version} to {release.Version}. Restarting with protection {(_service.IsEnabled ? "on" : "off")}.");
                _service.FlushIfDirty();
                _exiting = true;
                Program.RestartAfterUpdate(System.IO.Path.Combine(dir, "EasyFW.exe"), !_form.Visible);
                ExitThread();
            }
            catch (Exception ex)
            {
                Log.Write("Update failed: " + ex);
                _nextUpdateUtc = DateTime.UtcNow.AddHours(3);
                if (manual) MessageBox.Show(_form, "The update didn't work: " + ex.Message + "\n\nEasyFW carries on with the version you have.", "Check for updates", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                else ShowBalloon("Update didn't work", "EasyFW carries on with the version you have and tries again later.", ToolTipIcon.Warning, false);
            }
            finally { _updating = false; }
        }

        private void OnNetworkChanged(object sender, EventArgs e) => _nextPublicIpUtc = DateTime.UtcNow.AddSeconds(5);

        private async Task TickAsync()
        {
            try
            {
                if (_service.Config.Updates == UpdateChoice.Auto && !_updating && DateTime.UtcNow >= _nextUpdateUtc)
                {
                    _nextUpdateUtc = DateTime.UtcNow.AddHours(24);
                    _ = CheckForUpdatesAsync(false);
                }
                if (!_service.Config.NoPublicIpLookup && DateTime.UtcNow >= _nextPublicIpUtc)
                {
                    _nextPublicIpUtc = DateTime.UtcNow.AddMinutes(15);
                    _ = PublicIp.RefreshAsync().ContinueWith(t =>
                    {
                        if (PublicIp.Failed) _nextPublicIpUtc = DateTime.UtcNow.AddMinutes(2);
                    }, TaskScheduler.Default);
                }

                var batch = new List<FirewallEvent>();
                while (batch.Count < 5000 && _queue.TryDequeue(out var e)) batch.Add(e);
                if (batch.Count > 0) NotifyNew(_service.ProcessEvents(batch));
                if (batch.Count > 0) ReportThreats(batch);
                if (_service.Config.Blocklists.Count > 0 && _service.CanChange && DateTime.UtcNow >= _nextBlocklistUtc)
                {
                    var last = _service.Config.BlocklistsUpdatedUtc ?? DateTime.MinValue;
                    _nextBlocklistUtc = (DateTime.UtcNow - last).TotalHours >= 23 ? DateTime.UtcNow.AddHours(24) : last.AddHours(24);
                    if ((DateTime.UtcNow - last).TotalHours >= 23) _ = UpdateBlocklistsQuietlyAsync();
                }
                if (!_service.Config.NoFloodAlerts)
                {
                    foreach (var alert in _floods.Add(batch, DateTime.UtcNow, IpInfo.CountryText))
                    {
                        Log.Write($"Flood alert: {alert.Title}. {alert.Text}");
                        ShowBalloon(alert.Title, alert.Text, ToolTipIcon.Warning, false);
                    }
                }

                if (!_polling)
                {
                    _polling = true;
                    try
                    {
                        var active = await Task.Run(_env.PollActive);
                        _service.LastEndpoints = active.ToList();
                        await CloseDisallowedAsync(active);
                        _service.Connections.ApplyActive(active, DateTime.UtcNow);
                    }
                    finally { _polling = false; }
                }

                _service.FlushIfDirty();
                SampleBandwidth();
                _form.RefreshLive();
                await _service.ApplyPatternsAsync();
                await _service.ApplySchedulesAsync();
                await _service.ApplyLanChangeAsync();
                var ended = await _service.ExpireRulesAsync();
                if (ended.Count > 0)
                    ShowBalloon("Temporary rule ended", ended.Count == 1
                        ? $"The rule for {ended[0].DisplayName} has ended. It's blocked again and will ask next time."
                        : $"{ended.Count} temporary rules have ended. Those apps are blocked again and will ask next time.", ToolTipIcon.Info, true);
                if (_service.Traffic.SampleIfDue(DateTime.UtcNow, _service.Connections)) _form.RefreshGraph();

                if (DateTime.UtcNow >= _nextReconcileUtc)
                {
                    _nextReconcileUtc = DateTime.UtcNow.AddMinutes(1);
                    var disabled = await _service.ReconcileAsync(false);
                    if (disabled > 0)
                        ShowBalloon("Firewall rule neutralized", $"{disabled} allow rule(s) added outside EasyFW were switched off. Those apps will now ask for approval.", ToolTipIcon.Info, true);
                }
            }
            catch (Exception ex) { Log.Write("Tick failed: " + ex); }
        }

        private void NotifyNew(List<PendingRequest> added)
        {
            if (added.Count == 0 || !_service.Config.NotifyNewApps) return;
            var text = added.Count == 1
                ? $"{added[0].DisplayName} wants network access. Click to review."
                : $"{added.Count} apps want network access. Click to review.";
            ShowBalloon("Connection blocked", text, ToolTipIcon.Info, true);
        }

        private void ShowBalloon(string title, string text, ToolTipIcon icon, bool opensRequests)
        {
            _balloonOpensRequests = opensRequests;
            _tray.ShowBalloonTip(5000, title, text, icon);
        }

        private void OnServiceChanged()
        {
            var pending = _service.PendingCount;
            var state = !_service.IsEnabled ? IconFactory.TrayState.Off
                : pending > 0 ? IconFactory.TrayState.Pending
                : IconFactory.TrayState.On;
            if (_shownState != state)
            {
                _tray.Icon = IconFactory.Tray(state);
                _shownState = state;
            }

            var status = _service.Mode == RunMode.MonitorOnly ? "Monitor-only"
                : _service.IsBusy ? _service.ActivityTitle
                : _service.IsEnabled ? "Enabled" : "Disabled";
            var pendingText = pending == 1 ? "1 pending request" : $"{pending} pending requests";
            _tray.Text = Clip($"EasyFW: {status}, {pendingText}");
            _statusItem.Text = "Firewall: " + status;
            _pendingItem.Text = pendingText;
            _toggleItem.Text = _service.CanEnforce
                ? (_service.IsEnabled ? "Turn firewall off" : "Turn firewall on")
                : "Turn firewall on (not in monitor-only)";
            _toggleItem.Enabled = _service.CanChange && !_toggling;
            if (_lockdownItem != null)
            {
                _lockdownItem.Checked = _service.Config.Lockdown;
                _lockdownItem.Text = _service.Config.Lockdown ? "End lockdown" : "Lockdown (block all but chosen apps)...";
                _lockdownItem.Enabled = _service.CanChange && _service.IsEnabled;
            }
            _form.RefreshStatus();
        }

        private static string Clip(string s) => s.Length > 63 ? s.Substring(0, 63) : s;

        public async Task ToggleAsync()
        {
            if (_toggling || !_service.CanChange) return;
            if (_service.IsEnabled && !Guard.Unlock(_form.Visible ? _form : null, "Turning protection off")) return;
            // First-time toggles go through setup so the default-block prompt is always seen.
            if (!_service.Config.SetupCompleted && !_service.IsEnabled)
            {
                _form.ShowConnections();
                await _form.RunSetupAsync(_env.PollActive);
                return;
            }
            _toggling = true;
            _toggleItem.Enabled = false;
            _form.SetBusy(true);
            try
            {
                if (_service.IsEnabled)
                {
                    await _service.DisableAsync();
                    ShowBalloon("EasyFW is off", "Windows Firewall is back to its previous settings.", ToolTipIcon.Warning, false);
                }
                else
                {
                    await _service.EnableAsync();
                    ShowBalloon("EasyFW is on", "Apps without an Accept Always rule are blocked. " + AppInfo.NonCommercial + ".", ToolTipIcon.Info, false);
                }
            }
            catch (Exception ex)
            {
                Log.Write("Toggle failed: " + ex);
                MessageBox.Show(ex.Message, "EasyFW", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                _toggling = false;
                _form.SetBusy(false);
                OnServiceChanged();
            }
        }

        private async void ExitApp()
        {
            if (_exiting) return;
            if (_service.IsEnabled && !Guard.Unlock(_form.Visible ? _form : null, "Exiting EasyFW")) return;
            if (_service.IsBusy)
            {
                _form.ShowConnections();
                MessageBox.Show(_form, "EasyFW is still changing Windows Firewall. Exiting now would leave it half done, so please wait until it finishes.",
                    "Exit EasyFW", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            if (_service.IsEnabled && _service.CanEnforce)
            {
                _form.ShowConnections();
                using var ask = new ExitChoiceForm();
                ask.ShowDialog(_form);
                if (ask.Choice == ExitChoice.Cancel) return;
                if (ask.Choice == ExitChoice.KeepOn)
                {
                    // Protection stays recorded as on, so the next start checks the rules and carries on.
                    Log.Write("Exited with protection left on.");
                    ExitThread();
                    return;
                }
            }
            if (_service.NeedsRestoreOnExit)
            {
                // The window stays up with progress until Windows Firewall is back, then the app closes.
                _exiting = true;
                _form.ShowConnections();
                try { await _service.DisableAsync(); }
                catch (Exception ex)
                {
                    Log.Write("Restore on exit failed: " + ex);
                    var answer = MessageBox.Show(_form,
                        $"EasyFW couldn't put Windows Firewall back: {ex.Message}\n\nIf you exit now, traffic may stay blocked. Run EasyFW.exe --restore to try again.\n\nExit anyway?",
                        "Exit EasyFW", MessageBoxButtons.YesNo, MessageBoxIcon.Error, MessageBoxDefaultButton.Button2);
                    if (answer != DialogResult.Yes)
                    {
                        _exiting = false;
                        return;
                    }
                }
            }
            ExitThread();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                System.Net.NetworkInformation.NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
                _netTrace?.Dispose();
                _tick.Stop();
                _tick.Dispose();
                _showWait?.Unregister(null);
                _showSignal?.Dispose();
                try { _env.Events?.Stop(); }
                catch (Exception ex) { Log.Write("Stop events failed: " + ex.Message); }
                _service.Changed -= OnServiceChanged;
                try { if (_service.Mode == RunMode.Live) _service.SaveConfig(); }
                catch (Exception ex) { Log.Write("Final save failed: " + ex.Message); }
                _tray.Visible = false;
                _tray.Dispose();
                _form.AllowClose = true;
                _form.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
