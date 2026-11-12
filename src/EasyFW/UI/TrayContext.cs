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

        public TrayContext(AppEnvironment env, bool startInTray, EventWaitHandle showSignal)
        {
            _env = env;
            _service = env.Service;
            _showSignal = showSignal;
            _form = new MainForm(env.Service, ToggleAsync, ExitApp);
            _form.SetSetupSource(env.PollActive);
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

        private async Task TickAsync()
        {
            try
            {
                var batch = new List<FirewallEvent>();
                while (batch.Count < 5000 && _queue.TryDequeue(out var e)) batch.Add(e);
                if (batch.Count > 0) NotifyNew(_service.ProcessEvents(batch));

                if (!_polling)
                {
                    _polling = true;
                    try
                    {
                        var active = await Task.Run(_env.PollActive);
                        await CloseDisallowedAsync(active);
                        _service.Connections.ApplyActive(active, DateTime.UtcNow);
                    }
                    finally { _polling = false; }
                }

                _service.FlushIfDirty();
                _form.RefreshLive();
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
            _form.RefreshStatus();
        }

        private static string Clip(string s) => s.Length > 63 ? s.Substring(0, 63) : s;

        public async Task ToggleAsync()
        {
            if (_toggling || !_service.CanChange) return;
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
