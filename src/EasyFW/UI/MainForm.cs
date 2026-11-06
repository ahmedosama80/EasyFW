using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using EasyFW.Core;
using EasyFW.Platform;

namespace EasyFW.UI
{
    public sealed class MainForm : Form
    {
        private readonly FirewallService _service;
        private readonly Func<Task> _toggle;
        private readonly TabControl _tabs = new TabControl { Dock = DockStyle.Fill };
        private readonly TabPage _connectionsPage = new TabPage("Connections");
        private readonly TabPage _requestsPage = new TabPage("Rules && Requests");
        private readonly ConnectionsTab _connections;
        private readonly RulesTab _rules;
        private readonly PictureBox _shield = new PictureBox { SizeMode = PictureBoxSizeMode.Zoom, Size = new Size(36, 36), Margin = new Padding(10, 8, 8, 8) };
        private readonly Label _statusTitle = new Label { AutoSize = true, Font = Theme.Title, Margin = new Padding(0, 6, 0, 0) };
        private readonly Label _licenseNote = new Label { AutoSize = true, Text = AppInfo.NonCommercial, Font = Theme.Heading, Margin = new Padding(12, 9, 0, 0), UseMnemonic = false };
        private readonly Label _statusDetail = new Label { AutoSize = true, ForeColor = Theme.Muted, Margin = new Padding(1, 0, 0, 6) };
        private readonly Button _toggleButton = new Button { AutoSize = true, Padding = new Padding(10, 3, 10, 3), Margin = new Padding(6, 10, 6, 6) };
        private readonly Button _optionsButton = new Button { AutoSize = true, Text = "Options", Padding = new Padding(6, 3, 6, 3), Margin = new Padding(0, 10, 10, 6) };
        private readonly Button _aboutButton = new Button { AutoSize = true, Text = "About", Padding = new Padding(6, 3, 6, 3), Margin = new Padding(0, 10, 10, 6) };
        private readonly ContextMenuStrip _optionsMenu = new ContextMenuStrip();
        private readonly ToolStripMenuItem _notifyItem = new ToolStripMenuItem("Notify about new apps") { CheckOnClick = true };
        private readonly ToolStripMenuItem _essentialsItem = new ToolStripMenuItem("Allow essential Windows networking") { CheckOnClick = true };
        private readonly ToolStripMenuItem _autoStartItem = new ToolStripMenuItem("Start at logon");
        private readonly Panel _banner = new Panel { Dock = DockStyle.Top, Height = 38, BackColor = Theme.BannerBack, Visible = false };
        private readonly Label _bannerText = new Label { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, ForeColor = Theme.BannerText, Padding = new Padding(10, 0, 0, 0) };
        private readonly Button _bannerButton = new Button { Dock = DockStyle.Right, AutoSize = true, Margin = new Padding(4) };
        private readonly StatusStrip _statusStrip = new StatusStrip { SizingGrip = true };
        private readonly ToolStripStatusLabel _statusLabel = new ToolStripStatusLabel();
        private Action _bannerAction;
        private Func<List<ActiveEndpoint>> _pollForSetup;
        private bool _inSetup;
        private bool _hintShown;
        private IconFactory.TrayState? _shownState;

        public bool AllowClose { get; set; }

        /// <summary>Raised the first time closing the window leaves the app running.</summary>
        public event Action HiddenToTray;

        public MainForm(FirewallService service, Func<Task> toggle, Action exit)
        {
            _service = service;
            _toggle = toggle;
            Text = service.Mode == RunMode.Demo ? "EasyFW (demo)" : "EasyFW";
            Font = Theme.Base;
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96, 96);
            Size = new Size(1120, 680);
            MinimumSize = new Size(800, 480);
            StartPosition = FormStartPosition.CenterScreen;
            ShowInTaskbar = true;

            _connections = new ConnectionsTab(service, DecideAsync) { Dock = DockStyle.Fill };
            _rules = new RulesTab(service, DecideAsync) { Dock = DockStyle.Fill };
            _connectionsPage.Controls.Add(_connections);
            _requestsPage.Controls.Add(_rules);
            _tabs.TabPages.Add(_connectionsPage);
            _tabs.TabPages.Add(_requestsPage);
            _tabs.SelectedIndexChanged += (_, __) => RefreshLive();

            var header = BuildHeader();
            _banner.Controls.Add(_bannerText);
            _banner.Controls.Add(_bannerButton);
            _bannerButton.Click += (_, __) => _bannerAction?.Invoke();
            _statusStrip.Items.Add(_statusLabel);

            Controls.Add(_tabs);
            Controls.Add(_banner);
            Controls.Add(header);
            Controls.Add(_statusStrip);

            FormClosing += OnFormClosing;
            BuildOptions(exit);
            RefreshStatus();
        }

        private Control BuildHeader()
        {
            var grid = new TableLayoutPanel
            {
                Dock = DockStyle.Top, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
                ColumnCount = 5, RowCount = 1, BackColor = Theme.Header
            };
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            var text = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false, Margin = Padding.Empty };
            var titleRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = Padding.Empty };
            titleRow.Controls.Add(_statusTitle);
            titleRow.Controls.Add(_licenseNote);
            text.Controls.Add(titleRow);
            text.Controls.Add(_statusDetail);
            grid.Controls.Add(_shield, 0, 0);
            grid.Controls.Add(text, 1, 0);
            grid.Controls.Add(_toggleButton, 2, 0);
            grid.Controls.Add(_optionsButton, 3, 0);
            grid.Controls.Add(_aboutButton, 4, 0);
            _aboutButton.Click += (_, __) =>
            {
                using var about = new AboutForm();
                about.ShowDialog(this);
            };
            _toggleButton.Click += async (_, __) => await _toggle();
            _optionsButton.Click += (_, __) => _optionsMenu.Show(_optionsButton, new Point(0, _optionsButton.Height));
            return grid;
        }

        private void BuildOptions(Action exit)
        {
            _notifyItem.Checked = _service.Config.NotifyNewApps;
            _notifyItem.CheckedChanged += (_, __) =>
            {
                _service.Config.NotifyNewApps = _notifyItem.Checked;
                TrySave();
            };
            _essentialsItem.Checked = _service.Config.AllowEssentials;
            _essentialsItem.Click += async (_, __) => await ChangeEssentialsAsync();
            _autoStartItem.Click += (_, __) => ToggleAutoStart();
            _optionsMenu.Items.Add(_notifyItem);
            _optionsMenu.Items.Add(_essentialsItem);
            _optionsMenu.Items.Add(_autoStartItem);
            _optionsMenu.Items.Add(new ToolStripSeparator());
            _optionsMenu.Items.Add("How EasyFW works...", null, (_, __) => ShowFirewallNotice());
            _optionsMenu.Items.Add("Run setup again...", null, async (_, __) =>
            {
                if (_pollForSetup != null) await RunSetupAsync(_pollForSetup);
            });
            _optionsMenu.Items.Add(new ToolStripSeparator());
            _optionsMenu.Items.Add("Exit EasyFW", null, (_, __) => exit());
            _optionsMenu.Opening += (_, __) =>
            {
                var live = _service.Mode == RunMode.Live;
                _essentialsItem.Enabled = _service.CanChange;
                _autoStartItem.Enabled = live;
                if (live) _autoStartItem.Checked = AutoStart.IsEnabled;
            };
        }

        private async Task ChangeEssentialsAsync()
        {
            _service.Config.AllowEssentials = _essentialsItem.Checked;
            try
            {
                TrySave();
                await _service.ReconcileAsync(true);
            }
            catch (Exception ex) { ShowError(ex); }
        }

        private void ToggleAutoStart()
        {
            try
            {
                var exe = Program.ExePath;
                var enable = !AutoStart.IsEnabled;
                if (enable && !AutoStart.IsInProtectedFolder(exe))
                {
                    var answer = MessageBox.Show(this,
                        "Start at logon runs this file with administrator rights and no UAC prompt. It's in a folder that ordinary programs can change, so one could replace it to gain those rights.\n\nCopy EasyFW to Program Files first. Continue anyway?",
                        "Start at logon", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
                    if (answer != DialogResult.Yes) return;
                }
                AutoStart.Set(enable, exe);
            }
            catch (Exception ex) { ShowError(ex); }
        }

        private void TrySave()
        {
            try { _service.SaveConfig(); }
            catch (Exception ex) { ShowError(ex); }
        }

        private void ShowError(Exception ex)
        {
            Log.Write("UI action failed: " + ex);
            MessageBox.Show(this, ex.Message, "EasyFW", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        private void OnFormClosing(object sender, FormClosingEventArgs e)
        {
            if (AllowClose || e.CloseReason != CloseReason.UserClosing) return;
            e.Cancel = true;
            Hide();
            if (!_hintShown)
            {
                _hintShown = true;
                HiddenToTray?.Invoke();
            }
        }

        public void ShowConnections()
        {
            _tabs.SelectedTab = _connectionsPage;
            BringUp();
        }

        public void ShowRequests()
        {
            _tabs.SelectedTab = _requestsPage;
            BringUp();
        }

        private void BringUp()
        {
            Show();
            if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
            Activate();
            RefreshLive();
        }

        public void SetBusy(bool busy)
        {
            _toggleButton.Enabled = !busy && _service.CanChange;
            if (busy) _toggleButton.Text = "Working...";
            else RefreshStatus();
        }

        /// <summary>Refreshes everything derived from protection state and pending requests.</summary>
        public void RefreshStatus()
        {
            var on = _service.IsEnabled;
            var pending = _service.PendingCount;
            var state = !on ? IconFactory.TrayState.Off : pending > 0 ? IconFactory.TrayState.Pending : IconFactory.TrayState.On;
            if (_shownState != state)
            {
                _shownState = state;
                _shield.Image?.Dispose();
                _shield.Image = IconFactory.Shield(72, state);
                Icon = IconFactory.Tray(state);
            }

            var busy = _service.IsBusy;
            _statusTitle.Text = busy ? _service.ActivityTitle + "..." : on ? "Protection is on" : "Protection is off";
            _statusTitle.ForeColor = on && !busy ? Theme.Good : Theme.Off;
            _licenseNote.Visible = on && !busy;
            _statusDetail.Text = busy ? ActivityDetail() : on
                ? "Apps need an Accept Always rule to use the network."
                : _service.Config.SetupCompleted
                    ? "Windows Firewall is using its previous settings. EasyFW is not filtering anything."
                    : "EasyFW is not filtering anything yet.";
            _toggleButton.Text = busy ? "Working..." : on ? "Turn off" : "Turn on";
            _toggleButton.Enabled = _service.CanChange;
            _requestsPage.Text = pending > 0 ? $"Rules && Requests ({pending})" : "Rules && Requests";
            UpdateBanner();
            _rules.RefreshData();
            _connections.SetCanDecide(_service.CanChange);
        }

        private string ActivityDetail() => _service.Activity + ". This can take a couple of minutes.";

        private void UpdateBanner()
        {
            if (_service.Mode == RunMode.MonitorOnly)
                SetBanner("Monitor-only: EasyFW is only watching connections. It isn't blocking traffic or showing blocked attempts.", "Start protection", Program.RestartWithProtection);
            else if (_service.Mode == RunMode.Demo)
                SetBanner("Demo mode: traffic is simulated and Windows Firewall isn't touched.", null, null);
            else if (!_service.Config.SetupCompleted && !_inSetup)
                SetBanner(_service.IsEnabled ? "Everything is blocked until you approve it. Finish setup to approve your apps." : "Setup isn't finished, so your traffic isn't being filtered.", "Run setup", async () =>
                {
                    if (_pollForSetup != null) await RunSetupAsync(_pollForSetup);
                });
            else
                _banner.Visible = false;
        }

        private void SetBanner(string text, string button, Action action)
        {
            _bannerText.Text = text;
            _bannerButton.Visible = button != null;
            _bannerButton.Text = button ?? "";
            _bannerAction = action;
            _banner.Visible = true;
        }

        /// <summary>Refreshes the visible tab. Skipped while hidden so a tray-only app stays cheap.</summary>
        public void RefreshLive()
        {
            if (!Visible) return;
            if (_service.IsBusy) _statusDetail.Text = ActivityDetail();
            if (_tabs.SelectedTab == _connectionsPage)
            {
                _connections.RefreshData();
                _statusLabel.Text = _connections.Summary;
            }
            else
            {
                _statusLabel.Text = $"{_service.Config.Rules.Count} rule(s), {_service.PendingCount} pending";
            }
        }

        public void ShowFirewallNotice()
        {
            using var notice = new FirewallNoticeForm(_service.Mode, _service.Config.HideFirewallNotice);
            notice.ShowDialog(this);
            _service.Config.HideFirewallNotice = notice.HideAtStart;
            TrySave();
        }

        public void RefreshGraph()
        {
            if (Visible) _connections.RefreshGraph();
        }

        public void SetSetupSource(Func<List<ActiveEndpoint>> poll) => _pollForSetup = poll;

        public async Task RunSetupAsync(Func<List<ActiveEndpoint>> poll)
        {
            if (_inSetup || !_service.CanChange) return;
            _pollForSetup = poll;
            _inSetup = true;
            UpdateBanner();
            try
            {
                using var wizard = new SetupWizardForm(_service, poll);
                if (wizard.ShowDialog(this) != DialogResult.OK) return;
                var essentialsChanged = _service.Config.AllowEssentials != wizard.AllowEssentials;
                _service.Config.AllowEssentials = wizard.AllowEssentials;
                _essentialsItem.Checked = wizard.AllowEssentials;
                if (essentialsChanged) await _service.ReconcileAsync(true);
                foreach (var path in wizard.PreApproved)
                {
                    // Deciding again would drop ports the user has already limited this app to.
                    var existing = _service.FindRule(path);
                    if (existing == null || !existing.Enabled || existing.Action != RuleAction.Allow)
                        await _service.DecideAsync(path, RuleAction.Allow);
                }
                if (wizard.EnableNow && !_service.IsEnabled) await _service.EnableAsync();
                else if (!wizard.EnableNow && _service.IsEnabled) await _service.DisableAsync();
                _service.Config.SetupCompleted = true;
                _service.SaveConfig();
            }
            catch (Exception ex) { ShowError(ex); }
            finally
            {
                _inSetup = false;
                RefreshStatus();
            }
        }

        private async Task DecideAsync(string path, RuleAction action, string ports)
        {
            if (string.IsNullOrEmpty(path))
            {
                MessageBox.Show(this, "Windows didn't report which program this is, so a rule can't be made for it.", "EasyFW");
                return;
            }
            if (ports != null && AppPaths.Same(path, AppPaths.PingApp))
            {
                MessageBox.Show(this, "Pings don't use ports. Use Accept Always or Block Always for this one.", "Ping");
                return;
            }
            // Blocking only certain ports leaves the rest open, so it needs the same warnings as accepting.
            var opensNetwork = action == RuleAction.Allow || ports != null;
            if (opensNetwork && AppPaths.IsSharedServiceHost(path))
            {
                var answer = MessageBox.Show(this,
                    "svchost.exe hosts many Windows services. This lets all of them use the network, including Windows Update and Defender updates, but also anything else running inside it.\n\nContinue?",
                    "Shared service host", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
                if (answer != DialogResult.Yes) return;
            }
            if (action == RuleAction.Allow && AppPaths.Same(path, AppPaths.PingApp))
            {
                var answer = MessageBox.Show(this,
                    "Windows doesn't say which program sent a ping, so this can't be limited to one app. Accepting lets every program on this PC ping, and lets other devices ping this PC.\n\nAccept Always?",
                    "Ping", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
                if (answer != DialogResult.Yes) return;
            }
            var opensAllPorts = action == RuleAction.Allow ? ports == null : ports != null;
            if (opensAllPorts && AppPaths.Same(path, AppPaths.SystemApp))
            {
                var answer = MessageBox.Show(this,
                    "Windows System handles file sharing and other network services. This opens nearly all of it, in and out.\n\nContinue?",
                    "Windows System", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
                if (answer != DialogResult.Yes) return;
            }
            try { await _service.DecideAsync(path, action, ports); }
            catch (Exception ex) { ShowError(ex); }
        }
    }
}
