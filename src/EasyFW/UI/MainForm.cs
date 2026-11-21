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
    /// <summary>Makes a rule for an app, after any warnings. Null ports means all ports.</summary>
    public delegate Task DecideHandler(string path, RuleAction action, string ports, RuleDuration duration);

    public sealed class MainForm : Form
    {
        private readonly FirewallService _service;
        private readonly Func<Task> _toggle;
        private readonly TabControl _tabs = new TabControl { Dock = DockStyle.Fill };
        private readonly TabPage _connectionsPage = new TabPage("Connections");
        private readonly TabPage _requestsPage = new TabPage("Rules && Requests");
        private readonly TabPage _topPage = new TabPage("Top Connections");
        private readonly TabPage _mapPage = new TabPage("World Map");
        private readonly WorldMapTab _map;
        private readonly TabPage _portsPage = new TabPage("Ports && Shares");
        private readonly PortsTab _ports;
        private readonly TabPage _bandwidthPage = new TabPage("Bandwidth");
        private readonly BandwidthTab _bandwidth;
        private readonly ToolStripStatusLabel _rateLabel = new ToolStripStatusLabel { Spring = false, Alignment = ToolStripItemAlignment.Right };
        private readonly ConnectionsTab _connections;
        private readonly TopTab _top;
        private readonly RulesTab _rules;
        private readonly PictureBox _shield = new PictureBox { SizeMode = PictureBoxSizeMode.Zoom, Size = new Size(36, 36), Margin = new Padding(10, 8, 8, 8) };
        private readonly Label _statusTitle = new Label { AutoSize = true, Font = Theme.Title, Margin = new Padding(0, 6, 0, 0) };
        private readonly Label _licenseNote = new Label { AutoSize = true, Text = AppInfo.NonCommercial, Font = Theme.Heading, Margin = new Padding(12, 9, 0, 0), UseMnemonic = false };
        private readonly Label _publicIp = new Label
        {
            AutoSize = true, Font = Theme.Heading, ForeColor = Color.FromArgb(30, 64, 120), BackColor = Color.FromArgb(226, 236, 250),
            Padding = new Padding(6, 3, 6, 3), Margin = new Padding(10, 8, 0, 0), UseMnemonic = false, Cursor = Cursors.Hand
        };
        private readonly ToolTip _tips = new ToolTip();
        private readonly ToolStripMenuItem _updatesItem = new ToolStripMenuItem("Automatic updates from GitHub") { CheckOnClick = true };
        private readonly ToolStripMenuItem _publicIpItem = new ToolStripMenuItem("Show my public IP") { CheckOnClick = true };
        private readonly Label _statusDetail = new Label { AutoSize = true, ForeColor = Theme.Muted, Margin = new Padding(1, 0, 0, 6) };
        private readonly Button _toggleButton = new Button { AutoSize = true, Padding = new Padding(10, 3, 10, 3), Margin = new Padding(6, 10, 6, 6) };
        private readonly Button _lockdownButton = new Button { AutoSize = true, Text = "Lockdown", ForeColor = Theme.Off, Padding = new Padding(6, 3, 6, 3), Margin = new Padding(0, 10, 10, 6) };
        private readonly ToolStripMenuItem _floodItem = new ToolStripMenuItem("Alert on traffic floods") { CheckOnClick = true };
        private readonly Button _optionsButton = new Button { AutoSize = true, Text = "Options", Padding = new Padding(6, 3, 6, 3), Margin = new Padding(0, 10, 10, 6) };
        private readonly Button _aboutButton = new Button { AutoSize = true, Text = "About", Padding = new Padding(6, 3, 6, 3), Margin = new Padding(0, 10, 10, 6) };
        private readonly Button _exitButton = new Button { AutoSize = true, Text = "Exit", Padding = new Padding(6, 3, 6, 3), Margin = new Padding(0, 10, 10, 6) };
        private readonly Label _version = new Label { AutoSize = true, Text = "v" + AppInfo.Version, ForeColor = Theme.Muted, Margin = new Padding(8, 0, 0, 4) };
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

        /// <summary>Set by the tray app, which does the checking and installing.</summary>
        public Func<Task> CheckUpdatesRequested { get; set; }

        /// <summary>Raised the first time closing the window leaves the app running.</summary>
        public event Action HiddenToTray;

        public MainForm(FirewallService service, Func<Task> toggle, Action exit)
        {
            _service = service;
            _toggle = toggle;
            Guard.Service = service;
            Text = $"EasyFW {AppInfo.Version}" + (service.Mode == RunMode.Demo ? " (demo)" : "");
            Font = Theme.Base;
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96, 96);
            Size = new Size(1120, 680);
            MinimumSize = new Size(800, 480);
            StartPosition = FormStartPosition.CenterScreen;
            ShowInTaskbar = true;

            IpInfo.LoadCountries();
            _connections = new ConnectionsTab(service, DecideAsync) { Dock = DockStyle.Fill };
            _rules = new RulesTab(service, DecideAsync) { Dock = DockStyle.Fill };
            _top = new TopTab(service, DecideAsync) { Dock = DockStyle.Fill };
            _connectionsPage.Controls.Add(_connections);
            _requestsPage.Controls.Add(_rules);
            _topPage.Controls.Add(_top);
            _map = new WorldMapTab(service) { Dock = DockStyle.Fill };
            _mapPage.Controls.Add(_map);
            _ports = new PortsTab(service) { Dock = DockStyle.Fill };
            _portsPage.Controls.Add(_ports);
            _bandwidth = new BandwidthTab(service) { Dock = DockStyle.Fill };
            _bandwidthPage.Controls.Add(_bandwidth);
            _tabs.TabPages.Add(_connectionsPage);
            _tabs.TabPages.Add(_topPage);
            _tabs.TabPages.Add(_mapPage);
            _tabs.TabPages.Add(_bandwidthPage);
            _tabs.TabPages.Add(_portsPage);
            _tabs.TabPages.Add(_requestsPage);
            _tabs.SelectedIndexChanged += (_, __) => RefreshLive();

            var header = BuildHeader();
            _exitButton.Click += (_, __) => exit();
            _banner.Controls.Add(_bannerText);
            _banner.Controls.Add(_bannerButton);
            _bannerButton.Click += (_, __) => _bannerAction?.Invoke();
            _statusLabel.Spring = true;
            _statusLabel.TextAlign = ContentAlignment.MiddleLeft;
            _statusStrip.Items.Add(_statusLabel);
            _statusStrip.Items.Add(_rateLabel);

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
                ColumnCount = 7, RowCount = 1, BackColor = Theme.Header
            };
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            // The version sits under the shield, top left, so it shows inside the window and not only in the title bar.
            var badge = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false, Margin = Padding.Empty };
            badge.Controls.Add(_shield);
            badge.Controls.Add(_version);
            _shield.Margin = new Padding(10, 8, 8, 0);
            var text = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false, Margin = Padding.Empty };
            var titleRow = new FlowLayoutPanel { AutoSize = true, WrapContents = true, Margin = Padding.Empty };
            titleRow.Controls.Add(_statusTitle);
            titleRow.Controls.Add(_publicIp);
            titleRow.Controls.Add(_licenseNote);
            var ipMenu = new ContextMenuStrip();
            ipMenu.Items.Add("Copy public IP", null, (_, __) => { if (PublicIp.Address != null) UiHelpers.CopyRows(this, new[] { new[] { PublicIp.Address } }); });
            ipMenu.Items.Add("Check again", null, (_, __) => { _ = PublicIp.RefreshAsync(); });
            ipMenu.Items.Add("Set my location...", null, (_, __) => { ShowMap(); _map.ChooseLocation(); });
            _publicIp.ContextMenuStrip = ipMenu;
            _publicIp.Click += (_, __) => ipMenu.Show(_publicIp, new Point(0, _publicIp.Height));
            Action onIp = () => { if (IsHandleCreated && !IsDisposed) BeginInvoke((Action)ShowPublicIp); };
            PublicIp.Changed += onIp;
            Disposed += (_, __) => PublicIp.Changed -= onIp;
            ShowPublicIp();
            text.Controls.Add(titleRow);
            text.Controls.Add(_statusDetail);
            grid.Controls.Add(badge, 0, 0);
            grid.Controls.Add(text, 1, 0);
            grid.Controls.Add(_toggleButton, 2, 0);
            grid.Controls.Add(_lockdownButton, 3, 0);
            grid.Controls.Add(_optionsButton, 4, 0);
            grid.Controls.Add(_aboutButton, 5, 0);
            grid.Controls.Add(_exitButton, 6, 0);
            _lockdownButton.Click += async (_, __) => await LockdownForm.ToggleAsync(this, _service);
            _tips.SetToolTip(_lockdownButton, "Blocks every app at once, except the ones you choose. Your rules stay as they are.");
            _aboutButton.Click += (_, __) =>
            {
                using var about = new AboutForm();
                about.ShowDialog(this);
            };
            // The title row wraps instead of running under the buttons when a long country name or a narrow window leaves no room.
            grid.Layout += (_, __) =>
            {
                var widths = grid.GetColumnWidths();
                if (widths.Length < 2) return;
                var max = new Size(Math.Max(240, widths[1] - 4), 0);
                if (titleRow.MaximumSize != max) titleRow.MaximumSize = max;
            };
            _toggleButton.Click += async (_, __) => await _toggle();
            _optionsButton.Click += (_, __) =>
            {
                if (Guard.Unlock(this, "Changing options")) _optionsMenu.Show(_optionsButton, new Point(0, _optionsButton.Height));
            };
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
            _publicIpItem.Checked = !_service.Config.NoPublicIpLookup;
            _publicIpItem.ToolTipText = "Asks api.ipify.org (or a backup service) for this PC's internet address. Only the request is sent.";
            _publicIpItem.Click += async (_, __) => await ChangePublicIpAsync();
            _optionsMenu.Items.Add(_publicIpItem);
            _updatesItem.Checked = _service.Config.Updates == UpdateChoice.Auto;
            _updatesItem.ToolTipText = $"Checks github.com/{Updater.Repo} once a day and installs new releases. EasyFW may then make HTTPS connections.";
            _updatesItem.Click += async (_, __) => await SetUpdatesAsync(_updatesItem.Checked ? UpdateChoice.Auto : UpdateChoice.Off);
            _optionsMenu.Items.Add(_updatesItem);
            _optionsMenu.Items.Add("Check for updates now...", null, async (_, __) => { if (CheckUpdatesRequested != null) await CheckUpdatesRequested(); });
            _optionsMenu.Items.Add(new ToolStripSeparator());
            _optionsMenu.Items.Add("Blocked countries...", null, async (_, __) => await CountryBlockForm.EditAsync(this, _service));
            _optionsMenu.Items.Add("Blocklists of bad addresses...", null, async (_, __) => await BlocklistForm.EditAsync(this, _service));
            _optionsMenu.Items.Add("Lockdown apps...", null, async (_, __) => await LockdownForm.ChooseAppsAsync(this, _service));
            _optionsMenu.Items.Add("Password protection...", null, (_, __) =>
            {
                using var form = new PasswordSetForm(_service);
                form.ShowDialog(this);
            });
            _floodItem.Checked = !_service.Config.NoFloodAlerts;
            _floodItem.ToolTipText = "Warns when traffic suddenly jumps, an app opens a flood of connections, or someone scans this PC's ports.";
            _floodItem.CheckedChanged += (_, __) =>
            {
                _service.Config.NoFloodAlerts = !_floodItem.Checked;
                TrySave();
            };
            _optionsMenu.Items.Add(_floodItem);
            _optionsMenu.Items.Add("Reset column layout", null, (_, __) =>
            {
                UiHelpers.ResetColumns();
                TrySave();
            });
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

        /// <summary>Updates need EasyFW's own allow rule, so the rules are applied again either way.</summary>
        public async Task SetUpdatesAsync(UpdateChoice choice)
        {
            _service.Config.Updates = choice;
            _updatesItem.Checked = choice == UpdateChoice.Auto;
            try
            {
                TrySave();
                if (_service.CanChange && _service.IsEnabled) await _service.ReconcileAsync(true);
            }
            catch (Exception ex) { ShowError(ex); }
        }

        /// <summary>The lookup needs EasyFW's own allow rule, so the rules are applied again either way.</summary>
        private async Task ChangePublicIpAsync()
        {
            _service.Config.NoPublicIpLookup = !_publicIpItem.Checked;
            if (_service.Config.NoPublicIpLookup) PublicIp.Set(null);
            ShowPublicIp();
            try
            {
                TrySave();
                if (_service.CanChange) await _service.ReconcileAsync(true);
                if (!_service.Config.NoPublicIpLookup) _ = PublicIp.RefreshAsync();
            }
            catch (Exception ex) { ShowError(ex); }
        }

        private void ShowPublicIp()
        {
            var off = _service.Config.NoPublicIpLookup;
            _publicIp.Visible = !off;
            if (off) return;
            var ip = PublicIp.Address;
            var country = PublicIp.Country;
            _publicIp.Text = ip == null
                ? PublicIp.Failed ? "Public IP: not found" : "Public IP: checking..."
                : "IP " + ip + (country != null ? " · " + IpInfo.CountryName(country) : "");
            _tips.SetToolTip(_publicIp, ip == null
                ? "EasyFW asks a public service for this PC's internet address. Click to check again."
                : $"This PC's address on the internet, checked {PublicIp.CheckedUtc?.ToLocalTime():HH:mm}. Click to copy it or set your location.");
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

        public void ShowTop()
        {
            _tabs.SelectedTab = _topPage;
            BringUp();
        }

        public void ShowMap()
        {
            _tabs.SelectedTab = _mapPage;
            BringUp();
        }

        public void ShowBandwidth()
        {
            _tabs.SelectedTab = _bandwidthPage;
            BringUp();
        }

        public void ShowPorts()
        {
            _tabs.SelectedTab = _portsPage;
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
            var lockdown = on && _service.Config.Lockdown;
            _statusTitle.Text = busy ? _service.ActivityTitle + "..." : lockdown ? "LOCKDOWN" : on ? "Protection is on" : "Protection is off";
            _statusTitle.ForeColor = on && !busy && !lockdown ? Theme.Good : Theme.Off;
            _licenseNote.Visible = on && !busy;
            var kept = _service.Config.Rules.Count(r => r.Opens && r.KeepInLockdown && r.Enabled);
            var countries = _service.Config.BlockedCountries.Count;
            _statusDetail.Text = busy ? ActivityDetail() : lockdown
                ? (kept == 0 ? "Every app is blocked. " : $"Only {kept} chosen app(s) may connect. ") + "Click End lockdown to go back to your rules."
                : on
                ? "Apps need an Accept Always rule to use the network." + (countries > 0 ? $" {countries} countr{(countries == 1 ? "y" : "ies")} blocked." : "")
                : _service.Config.SetupCompleted
                    ? "Windows Firewall is using its previous settings. EasyFW is not filtering anything."
                    : "EasyFW is not filtering anything yet.";
            _toggleButton.Text = busy ? "Working..." : on ? "Turn off" : "Turn on";
            _toggleButton.Enabled = _service.CanChange;
            _lockdownButton.Text = lockdown ? "End lockdown" : "Lockdown";
            _lockdownButton.Enabled = _service.CanChange && on;
            _requestsPage.Text = pending > 0 ? $"Rules && Requests ({pending})" : "Rules && Requests";
            UpdateBanner();
            // Blocked attempts change the pending list every second. Rebuilding lists nobody is looking at made the window lag.
            if (Visible && _tabs.SelectedTab == _requestsPage) _rules.RefreshData();
            else _rules.MarkDirty();
            _connections.SetCanDecide(_service.CanChange);
            _top.SetCanDecide(_service.CanChange);
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
            var rate = _service.Bandwidth.Now;
            _rateLabel.Text = _service.Bandwidth.Running
                ? $"↓ {BandwidthMeter.Text(rate.Down)}  ↑ {BandwidthMeter.Text(rate.Up)}   ·   Internet ↓ {BandwidthMeter.Text(rate.InternetDown)} ↑ {BandwidthMeter.Text(rate.InternetUp)}   ·   LAN ↓ {BandwidthMeter.Text(rate.LanDown)} ↑ {BandwidthMeter.Text(rate.LanUp)}"
                : "";
            if (_tabs.SelectedTab == _connectionsPage)
            {
                _connections.RefreshData();
                _statusLabel.Text = _connections.Summary;
            }
            else if (_tabs.SelectedTab == _topPage)
            {
                _top.RefreshData();
                _statusLabel.Text = _top.Summary;
            }
            else if (_tabs.SelectedTab == _bandwidthPage)
            {
                _bandwidth.RefreshData();
                _statusLabel.Text = _bandwidth.Summary;
            }
            else if (_tabs.SelectedTab == _portsPage)
            {
                _ports.RefreshData();
                _statusLabel.Text = _ports.Summary;
            }
            else if (_tabs.SelectedTab == _mapPage)
            {
                _map.RefreshData();
                _statusLabel.Text = _map.Summary;
            }
            else
            {
                _rules.RefreshNames();
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

        private async Task DecideAsync(string path, RuleAction action, string ports, RuleDuration duration)
        {
            if (!Guard.Unlock(this, "Changing rules")) return;
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
            try { await _service.DecideAsync(path, action, ports, duration); }
            catch (Exception ex) { ShowError(ex); }
        }
    }
}
