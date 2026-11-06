using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using EasyFW.Core;

namespace EasyFW.UI
{
    /// <summary>First-run prompt: explains default-block, which is already in force, and lets the user approve apps.</summary>
    public sealed class SetupWizardForm : Form
    {
        private readonly FirewallService _service;
        private readonly Func<List<ActiveEndpoint>> _poll;
        private readonly Panel _host = new Panel { Dock = DockStyle.Fill, Padding = new Padding(20, 14, 20, 8) };
        private readonly List<Control> _pages = new List<Control>();
        private readonly Button _back = new Button { Text = "Back", AutoSize = true, Margin = new Padding(6, 0, 0, 0) };
        private readonly Button _next = new Button { Text = "Next", AutoSize = true, Margin = new Padding(6, 0, 0, 0) };
        private readonly Button _later = new Button { Text = "Leave off for now", AutoSize = true, Margin = new Padding(6, 0, 0, 0), Visible = false };
        private readonly Label _step = new Label { AutoSize = true, ForeColor = Theme.Muted, Margin = new Padding(0, 6, 0, 0) };
        private readonly CheckBox _essentials = new CheckBox
        {
            Text = "Allow essential Windows networking (recommended)", AutoSize = true, Checked = true, Font = Theme.Heading
        };
        private readonly CheckedListBox _apps = new CheckedListBox { Dock = DockStyle.Fill, CheckOnClick = true, IntegralHeight = false };
        private readonly Label _summary = new Label { AutoSize = true, MaximumSize = new Size(620, 0) };
        private readonly string _policyWarning;
        private int _index;
        private bool _appsLoaded;

        public bool AllowEssentials => _essentials.Checked;
        public bool EnableNow { get; private set; }
        public List<string> PreApproved { get; private set; } = new List<string>();

        public SetupWizardForm(FirewallService service, Func<List<ActiveEndpoint>> poll)
        {
            _service = service;
            _poll = poll;
            _policyWarning = service.PolicyWarning();
            Text = "EasyFW setup";
            Font = Theme.Base;
            Icon = IconFactory.Tray(IconFactory.TrayState.On);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            ShowInTaskbar = true;
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96, 96);
            ClientSize = new Size(680, 500);

            _essentials.Checked = service.Config.AllowEssentials;
            _pages.Add(WelcomePage());
            _pages.Add(EssentialsPage());
            _pages.Add(FinishPage());
            foreach (var page in _pages) _host.Controls.Add(page);

            var buttons = new TableLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, ColumnCount = 4, Padding = new Padding(20, 8, 20, 14) };
            buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            for (var i = 0; i < 3; i++) buttons.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            buttons.Controls.Add(_step, 0, 0);
            buttons.Controls.Add(_back, 1, 0);
            buttons.Controls.Add(_later, 2, 0);
            buttons.Controls.Add(_next, 3, 0);

            _back.Click += (_, __) => Go(_index - 1);
            _next.Click += (_, __) => NextClicked();
            _later.Click += (_, __) => Finish(false);
            AcceptButton = _next;

            Controls.Add(_host);
            Controls.Add(buttons);
            Go(0);
        }

        private static Control Page(params Control[] rows)
        {
            var page = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = rows.Length };
            page.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            for (var i = 0; i < rows.Length; i++)
            {
                page.RowStyles.Add(rows[i].Dock == DockStyle.Fill ? new RowStyle(SizeType.Percent, 100) : new RowStyle(SizeType.AutoSize));
                page.Controls.Add(rows[i], 0, i);
            }
            return page;
        }

        private static Label Heading(string text) =>
            new Label { Text = text, AutoSize = true, Font = Theme.Title, Margin = new Padding(0, 0, 0, 8) };

        private static Label Para(string text, Color? color = null) => new Label
        {
            Text = text, AutoSize = true, UseMnemonic = false, MaximumSize = new Size(630, 0), Margin = new Padding(0, 0, 0, 10),
            ForeColor = color ?? SystemColors.ControlText
        };

        private Control WelcomePage()
        {
            var rows = new List<Control>
            {
                Heading("EasyFW blocks everything by default"),
                Para("Protection starts as soon as EasyFW opens. No app can use the network, in or out, until you approve it, and open connections from other apps are closed. That includes programs you use every day."),
                Para("What to expect:"),
                Para("•  Browsers, email, games and cloud sync stop connecting until you choose Accept Always.\n" +
                     "•  Windows Update and Defender updates are blocked too until you approve them. Please approve them soon: they keep this PC safe.\n" +
                     "•  VPN clients and remote access (Remote Desktop, TeamViewer, AnyDesk) stop working until you approve them.\n" +
                     "•  Allow rules already in Windows Firewall are switched off while EasyFW is on, and come back when you turn it off."),
                Para("When a blocked app tries to connect you get a small notification, and it waits in the Rules & Requests tab for your decision. Nothing pops up over your work."),
                Para("Turning EasyFW off or exiting it puts Windows Firewall back exactly as it was. Protection comes back on the next time EasyFW starts.")
            };
            if (_policyWarning != null) rows.Add(Para(_policyWarning, Theme.Off));
            return Page(rows.ToArray());
        }

        private Control EssentialsPage()
        {
            var note = Para("Lets Windows get an address and look up names (DHCP, DNS, IPv6 neighbor discovery, the connection check). Without this, approved apps can't connect either.", Theme.Muted);
            note.Margin = new Padding(18, 0, 0, 12);
            var apps = new Label { Text = "Approve apps now (optional)", AutoSize = true, Font = Theme.Heading, Margin = new Padding(0, 4, 0, 2) };
            var appsNote = Para("These are using the network right now. Ticked apps get Accept Always; anything else will ask later. Only tick what you recognize.", Theme.Muted);
            return Page(Heading("Choose what stays connected"), _essentials, note, apps, appsNote, _apps);
        }

        private Control FinishPage() => Page(Heading(_service.IsEnabled ? "Protection is on" : "Ready to turn on protection"), _summary);

        private void LoadApps()
        {
            if (_appsLoaded) return;
            _appsLoaded = true;
            try
            {
                var known = _service.Config.Rules.Select(r => r.AppPath);
                var paths = _poll()
                    .Where(e => !string.IsNullOrEmpty(e.AppPath) && e.AppPath != AppPaths.SystemApp && !AppPaths.IsSharedServiceHost(e.AppPath))
                    .Where(e => !IpText.IsLoopback(e.LocalIp) && !IpText.IsLoopback(e.RemoteIp))
                    .Select(e => e.AppPath)
                    .Except(known, StringComparer.OrdinalIgnoreCase)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(p => AppPaths.DisplayName(p), StringComparer.OrdinalIgnoreCase);
                foreach (var path in paths) _apps.Items.Add(path);
            }
            catch (Exception ex) { Log.Write("Setup app list failed: " + ex.Message); }
        }

        public void Go(int index)
        {
            _index = index;
            for (var i = 0; i < _pages.Count; i++) _pages[i].Visible = i == index;
            _pages[index].BringToFront();
            _step.Text = $"Step {index + 1} of {_pages.Count}";
            _back.Enabled = index > 0;
            var last = index == _pages.Count - 1;
            _later.Visible = last;
            _next.Text = !last ? "Next" : _service.IsEnabled ? "Keep protection on" : "Turn on protection";
            _later.Text = _service.IsEnabled ? "Turn protection off" : "Leave off for now";
            _next.Enabled = !(last && _policyWarning != null);
            if (index == 1) LoadApps();
            if (last) UpdateSummary();
        }

        private void UpdateSummary()
        {
            var count = _apps.CheckedItems.Count;
            _summary.Text =
                "While protection is on:\n\n" +
                "•  All incoming and outgoing traffic is blocked unless a rule allows it.\n" +
                $"•  Essential Windows networking is {(_essentials.Checked ? "allowed" : "NOT allowed, so you will probably lose internet access")}.\n" +
                $"•  {(count == 0 ? "No apps are" : count == 1 ? "1 app is" : count + " apps are")} approved in advance. Open connections from other apps are closed.\n" +
                "•  Windows logs firewall activity to the Security log so EasyFW can show blocked attempts.\n\n" +
                $"Choose {_later.Text} to put Windows Firewall back as it was. Protection comes back on the next time EasyFW starts." +
                (_policyWarning != null ? "\n\n" + _policyWarning : "");
        }

        private void NextClicked()
        {
            if (_index < _pages.Count - 1) Go(_index + 1);
            else Finish(true);
        }

        private void Finish(bool enable)
        {
            EnableNow = enable;
            PreApproved = _apps.CheckedItems.Cast<string>().ToList();
            DialogResult = DialogResult.OK;
        }
    }
}
