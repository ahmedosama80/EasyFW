using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;
using EasyFW.Core;
using EasyFW.Platform;

namespace EasyFW.UI
{
    /// <summary>Every connection one app made or tried in the last hour, newest first. Opened from a right-click on any list.</summary>
    public sealed class AppLogForm : Form
    {
        private static readonly (string Title, int Width, HorizontalAlignment Align)[] Columns =
        {
            ("Time", 76, HorizontalAlignment.Left),
            ("Status", 72, HorizontalAlignment.Left),
            ("Dir", 44, HorizontalAlignment.Left),
            ("Proto", 56, HorizontalAlignment.Left),
            ("Local IP", 118, HorizontalAlignment.Left),
            ("Local Port", 70, HorizontalAlignment.Right),
            ("Remote IP", 130, HorizontalAlignment.Left),
            ("Remote Host", 200, HorizontalAlignment.Left),
            ("Country", 130, HorizontalAlignment.Left),
            ("Remote Port", 78, HorizontalAlignment.Right),
            ("Internet", 62, HorizontalAlignment.Left)
        };

        private readonly FirewallService _service;
        private readonly string _target;
        private readonly ListView _list = new ListView
        {
            Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, VirtualMode = true, HideSelection = false, BorderStyle = BorderStyle.None
        };
        private readonly ComboBox _status = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 86, Margin = new Padding(4, 5, 8, 4) };
        private readonly TextBox _search = new TextBox { Width = 150, Margin = new Padding(4, 5, 10, 4) };
        private readonly CheckBox _pause = UiHelpers.PauseButton();
        private readonly Label _summary = new Label { AutoSize = true, Margin = new Padding(8, 8, 4, 4), ForeColor = Theme.Muted };
        private readonly Timer _timer = new Timer { Interval = 2000 };
        private List<FirewallEvent> _rows = new List<FirewallEvent>();
        private int _infoVersion = -1;

        public AppLogForm(FirewallService service, string ruleTarget)
        {
            _service = service;
            _target = ruleTarget;
            Text = $"Log for {AppPaths.DisplayName(ruleTarget)}: last hour";
            Font = Theme.Base;
            StartPosition = FormStartPosition.CenterParent;
            ShowInTaskbar = false;
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96, 96);
            ClientSize = new Size(1080, 560);
            MinimizeBox = false;
            Icon = IconFactory.Tray(IconFactory.TrayState.On);

            foreach (var c in Columns) _list.Columns.Add(c.Title, c.Width, c.Align);
            UiHelpers.EnableDoubleBuffer(_list);
            _list.RetrieveVirtualItem += OnRetrieveItem;
            Flags.ShowInColumn(_list, 8, 6, i => i < _rows.Count && _rows[i].Verdict == Verdict.Blocked ? Theme.BlockedRow : (Color?)null);
            UiHelpers.ShowFullTextOnHover(_list);
            UiHelpers.RememberColumns(_list, "applog", _service);
            var menu = new ContextMenuStrip();
            var copy = new ToolStripMenuItem("Copy row");
            copy.Click += (_, __) => UiHelpers.CopyRows(this, _list.SelectedIndices.Cast<int>().Where(i => i < _rows.Count).Select(i => Cells(_rows[i])));
            menu.Items.Add(copy);
            menu.Items.Add(UiHelpers.CopyPathItem(() => this, () => new[] { _target }));
            menu.Opening += (_, e) =>
            {
                if (_list.SelectedIndices.Count == 0) e.Cancel = true;
                copy.Text = UiHelpers.CopyLabel(_list.SelectedIndices.Count);
            };
            _list.ContextMenuStrip = menu;

            _status.Items.AddRange(new object[] { "All", "Accepted", "Blocked" });
            _status.SelectedIndex = 0;

            var path = new Label
            {
                Dock = DockStyle.Top, AutoSize = false, Height = 26, AutoEllipsis = true, Padding = new Padding(8, 6, 8, 0),
                Text = ruleTarget + "   ·   Signed: " + Signed(ruleTarget)
            };
            path.ContextMenuStrip = new ContextMenuStrip();
            path.ContextMenuStrip.Items.Add(UiHelpers.CopyPathItem(() => this, () => new[] { _target }));
            var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(4, 2, 4, 2), WrapContents = true };
            bar.Controls.Add(UiHelpers.BarLabel("Search"));
            bar.Controls.Add(_search);
            bar.Controls.Add(UiHelpers.BarLabel("Status"));
            bar.Controls.Add(_status);
            bar.Controls.Add(_pause);
            bar.Controls.Add(_summary);

            _search.TextChanged += (_, __) => RefreshData();
            _status.SelectedIndexChanged += (_, __) => RefreshData();
            _pause.CheckedChanged += (_, __) => RefreshData();
            _timer.Tick += (_, __) =>
            {
                if (!_pause.Checked) RefreshData();
                else if (IpInfo.Version != _infoVersion)
                {
                    _infoVersion = IpInfo.Version;
                    _list.Invalidate();
                }
            };
            Shown += (_, __) => _timer.Start();
            FormClosed += (_, __) => _timer.Dispose();

            Controls.Add(_list);
            Controls.Add(bar);
            Controls.Add(path);
            RefreshData();
        }

        private static string Signed(string target)
        {
            var text = AppSignature.Text(target);
            return text.Length == 0 ? "checking..." : text;
        }

        private void RefreshData()
        {
            _infoVersion = IpInfo.Version;
            var all = _service.History.ForApp(_target, DateTime.UtcNow);
            var status = _status.SelectedIndex == 1 ? Verdict.Accepted : _status.SelectedIndex == 2 ? Verdict.Blocked : (Verdict?)null;
            var text = _search.Text.Trim();
            var selected = new HashSet<FirewallEvent>(_list.SelectedIndices.Cast<int>().Where(i => i < _rows.Count).Select(i => _rows[i]));
            _rows = all.Where(e => (status == null || e.Verdict == status) && (text.Length == 0 || Cells(e).Any(c => c.IndexOf(text, StringComparison.OrdinalIgnoreCase) >= 0))).ToList();
            UiHelpers.ResetVirtual(_list, _rows.Count, Enumerable.Range(0, _rows.Count).Where(i => selected.Contains(_rows[i])));

            var blocked = all.Count(e => e.Verdict == Verdict.Blocked);
            var internet = all.Count(e => NetRanges.IsInternet(e.RemoteIp));
            var oldest = _service.History.OldestUtc;
            var note = oldest.HasValue && oldest.Value > DateTime.UtcNow.AddMinutes(-EventHistory.Minutes + 1) && _service.History.Count >= 200000
                ? $" (busy PC: kept from {oldest.Value.ToLocalTime():HH:mm})" : "";
            _summary.Text = $"{all.Count} attempt(s) in the last hour: {all.Count - blocked} accepted, {blocked} blocked, {internet} to the internet. Showing {_rows.Count}.{note}"
                + (_pause.Checked ? " (paused)" : "");
        }

        private static string[] Cells(FirewallEvent e) => new[]
        {
            e.TimeUtc.ToLocalTime().ToString("HH:mm:ss"),
            e.Verdict == Verdict.Blocked ? "Blocked" : e.Verdict == Verdict.Accepted ? "Accepted" : "-",
            e.Direction == TrafficDirection.Inbound ? "In" : e.Direction == TrafficDirection.Outbound ? "Out" : "-",
            e.Protocol ?? "",
            e.LocalIp ?? "",
            e.LocalPort == 0 ? "*" : e.LocalPort.ToString(),
            e.RemoteIp ?? "",
            IpInfo.HostName(e.RemoteIp),
            IpInfo.CountryText(e.RemoteIp),
            e.RemotePort == 0 ? "*" : e.RemotePort.ToString(),
            NetRanges.IsInternet(e.RemoteIp) ? "Yes" : "No"
        };

        private void OnRetrieveItem(object sender, RetrieveVirtualItemEventArgs e)
        {
            if (e.ItemIndex >= _rows.Count)
            {
                e.Item = new ListViewItem(new string[Columns.Length]);
                return;
            }
            var row = _rows[e.ItemIndex];
            var item = new ListViewItem(Cells(row));
            if (row.Verdict == Verdict.Blocked)
            {
                item.ForeColor = Theme.Blocked;
                item.BackColor = Theme.BlockedRow;
            }
            e.Item = item;
        }

        /// <summary>Shows the log for an app, owned by the main window so it closes with it. Several can be open at once.</summary>
        public static void Open(IWin32Window owner, FirewallService service, string ruleTarget)
        {
            if (string.IsNullOrEmpty(ruleTarget)) return;
            var form = new AppLogForm(service, ruleTarget);
            if (owner is Form f) form.Owner = f;
            form.FormClosed += (_, __) => form.Dispose();
            form.Show();
        }
    }
}
