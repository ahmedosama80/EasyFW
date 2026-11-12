using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using EasyFW.Core;

namespace EasyFW.UI
{
    /// <summary>The busiest traffic: connections grouped by app, remote address and destination port, ranked by how often they happened.</summary>
    public sealed class TopTab : UserControl
    {
        private const int Limit = 200;

        private static readonly (string Title, int Width, HorizontalAlignment Align)[] Columns =
        {
            ("#", 40, HorizontalAlignment.Right),
            ("Process", 150, HorizontalAlignment.Left),
            ("Dir", 44, HorizontalAlignment.Left),
            ("Proto", 56, HorizontalAlignment.Left),
            ("Remote IP", 130, HorizontalAlignment.Left),
            ("Remote Host", 180, HorizontalAlignment.Left),
            ("Country", 130, HorizontalAlignment.Left),
            ("Dest Port", 66, HorizontalAlignment.Right),
            ("Total", 64, HorizontalAlignment.Right),
            ("Accepted", 70, HorizontalAlignment.Right),
            ("Blocked", 64, HorizontalAlignment.Right),
            ("First seen", 76, HorizontalAlignment.Left),
            ("Last seen", 76, HorizontalAlignment.Left),
            ("Path", 320, HorizontalAlignment.Left)
        };

        private readonly FirewallService _service;
        private readonly Func<string, RuleAction, string, Task> _decide;
        private readonly ListView _list = new ListView
        {
            Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, VirtualMode = true, HideSelection = false, BorderStyle = BorderStyle.None
        };
        private readonly TextBox _search = new TextBox { Width = 150, Margin = new Padding(4, 5, 10, 4) };
        private readonly ComboBox _status = Combo(78, "All", "Accepted", "Blocked");
        private readonly ComboBox _direction = Combo(78, "All", "Inbound", "Outbound");
        private readonly ComboBox _protocol = Combo(78, "All", "TCP", "UDP", "ICMP", "ICMPv6");
        private readonly ComboBox _rank = Combo(82, "Total", "Blocked", "Accepted");
        private static readonly (string Text, int Minutes)[] Periods = { ("Last 10 min", 10), ("Last 30 min", 30), ("Last 1 hour", 60) };
        private readonly ComboBox _period = Combo(96, Periods.Select(p => (object)p.Text).ToArray());
        private long _shownMinute;
        private int _infoVersion = -1;
        private readonly CheckBox _hideLoopback = new CheckBox { Text = "Hide loopback", AutoSize = true, Checked = true, Margin = new Padding(0, 7, 10, 4) };
        private readonly Button _reset = new Button { Text = "Reset counts", AutoSize = true, Margin = new Padding(0, 3, 4, 3) };
        private readonly ToolStripMenuItem _acceptItem = new ToolStripMenuItem("Accept Always");
        private readonly ToolStripMenuItem _blockItem = new ToolStripMenuItem("Block Always");
        private readonly ToolStripMenuItem _copyItem = new ToolStripMenuItem("Copy row");
        private List<FlowStat> _rows = new List<FlowStat>();
        private long _shownVersion = -1;
        private bool _filterDirty = true;

        public string Summary { get; private set; } = "";

        public TopTab(FirewallService service, Func<string, RuleAction, string, Task> decide)
        {
            _service = service;
            _decide = decide;

            foreach (var c in Columns) _list.Columns.Add(c.Title, c.Width, c.Align);
            UiHelpers.EnableDoubleBuffer(_list);
            _list.RetrieveVirtualItem += OnRetrieveItem;
            _list.ContextMenuStrip = BuildMenu();
            Flags.ShowInColumn(_list, 6, 4, i => i < _rows.Count && _rows[i].Accepted == 0 ? Theme.BlockedRow : (System.Drawing.Color?)null);

            var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(4, 4, 4, 0), WrapContents = true };
            bar.Controls.Add(UiHelpers.BarLabel("Period"));
            bar.Controls.Add(_period);
            bar.Controls.Add(UiHelpers.BarLabel("Search"));
            bar.Controls.Add(_search);
            bar.Controls.Add(UiHelpers.BarLabel("Status"));
            bar.Controls.Add(_status);
            bar.Controls.Add(UiHelpers.BarLabel("Direction"));
            bar.Controls.Add(_direction);
            bar.Controls.Add(UiHelpers.BarLabel("Protocol"));
            bar.Controls.Add(_protocol);
            bar.Controls.Add(UiHelpers.BarLabel("Rank by"));
            bar.Controls.Add(_rank);
            bar.Controls.Add(_hideLoopback);
            bar.Controls.Add(_reset);

            var note = new Label
            {
                Dock = DockStyle.Top, AutoSize = false, Height = 22, AutoEllipsis = true, ForeColor = Theme.Muted, Padding = new Padding(8, 0, 8, 4),
                Text = "Connections to the same address and port count together. Counts are connections made or tried, not bytes: Windows doesn't report bytes per connection."
            };

            _search.TextChanged += (_, __) => FilterChanged();
            foreach (var combo in new[] { _period, _status, _direction, _protocol, _rank })
                combo.SelectedIndexChanged += (_, __) => FilterChanged();
            _hideLoopback.CheckedChanged += (_, __) => FilterChanged();
            _reset.Click += (_, __) =>
            {
                _service.Connections.Flows.Clear();
                FilterChanged();
            };

            Controls.Add(_list);
            Controls.Add(note);
            Controls.Add(bar);
        }

        private static ComboBox Combo(int width, params object[] items)
        {
            var c = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = width, Margin = new Padding(4, 5, 8, 4) };
            c.Items.AddRange(items);
            c.SelectedIndex = 0;
            return c;
        }

        private ContextMenuStrip BuildMenu()
        {
            var menu = new ContextMenuStrip();
            _acceptItem.Click += async (_, __) => await DecideSelected(RuleAction.Allow);
            _blockItem.Click += async (_, __) => await DecideSelected(RuleAction.Block);
            menu.Items.Add(_acceptItem);
            menu.Items.Add(_blockItem);
            menu.Items.Add(new ToolStripSeparator());
            _copyItem.Click += (_, __) => UiHelpers.CopyRows(FindForm(), SelectedIndices().Select(i => Cells(_rows[i], i)));
            menu.Items.Add(_copyItem);
            menu.Items.Add("Open file location", null, (_, __) => OpenLocation());
            menu.Opening += (_, e) =>
            {
                if (_list.SelectedIndices.Count == 0) e.Cancel = true;
                _copyItem.Text = UiHelpers.CopyLabel(_list.SelectedIndices.Count);
            };
            return menu;
        }

        public void SetCanDecide(bool can)
        {
            _acceptItem.Enabled = can;
            _blockItem.Enabled = can;
        }

        private IEnumerable<int> SelectedIndices() => _list.SelectedIndices.Cast<int>().Where(i => i < _rows.Count);

        private FlowStat Selected => SelectedIndices().Select(i => _rows[i]).FirstOrDefault();

        private async Task DecideSelected(RuleAction action)
        {
            var row = Selected;
            if (row != null && !string.IsNullOrEmpty(row.AppPath)) await _decide(AppPaths.RuleTarget(row.AppPath, row.Protocol), action, null);
        }

        private void OpenLocation()
        {
            var path = Selected?.AppPath;
            if (!string.IsNullOrEmpty(path) && File.Exists(path)) Process.Start("explorer.exe", $"/select,\"{path}\"");
        }

        private void FilterChanged()
        {
            _filterDirty = true;
            RefreshData();
        }

        private FlowFilter CurrentFilter() => new FlowFilter
        {
            Text = _search.Text,
            Status = _status.SelectedIndex == 1 ? Verdict.Accepted : _status.SelectedIndex == 2 ? Verdict.Blocked : (Verdict?)null,
            Direction = _direction.SelectedIndex == 1 ? TrafficDirection.Inbound : _direction.SelectedIndex == 2 ? TrafficDirection.Outbound : (TrafficDirection?)null,
            Protocol = _protocol.SelectedIndex > 0 ? (string)_protocol.SelectedItem : null,
            HideLoopback = _hideLoopback.Checked
        };

        public void RefreshData()
        {
            var flows = _service.Connections.Flows;
            var now = DateTime.UtcNow;
            if (IpInfo.Version != _infoVersion)
            {
                _infoVersion = IpInfo.Version;
                _list.Invalidate();
            }
            // A new minute moves the period along, so old counts drop out even with no new traffic.
            var minute = FlowStats.MinuteOf(now);
            if (!_filterDirty && flows.Version == _shownVersion && minute == _shownMinute) return;
            _filterDirty = false;
            _shownVersion = flows.Version;
            _shownMinute = minute;

            var period = Periods[Math.Max(0, _period.SelectedIndex)];
            var selected = new HashSet<string>(SelectedIndices().Select(i => _rows[i].Key));
            _rows = flows.Top(CurrentFilter(), (FlowRank)_rank.SelectedIndex, period.Minutes, Limit, now, out var matching);
            _list.BeginUpdate();
            try
            {
                _list.SelectedIndices.Clear();
                _list.VirtualListSize = _rows.Count;
                for (var i = 0; i < _rows.Count && selected.Count > 0; i++)
                    if (selected.Contains(_rows[i].Key)) _list.SelectedIndices.Add(i);
            }
            finally { _list.EndUpdate(); }
            _list.Invalidate();

            var span = period.Minutes == 60 ? "the last hour" : $"the last {period.Minutes} minutes";
            Summary = matching > _rows.Count
                ? $"Top {_rows.Count} of {matching} connection groups in {span}"
                : $"{_rows.Count} connection group(s) in {span}";
        }

        private static string[] Cells(FlowStat f, int index) => new[]
        {
            (index + 1).ToString(),
            f.ProcessName ?? "",
            f.Direction == TrafficDirection.Inbound ? "In" : f.Direction == TrafficDirection.Outbound ? "Out" : "-",
            f.Protocol ?? "",
            f.RemoteIp ?? "",
            IpInfo.HostName(f.RemoteIp),
            IpInfo.CountryText(f.RemoteIp),
            f.DestPort == 0 ? "*" : f.DestPort.ToString(),
            f.Total.ToString(),
            f.Accepted.ToString(),
            f.Blocked.ToString(),
            f.FirstSeenUtc.ToLocalTime().ToString("HH:mm:ss"),
            f.LastSeenUtc.ToLocalTime().ToString("HH:mm:ss"),
            f.AppPath ?? ""
        };

        private void OnRetrieveItem(object sender, RetrieveVirtualItemEventArgs e)
        {
            // The list can ask for a row while a shrink is in flight, and it must always get an item.
            if (e.ItemIndex >= _rows.Count)
            {
                e.Item = new ListViewItem(new string[Columns.Length]);
                return;
            }
            var row = _rows[e.ItemIndex];
            var item = new ListViewItem(Cells(row, e.ItemIndex));
            if (row.Accepted == 0)
            {
                item.ForeColor = Theme.Blocked;
                item.BackColor = Theme.BlockedRow;
            }
            e.Item = item;
        }
    }
}
