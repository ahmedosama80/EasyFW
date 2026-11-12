using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using EasyFW.Core;

namespace EasyFW.UI
{
    public sealed class ConnectionsTab : UserControl
    {
        private static readonly (string Title, int Width, ConnectionColumn Column, HorizontalAlignment Align)[] Columns =
        {
            ("Time", 76, ConnectionColumn.Time, HorizontalAlignment.Left),
            ("Status", 76, ConnectionColumn.Status, HorizontalAlignment.Left),
            ("Process", 150, ConnectionColumn.Process, HorizontalAlignment.Left),
            ("PID", 58, ConnectionColumn.Pid, HorizontalAlignment.Right),
            ("Dir", 44, ConnectionColumn.Direction, HorizontalAlignment.Left),
            ("Proto", 56, ConnectionColumn.Protocol, HorizontalAlignment.Left),
            ("Local IP", 118, ConnectionColumn.LocalIp, HorizontalAlignment.Left),
            ("Local Host", 130, ConnectionColumn.LocalHost, HorizontalAlignment.Left),
            ("Remote IP", 124, ConnectionColumn.RemoteIp, HorizontalAlignment.Left),
            ("Remote Host", 180, ConnectionColumn.RemoteHost, HorizontalAlignment.Left),
            ("Country", 130, ConnectionColumn.Country, HorizontalAlignment.Left),
            ("Src Port", 62, ConnectionColumn.SourcePort, HorizontalAlignment.Right),
            ("Dest Port", 66, ConnectionColumn.DestPort, HorizontalAlignment.Right),
            ("State", 84, ConnectionColumn.State, HorizontalAlignment.Left),
            ("Hits", 44, ConnectionColumn.Hits, HorizontalAlignment.Right),
            ("Path", 320, ConnectionColumn.Path, HorizontalAlignment.Left)
        };

        private readonly FirewallService _service;
        private readonly Func<string, RuleAction, string, Task> _decide;
        private readonly ListView _list = new ListView
        {
            Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, VirtualMode = true, HideSelection = false, BorderStyle = BorderStyle.None
        };
        private readonly TextBox _search = new TextBox { Width = 170, Margin = new Padding(4, 5, 10, 4) };
        private readonly ComboBox _verdict = Combo("All", "Accepted", "Blocked");
        private readonly ComboBox _direction = Combo("All", "Inbound", "Outbound");
        private readonly ComboBox _protocol = Combo("All", "TCP", "UDP", "ICMP", "ICMPv6");
        private readonly CheckBox _activeOnly = new CheckBox { Text = "Active only", AutoSize = true, Margin = new Padding(4, 7, 10, 4) };
        private readonly CheckBox _hideLoopback = new CheckBox { Text = "Hide loopback", AutoSize = true, Checked = true, Margin = new Padding(0, 7, 10, 4) };
        private readonly CheckBox _pause = UiHelpers.PauseButton();
        private readonly Button _clear = new Button { Text = "Clear history", AutoSize = true, Margin = new Padding(0, 3, 4, 3) };
        private readonly TrafficGraph _graph;
        private readonly ToolStripMenuItem _acceptItem = new ToolStripMenuItem("Accept Always");
        private readonly ToolStripMenuItem _blockItem = new ToolStripMenuItem("Block Always");
        private readonly ToolStripMenuItem _acceptPortsItem = new ToolStripMenuItem("Accept on ports...");
        private readonly ToolStripMenuItem _blockPortsItem = new ToolStripMenuItem("Block on ports...");
        private readonly ToolStripMenuItem _copyItem = new ToolStripMenuItem("Copy row");
        private List<ConnectionEntry> _rows = new List<ConnectionEntry>();
        private ConnectionColumn _sortColumn = ConnectionColumn.Time;
        private bool _ascending;
        private long _shownVersion = -1;
        private bool _filterDirty = true;
        private int _infoVersion = -1;

        public string Summary { get; private set; } = "";

        public ConnectionsTab(FirewallService service, Func<string, RuleAction, string, Task> decide)
        {
            _service = service;
            _decide = decide;
            _graph = new TrafficGraph(service.Traffic);

            foreach (var c in Columns) _list.Columns.Add(c.Title, c.Width, c.Align);
            UiHelpers.EnableDoubleBuffer(_list);
            _list.RetrieveVirtualItem += OnRetrieveItem;
            _list.ColumnClick += (_, e) => SortBy(e.Column);
            _list.ContextMenuStrip = BuildMenu();
            Flags.ShowInColumn(_list, Column(ConnectionColumn.Country), Column(ConnectionColumn.RemoteIp),
                i => i < _rows.Count && _rows[i].Verdict == Verdict.Blocked ? Theme.BlockedRow : (Color?)null);
            UpdateHeaders();

            var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(4, 4, 4, 2), WrapContents = true };
            bar.Controls.Add(UiHelpers.BarLabel("Search"));
            bar.Controls.Add(_search);
            bar.Controls.Add(UiHelpers.BarLabel("Status"));
            bar.Controls.Add(_verdict);
            bar.Controls.Add(UiHelpers.BarLabel("Direction"));
            bar.Controls.Add(_direction);
            bar.Controls.Add(UiHelpers.BarLabel("Protocol"));
            bar.Controls.Add(_protocol);
            bar.Controls.Add(_activeOnly);
            bar.Controls.Add(_hideLoopback);
            bar.Controls.Add(_pause);
            bar.Controls.Add(_clear);

            _search.TextChanged += (_, __) => FilterChanged();
            _verdict.SelectedIndexChanged += (_, __) => FilterChanged();
            _direction.SelectedIndexChanged += (_, __) => FilterChanged();
            _protocol.SelectedIndexChanged += (_, __) => FilterChanged();
            _activeOnly.CheckedChanged += (_, __) => FilterChanged();
            _hideLoopback.CheckedChanged += (_, __) => FilterChanged();
            _pause.CheckedChanged += (_, __) => FilterChanged();
            _clear.Click += (_, __) =>
            {
                _service.Connections.Clear();
                FilterChanged();
            };

            Controls.Add(_list);
            Controls.Add(_graph);
            Controls.Add(bar);
        }

        private static int Column(ConnectionColumn c) => Array.FindIndex(Columns, x => x.Column == c);

        private static ComboBox Combo(params object[] items)
        {
            var c = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 78, Margin = new Padding(4, 5, 8, 4) };
            c.Items.AddRange(items);
            c.SelectedIndex = 0;
            return c;
        }

        private ContextMenuStrip BuildMenu()
        {
            var menu = new ContextMenuStrip();
            _acceptItem.Click += async (_, __) => await DecideSelected(RuleAction.Allow);
            _blockItem.Click += async (_, __) => await DecideSelected(RuleAction.Block);
            _acceptPortsItem.Click += async (_, __) => await DecideSelectedPorts(RuleAction.Allow);
            _blockPortsItem.Click += async (_, __) => await DecideSelectedPorts(RuleAction.Block);
            menu.Items.Add(_acceptItem);
            menu.Items.Add(_blockItem);
            menu.Items.Add(_acceptPortsItem);
            menu.Items.Add(_blockPortsItem);
            menu.Items.Add(new ToolStripSeparator());
            _copyItem.Click += (_, __) => CopyRows();
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
            _acceptPortsItem.Enabled = can;
            _blockPortsItem.Enabled = can;
        }

        private ConnectionEntry Selected =>
            _list.SelectedIndices.Count > 0 && _list.SelectedIndices[0] < _rows.Count ? _rows[_list.SelectedIndices[0]] : null;

        private async Task DecideSelected(RuleAction action)
        {
            var row = Selected;
            if (row != null) await _decide(AppPaths.RuleTarget(row.AppPath, row.Protocol), action, null);
        }

        private async Task DecideSelectedPorts(RuleAction action)
        {
            var row = Selected;
            if (row == null) return;
            using var form = new PortsForm(AppPaths.DisplayName(row.AppPath), action, row.DestPort > 0 ? row.DestPort.ToString() : "");
            if (form.ShowDialog(FindForm()) == DialogResult.OK)
                await _decide(AppPaths.RuleTarget(row.AppPath, row.Protocol), action, form.Ports);
        }

        private void CopyRows() =>
            UiHelpers.CopyRows(FindForm(), _list.SelectedIndices.Cast<int>().Where(i => i < _rows.Count).Select(i => Cells(_rows[i])));

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

        private ConnectionFilter CurrentFilter() => new ConnectionFilter
        {
            Text = _search.Text,
            Verdict = _verdict.SelectedIndex == 1 ? Verdict.Accepted : _verdict.SelectedIndex == 2 ? Verdict.Blocked : (Verdict?)null,
            Direction = _direction.SelectedIndex == 1 ? TrafficDirection.Inbound : _direction.SelectedIndex == 2 ? TrafficDirection.Outbound : (TrafficDirection?)null,
            Protocol = _protocol.SelectedIndex > 0 ? (string)_protocol.SelectedItem : null,
            ActiveOnly = _activeOnly.Checked,
            HideLoopback = _hideLoopback.Checked
        };

        private void SortBy(int column)
        {
            var c = Columns[column].Column;
            if (c == _sortColumn) _ascending = !_ascending;
            else
            {
                _sortColumn = c;
                _ascending = c != ConnectionColumn.Time && c != ConnectionColumn.Hits;
            }
            UpdateHeaders();
            FilterChanged();
        }

        private void UpdateHeaders()
        {
            for (var i = 0; i < Columns.Length; i++)
            {
                var arrow = Columns[i].Column != _sortColumn ? "" : _ascending ? " ▲" : " ▼";
                _list.Columns[i].Text = Columns[i].Title + arrow;
            }
        }

        public void RefreshGraph() => _graph.Invalidate();

        public void RefreshData()
        {
            var store = _service.Connections;
            // Names and countries arrive in the background, and rows build their cells as they paint.
            if (IpInfo.Version != _infoVersion)
            {
                _infoVersion = IpInfo.Version;
                _list.Invalidate();
            }
            if (_pause.Checked && !_filterDirty) return;
            if (!_filterDirty && store.Version == _shownVersion) return;
            _filterDirty = false;
            _shownVersion = store.Version;

            var selected = new HashSet<string>(_list.SelectedIndices.Cast<int>().Where(i => i < _rows.Count).Select(i => _rows[i].Key));
            _rows = store.Query(CurrentFilter(), _sortColumn, _ascending);
            _list.BeginUpdate();
            try
            {
                _list.SelectedIndices.Clear();
                _list.VirtualListSize = _rows.Count;
                if (selected.Count > 0)
                {
                    for (var i = 0; i < _rows.Count; i++)
                        if (selected.Contains(_rows[i].Key)) _list.SelectedIndices.Add(i);
                }
            }
            finally { _list.EndUpdate(); }
            _list.Invalidate();

            var blocked = _rows.Count(r => r.Verdict == Verdict.Blocked);
            var active = _rows.Count(r => r.IsActive);
            Summary = $"Showing {_rows.Count} of {store.Count} connections: {active} active, {blocked} blocked" + (_pause.Checked ? " (paused)" : "");
        }

        private static string[] Cells(ConnectionEntry e) => new[]
        {
            e.LastSeenUtc.ToLocalTime().ToString("HH:mm:ss"),
            e.Verdict == Verdict.Blocked ? "Blocked" : e.Verdict == Verdict.Accepted ? "Accepted" : "-",
            e.ProcessName ?? "",
            e.Pid.ToString(),
            e.Direction == TrafficDirection.Inbound ? "In" : e.Direction == TrafficDirection.Outbound ? "Out" : "-",
            e.Protocol ?? "",
            e.LocalIp ?? "",
            IpInfo.HostName(e.LocalIp),
            e.RemoteIp ?? "",
            IpInfo.HostName(e.RemoteIp),
            IpInfo.CountryText(e.RemoteIp),
            e.SourcePort == 0 ? "*" : e.SourcePort.ToString(),
            e.DestPort == 0 ? "*" : e.DestPort.ToString(),
            e.State ?? "",
            e.Hits.ToString(),
            e.AppPath ?? ""
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
            var item = new ListViewItem(Cells(row));
            if (row.Verdict == Verdict.Blocked)
            {
                item.ForeColor = Theme.Blocked;
                item.BackColor = Theme.BlockedRow;
            }
            else if (!row.IsActive && row.State == "Closed")
            {
                item.ForeColor = Theme.Closed;
            }
            e.Item = item;
        }
    }

    public static class UiHelpers
    {
        public static void EnableDoubleBuffer(Control control)
        {
            typeof(Control).GetProperty("DoubleBuffered", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
                ?.SetValue(control, true);
        }

        public static string CopyLabel(int rows) => rows > 1 ? $"Copy {rows} rows" : "Copy row";

        /// <summary>Tab-separated with one line per row, so it pastes into a spreadsheet as cells.</summary>
        public static string RowsText(IEnumerable<IEnumerable<string>> rows) =>
            string.Join(Environment.NewLine, rows.Select(cells => string.Join("\t", cells)));

        public static void CopyRows(IWin32Window owner, IEnumerable<IEnumerable<string>> rows)
        {
            var text = RowsText(rows);
            if (text.Length == 0) return;
            // Another program can be holding the clipboard for a moment, so this retries before giving up.
            try { Clipboard.SetDataObject(text, true, 5, 100); }
            catch (System.Runtime.InteropServices.ExternalException ex)
            {
                Log.Write("Copy failed: " + ex.Message);
                MessageBox.Show(owner, "Another program is using the clipboard. Try again in a moment.", "Copy");
            }
        }

        /// <summary>A push button that stays down while the list is paused, so it's plain whether updates are stopped.</summary>
        public static CheckBox PauseButton()
        {
            var button = new CheckBox { Appearance = Appearance.Button, Text = "Pause updates", AutoSize = true, TextAlign = System.Drawing.ContentAlignment.MiddleCenter, Margin = new Padding(0, 3, 6, 3) };
            button.CheckedChanged += (_, __) => button.Text = button.Checked ? "Resume updates" : "Pause updates";
            return button;
        }

        public static Label BarLabel(string text) =>
            new Label { Text = text, AutoSize = true, Margin = new Padding(4, 8, 0, 4) };
    }
}
