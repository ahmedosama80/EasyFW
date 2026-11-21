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
            ("Blocklist", 120, ConnectionColumn.Threat, HorizontalAlignment.Left),
            ("Src Port", 62, ConnectionColumn.SourcePort, HorizontalAlignment.Right),
            ("Dest Port", 66, ConnectionColumn.DestPort, HorizontalAlignment.Right),
            ("State", 84, ConnectionColumn.State, HorizontalAlignment.Left),
            ("Hits", 44, ConnectionColumn.Hits, HorizontalAlignment.Right),
            ("Signed", 150, ConnectionColumn.Signed, HorizontalAlignment.Left),
            ("Path", 320, ConnectionColumn.Path, HorizontalAlignment.Left)
        };

        private readonly FirewallService _service;
        private readonly DecideHandler _decide;
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
        private ToolStripMenuItem _acceptForItem, _blockForItem;
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

        public ConnectionsTab(FirewallService service, DecideHandler decide)
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
            UiHelpers.ShowFullTextOnHover(_list);
            UiHelpers.RememberColumns(_list, "connections", _service);

            var bar =new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(4, 4, 4, 2), WrapContents = true };
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
            _acceptForItem = UiHelpers.ForAWhileMenu(RuleAction.Allow, d => DecideSelected(RuleAction.Allow, d));
            _blockForItem = UiHelpers.ForAWhileMenu(RuleAction.Block, d => DecideSelected(RuleAction.Block, d));
            _acceptItem.Click += async (_, __) => await DecideSelected(RuleAction.Allow);
            _blockItem.Click += async (_, __) => await DecideSelected(RuleAction.Block);
            _acceptPortsItem.Click += async (_, __) => await DecideSelectedPorts(RuleAction.Allow);
            _blockPortsItem.Click += async (_, __) => await DecideSelectedPorts(RuleAction.Block);
            menu.Items.Add(_acceptItem);
            menu.Items.Add(_acceptForItem);
            menu.Items.Add(_blockItem);
            menu.Items.Add(_blockForItem);
            menu.Items.Add(_acceptPortsItem);
            menu.Items.Add(_blockPortsItem);
            menu.Items.Add(new ToolStripSeparator());
            _copyItem.Click += (_, __) => CopyRows();
            menu.Items.Add(_copyItem);
            var copyPath = UiHelpers.CopyPathItem(FindForm, () => _list.SelectedIndices.Cast<int>().Where(i => i < _rows.Count).Select(i => _rows[i].AppPath));
            menu.Items.Add(copyPath);
            menu.Items.Add("Open file location", null, (_, __) => OpenLocation());
            menu.Items.Add("Show log (last hour)", null, (_, __) =>
            {
                var row = Selected;
                if (row != null) AppLogForm.Open(FindForm(), _service, AppPaths.RuleTarget(row.AppPath, row.Protocol));
            });
            menu.Opening += (_, e) =>
            {
                if (_list.SelectedIndices.Count == 0) e.Cancel = true;
                _copyItem.Text = UiHelpers.CopyLabel(_list.SelectedIndices.Count);
                copyPath.Text = UiHelpers.CopyPathLabel(_list.SelectedIndices.Count);
            };
            return menu;
        }

        public void SetCanDecide(bool can)
        {
            _acceptItem.Enabled = can;
            _blockItem.Enabled = can;
            if (_acceptForItem != null) _acceptForItem.Enabled = _blockForItem.Enabled = can;
            _acceptPortsItem.Enabled = can;
            _blockPortsItem.Enabled = can;
        }

        private ConnectionEntry Selected =>
            _list.SelectedIndices.Count > 0 && _list.SelectedIndices[0] < _rows.Count ? _rows[_list.SelectedIndices[0]] : null;

        private async Task DecideSelected(RuleAction action, RuleDuration duration = RuleDuration.Forever)
        {
            var row = Selected;
            if (row != null) await _decide(AppPaths.RuleTarget(row.AppPath, row.Protocol), action, null, duration);
        }

        private async Task DecideSelectedPorts(RuleAction action)
        {
            var row = Selected;
            if (row == null) return;
            using var form = new PortsForm(AppPaths.DisplayName(row.AppPath), action, row.DestPort > 0 ? row.DestPort.ToString() : "");
            if (form.ShowDialog(FindForm()) == DialogResult.OK)
                await _decide(AppPaths.RuleTarget(row.AppPath, row.Protocol), action, form.Ports, RuleDuration.Forever);
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
            if (IpInfo.Version + EasyFW.Platform.AppSignature.Version != _infoVersion)
            {
                _infoVersion = IpInfo.Version + EasyFW.Platform.AppSignature.Version;
                _list.Invalidate();
            }
            if (_pause.Checked && !_filterDirty) return;
            if (!_filterDirty && store.Version == _shownVersion) return;
            _filterDirty = false;
            _shownVersion = store.Version;

            var selected = new HashSet<string>(_list.SelectedIndices.Cast<int>().Where(i => i < _rows.Count).Select(i => _rows[i].Key));
            _rows = store.Query(CurrentFilter(), _sortColumn, _ascending);
            UiHelpers.ResetVirtual(_list, _rows.Count,
                selected.Count == 0 ? Enumerable.Empty<int>() : Enumerable.Range(0, _rows.Count).Where(i => selected.Contains(_rows[i].Key)));

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
            BlocklistIndex.Current.Match(e.RemoteIp) ?? "",
            e.SourcePort == 0 ? "*" : e.SourcePort.ToString(),
            e.DestPort == 0 ? "*" : e.DestPort.ToString(),
            e.State ?? "",
            e.Hits.ToString(),
            EasyFW.Platform.AppSignature.Text(e.AppPath),
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

        /// <summary>Sets a virtual list's row count and selects rows again after a refresh.</summary>
        public static void ResetVirtual(ListView list, int count, IEnumerable<int> select)
        {
            list.BeginUpdate();
            try
            {
                list.SelectedIndices.Clear();
                // After a shrink WinForms puts the old top row back, and that throws when the list has no top row,
                // for example while the window is minimized. The new size is already set by then.
                try { list.VirtualListSize = count; }
                catch (NullReferenceException) { }
                // Each selection is a call into the list, so a select-all over thousands of rows isn't carried over.
                foreach (var i in select.Take(500)) list.SelectedIndices.Add(i);
            }
            finally { list.EndUpdate(); }
            list.Invalidate();
        }

        /// <summary>Raised by Options > Reset column layout: every list puts its columns back the way they came.</summary>
        public static event Action ColumnsReset;

        public static void ResetColumns() => ColumnsReset?.Invoke();

        /// <summary>
        /// Lets the user drag columns into a new order, and keeps that order and the column widths in the config under <paramref name="name"/>.
        /// A saved layout for a different number of columns is ignored, so a version with new columns starts fresh.
        /// </summary>
        public static void RememberColumns(ListView list, string name, FirewallService service)
        {
            list.AllowColumnReorder = true;
            var columns = list.Columns.Cast<ColumnHeader>().ToList();
            var defaultWidths = columns.Select(c => c.Width).ToArray();
            var applying = false;

            var saved = service.Config.ColumnsFor(name);
            if (saved?.Order != null && saved.Order.Length == columns.Count && saved.Order.OrderBy(i => i).SequenceEqual(Enumerable.Range(0, columns.Count)))
            {
                applying = true;
                try
                {
                    // Setting display indexes in order of the target position keeps each move from shifting the ones already placed.
                    foreach (var i in Enumerable.Range(0, columns.Count).OrderBy(i => saved.Order[i])) columns[i].DisplayIndex = saved.Order[i];
                    if (saved.Widths != null && saved.Widths.Length == columns.Count)
                        for (var i = 0; i < columns.Count; i++) columns[i].Width = Math.Max(20, Math.Min(2000, saved.Widths[i]));
                }
                finally { applying = false; }
            }

            void Save()
            {
                if (applying || list.IsDisposed) return;
                service.SaveColumns(name, columns.Select(c => c.DisplayIndex).ToArray(), columns.Select(c => c.Width).ToArray());
            }
            // The new display indexes are only in place once the reorder event has finished.
            list.ColumnReordered += (_, __) =>
            {
                if (list.IsHandleCreated) list.BeginInvoke((Action)Save);
            };
            list.ColumnWidthChanged += (_, __) => Save();

            Action reset = () =>
            {
                if (list.IsDisposed) return;
                applying = true;
                try
                {
                    for (var i = 0; i < columns.Count; i++) columns[i].DisplayIndex = i;
                    for (var i = 0; i < columns.Count; i++) columns[i].Width = defaultWidths[i];
                }
                finally { applying = false; }
                service.SaveColumns(name, null, null);
                list.Invalidate();
            };
            ColumnsReset += reset;
            list.Disposed += (_, __) => ColumnsReset -= reset;
        }

        /// <summary>Shows a cell's full text in a tooltip when the mouse rests on a cell too narrow for it.</summary>
        public static void ShowFullTextOnHover(ListView list)
        {
            var tip = new ToolTip { InitialDelay = 300, ReshowDelay = 100, AutoPopDelay = 30000 };
            string shown = null;
            var at = Point.Empty;
            list.MouseMove += (_, e) =>
            {
                string text = null;
                ListViewHitTestInfo hit = null;
                try { hit = list.HitTest(e.Location); }
                catch (ArgumentOutOfRangeException) { }
                if (hit?.Item != null && hit.SubItem != null)
                {
                    var column = hit.Item.SubItems.IndexOf(hit.SubItem);
                    var t = hit.SubItem.Text ?? "";
                    // Room for the cell padding, and for a flag or icon drawn before the text.
                    if (column >= 0 && column < list.Columns.Count && t.Length > 0
                        && TextRenderer.MeasureText(t, list.Font).Width + 24 > list.Columns[column].Width)
                        text = t;
                }
                if (text == shown && (text == null || Math.Abs(e.Y - at.Y) < 8)) return;
                shown = text;
                at = e.Location;
                if (text == null) tip.Hide(list);
                else tip.Show(text, list, e.X + 12, e.Y + 20, 30000);
            };
            list.MouseLeave += (_, __) =>
            {
                shown = null;
                tip.Hide(list);
            };
            list.Disposed += (_, __) => tip.Dispose();
        }

        public static string CopyLabel(int rows) => rows > 1 ? $"Copy {rows} rows" : "Copy row";

        /// <summary>"Accept for a while" with Until restart, 10 minutes, 30 minutes and 1 hour under it.</summary>
        public static ToolStripMenuItem ForAWhileMenu(RuleAction action, Func<RuleDuration, Task> decide)
        {
            var item = new ToolStripMenuItem(action == RuleAction.Allow ? "Accept for a while" : "Block for a while");
            foreach (var d in RuleDurations.All.Where(d => d != RuleDuration.Forever))
            {
                var duration = d;
                item.DropDownItems.Add(RuleDurations.Text(d), null, async (_, __) => await decide(duration));
            }
            return item;
        }

        public static string CopyPathLabel(int rows) => rows > 1 ? "Copy paths" : "Copy path";

        /// <summary>The full path of each app, one per line, each once.</summary>
        public static void CopyPaths(IWin32Window owner, IEnumerable<string> paths) =>
            CopyRows(owner, paths.Where(p => !string.IsNullOrEmpty(p)).Distinct(StringComparer.OrdinalIgnoreCase).Select(p => new[] { p }));

        /// <summary>A "Copy path" menu item that copies whatever paths are picked when it's clicked.</summary>
        public static ToolStripMenuItem CopyPathItem(Func<IWin32Window> owner, Func<IEnumerable<string>> paths)
        {
            var item = new ToolStripMenuItem("Copy path");
            item.Click += (_, __) => CopyPaths(owner(), paths());
            return item;
        }

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
