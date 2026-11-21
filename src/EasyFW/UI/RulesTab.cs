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
    public sealed class RulesTab : UserControl
    {
        private readonly FirewallService _service;
        private readonly DecideHandler _decide;
        private readonly ListView _pending = NewList(("Application", 170), ("Wants", 84), ("Wants internet", 96), ("Signed", 150), ("Remote IP", 130), ("Remote Host", 170), ("Country", 130), ("Src Port", 62), ("Dest Port", 66), ("Proto", 60), ("Attempts", 66), ("First seen", 130), ("Path", 360));
        private readonly ListView _rules = NewList(("Application", 170), ("Decision", 130), ("Expires", 130), ("Hours", 150), ("In lockdown", 84), ("Direction", 80), ("Ports", 130), ("Network", 150), ("Internet access", 100), ("Wants internet", 96), ("Signed", 150), ("Enabled", 62), ("Notes", 200), ("Created", 130), ("Path", 300));
        private readonly Button _patterns = ActionButton("Path && keyword rules...");
        private readonly Button _accept = ActionButton("Accept Always");
        private readonly Button _block = ActionButton("Block Always");
        private readonly ComboBox _duration = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 120, Margin = new Padding(0, 4, 6, 4) };
        private readonly Button _acceptPorts = ActionButton("Accept on ports...");
        private readonly Button _blockPorts = ActionButton("Block on ports...");
        private readonly Button _dismiss = ActionButton("Dismiss");
        private readonly Button _add = ActionButton("Add rule...");
        private readonly Button _edit = ActionButton("Edit...");
        private readonly Button _delete = ActionButton("Delete");
        private readonly Button _export = ActionButton("Export...");
        private readonly Button _import = ActionButton("Import...");
        private readonly Label _pendingTitle = new Label { AutoSize = true, Font = Theme.Heading, Margin = new Padding(0, 6, 12, 6) };
        private readonly Label _rulesTitle = new Label { AutoSize = true, Font = Theme.Heading, Margin = new Padding(0, 6, 12, 6) };
        private readonly Label _emptyPending = EmptyHint(NoPendingText);
        private readonly Label _emptyRules = EmptyHint(NoRulesText);
        private readonly TextBox _pendingSearch = SearchBox();
        private string[] _pendingTitles;
        private int _pendingSort = -1;
        private bool _pendingAscending;
        private readonly ComboBox _pendingDirection = Combo("All", "Inbound", "Outbound");
        private readonly ComboBox _pendingProtocol = Combo("All", "TCP", "UDP", "ICMP", "ICMPv6");
        private readonly TextBox _rulesSearch = SearchBox();
        private readonly ComboBox _rulesDecision = Combo("All", "Accept", "Block");
        private readonly ComboBox _rulesDirection = Combo("All", "Inbound", "Outbound");
        private readonly ComboBox _rulesState = Combo("All", "Active", "Disabled");
        private const string NoPendingText = "No pending requests. When an unapproved app tries to connect, it appears here.";
        private const string NoRulesText = "No rules yet. Decide on a request above, or add one by hand.";
        private const string NoMatchText = "Nothing matches these filters.";
        private int _infoVersion = -1;
        private int _signVersion = -1;
        private bool _dirty = true;

        public RulesTab(FirewallService service, DecideHandler decide)
        {
            _service = service;
            _decide = decide;

            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Padding = new Padding(8, 4, 8, 8) };
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            foreach (var d in RuleDurations.All) _duration.Items.Add(RuleDurations.Text(d));
            _duration.SelectedIndex = 0;
            _duration.SelectedIndexChanged += (_, __) =>
            {
                _accept.Text = RuleDurations.ActionText(RuleAction.Allow, Duration);
                _block.Text = RuleDurations.ActionText(RuleAction.Block, Duration);
            };
            layout.Controls.Add(Toolbar(_pendingTitle, UiHelpers.BarLabel("Keep"), _duration, _accept, _block, _acceptPorts, _blockPorts, _dismiss,
                FilterGroup(UiHelpers.BarLabel("Search"), _pendingSearch, UiHelpers.BarLabel("Wants"), _pendingDirection, UiHelpers.BarLabel("Protocol"), _pendingProtocol)), 0, 0);
            layout.Controls.Add(WithHint(_pending, _emptyPending), 0, 1);
            layout.Controls.Add(Toolbar(_rulesTitle, _add, _edit, _delete, _patterns, _export, _import,
                FilterGroup(UiHelpers.BarLabel("Search"), _rulesSearch, UiHelpers.BarLabel("Decision"), _rulesDecision, UiHelpers.BarLabel("Direction"), _rulesDirection, UiHelpers.BarLabel("State"), _rulesState)), 0, 2);
            layout.Controls.Add(WithHint(_rules, _emptyRules), 0, 3);
            Controls.Add(layout);

            _accept.Click += async (_, __) => await DecidePending(RuleAction.Allow);
            _block.Click += async (_, __) => await DecidePending(RuleAction.Block);
            _acceptPorts.Click += async (_, __) => await DecidePendingPorts(RuleAction.Allow);
            _blockPorts.Click += async (_, __) => await DecidePendingPorts(RuleAction.Block);
            _export.Click += (_, __) => ExportRules();
            _import.Click += async (_, __) => await ImportRules();
            _dismiss.Click += (_, __) =>
            {
                foreach (var p in SelectedPending()) _service.Dismiss(p.AppPath);
            };
            _add.Click += async (_, __) => await EditRule(null);
            _edit.Click += async (_, __) => await EditRule(SelectedRules().FirstOrDefault());
            _delete.Click += async (_, __) => await DeleteSelected();
            _rules.DoubleClick += async (_, __) => await EditRule(SelectedRules().FirstOrDefault());
            _patterns.Click += (_, __) =>
            {
                if (!Guard.Unlock(FindForm(), "Changing path and keyword rules")) return;
                using var form = new PatternsForm(_service);
                form.ShowDialog(FindForm());
            };
            _pending.ContextMenuStrip = BuildPendingMenu();
            _rules.ContextMenuStrip = BuildRulesMenu();
            Flags.ShowInColumn(_pending, 6, 4);
            UiHelpers.ShowFullTextOnHover(_pending);
            UiHelpers.ShowFullTextOnHover(_rules);
            UiHelpers.RememberColumns(_pending, "pending", _service);
            _pendingTitles = _pending.Columns.Cast<ColumnHeader>().Select(c => c.Text).ToArray();
            _pending.ColumnClick += (_, e) => SortPendingBy(e.Column);
            UiHelpers.RememberColumns(_rules, "rules", _service);
            _pending.SelectedIndexChanged += (_, __) => UpdateButtons();
            _rules.SelectedIndexChanged += (_, __) => UpdateButtons();
            _pendingSearch.TextChanged += (_, __) => RefreshData();
            _rulesSearch.TextChanged += (_, __) => RefreshData();
            foreach (var combo in new[] { _pendingDirection, _pendingProtocol, _rulesDecision, _rulesDirection, _rulesState })
                combo.SelectedIndexChanged += (_, __) => RefreshData();
            RefreshData();
        }

        private static ListView NewList(params (string Title, int Width)[] columns)
        {
            var list = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, HideSelection = false };
            foreach (var c in columns) list.Columns.Add(c.Title, c.Width);
            UiHelpers.EnableDoubleBuffer(list);
            return list;
        }

        private static TextBox SearchBox() => new TextBox { Width = 120, Margin = new Padding(4, 5, 6, 4) };

        private static ComboBox Combo(params object[] items)
        {
            var c = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 78, Margin = new Padding(4, 5, 6, 4) };
            c.Items.AddRange(items);
            c.SelectedIndex = 0;
            return c;
        }

        private static TrafficDirection? DirectionFrom(ComboBox c) =>
            c.SelectedIndex == 1 ? TrafficDirection.Inbound : c.SelectedIndex == 2 ? TrafficDirection.Outbound : (TrafficDirection?)null;

        private PendingFilter CurrentPendingFilter() => new PendingFilter
        {
            Text = _pendingSearch.Text,
            Direction = DirectionFrom(_pendingDirection),
            Protocol = _pendingProtocol.SelectedIndex > 0 ? (string)_pendingProtocol.SelectedItem : null
        };

        private RuleFilter CurrentRuleFilter() => new RuleFilter
        {
            Text = _rulesSearch.Text,
            Action = _rulesDecision.SelectedIndex == 1 ? RuleAction.Allow : _rulesDecision.SelectedIndex == 2 ? RuleAction.Block : (RuleAction?)null,
            Direction = DirectionFrom(_rulesDirection),
            Enabled = _rulesState.SelectedIndex == 1 ? true : _rulesState.SelectedIndex == 2 ? false : (bool?)null
        };

        private static Button ActionButton(string text) =>
            new Button { Text = text, AutoSize = true, Padding = new Padding(6, 1, 6, 1), Margin = new Padding(0, 2, 6, 4) };

        private static Label EmptyHint(string text) =>
            new Label { Text = text, ForeColor = Theme.Muted, AutoSize = false, TextAlign = ContentAlignment.MiddleCenter, Dock = DockStyle.Fill, BackColor = SystemColors.Window };

        private static Control WithHint(ListView list, Label hint)
        {
            var host = new Panel { Dock = DockStyle.Fill, Margin = Padding.Empty, BorderStyle = BorderStyle.FixedSingle };
            list.BorderStyle = BorderStyle.None;
            host.Controls.Add(hint);
            host.Controls.Add(list);
            return host;
        }

        private static Control Toolbar(Label title, params Control[] buttons)
        {
            var bar = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = true, Margin = new Padding(0, 4, 0, 0) };
            bar.Controls.Add(title);
            bar.Controls.AddRange(buttons);
            return bar;
        }

        /// <summary>Wraps as one piece, so a filter never lands on a different line from its label.</summary>
        private static Control FilterGroup(params Control[] controls)
        {
            var group = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = Padding.Empty };
            group.Controls.AddRange(controls);
            return group;
        }

        private ContextMenuStrip BuildPendingMenu()
        {
            var menu = new ContextMenuStrip();
            menu.Items.Add("Show log (last hour)", null, (_, __) => ShowLog(SelectedPending().FirstOrDefault()?.AppPath));
            menu.Items.Add(new ToolStripSeparator());
            var copy = new ToolStripMenuItem("Copy row");
            copy.Click += (_, __) => CopyRows(_pending);
            menu.Items.Add(copy);
            var copyPath = UiHelpers.CopyPathItem(FindForm, () => SelectedPending().Select(p => p.AppPath));
            menu.Items.Add(copyPath);
            menu.Opening += (_, e) =>
            {
                if (_pending.SelectedItems.Count == 0) e.Cancel = true;
                copy.Text = UiHelpers.CopyLabel(_pending.SelectedItems.Count);
                copyPath.Text = UiHelpers.CopyPathLabel(_pending.SelectedItems.Count);
            };
            return menu;
        }

        private ContextMenuStrip BuildRulesMenu()
        {
            var menu = new ContextMenuStrip();
            var edit = new ToolStripMenuItem("Edit...");
            edit.Click += async (_, __) => await EditRule(SelectedRules().FirstOrDefault());
            menu.Items.Add(edit);
            menu.Items.Add("Show log (last hour)", null, (_, __) => ShowLog(SelectedRules().FirstOrDefault()?.AppPath));
            menu.Items.Add(new ToolStripSeparator());
            var copy = new ToolStripMenuItem("Copy row");
            copy.Click += (_, __) => CopyRows(_rules);
            menu.Items.Add(copy);
            var copyPath = UiHelpers.CopyPathItem(FindForm, () => SelectedRules().Select(r => r.AppPath));
            menu.Items.Add(copyPath);
            menu.Opening += (_, e) =>
            {
                if (_rules.SelectedItems.Count == 0) e.Cancel = true;
                copyPath.Text = UiHelpers.CopyPathLabel(_rules.SelectedItems.Count);
                edit.Enabled = _service.CanChange && _rules.SelectedItems.Count == 1;
                copy.Text = UiHelpers.CopyLabel(_rules.SelectedItems.Count);
            };
            return menu;
        }

        private void CopyRows(ListView list) =>
            UiHelpers.CopyRows(FindForm(), list.SelectedItems.Cast<ListViewItem>().Select(i => i.SubItems.Cast<ListViewItem.ListViewSubItem>().Select(c => c.Text)));

        private void ShowLog(string target) => AppLogForm.Open(FindForm(), _service, target);

        private List<PendingRequest> SelectedPending() => _pending.SelectedItems.Cast<ListViewItem>().Select(i => (PendingRequest)i.Tag).ToList();

        private List<AppRule> SelectedRules() => _rules.SelectedItems.Cast<ListViewItem>().Select(i => (AppRule)i.Tag).ToList();

        /// <summary>How long Accept and Block on pending requests last.</summary>
        private RuleDuration Duration => RuleDurations.All[Math.Max(0, _duration.SelectedIndex)];

        private async Task DecidePending(RuleAction action)
        {
            var duration = Duration;
            foreach (var p in SelectedPending()) await _decide(p.AppPath, action, null, duration);
        }

        private async Task DecidePendingPorts(RuleAction action)
        {
            var selected = SelectedPending();
            if (selected.Count == 0) return;
            var name = selected.Count == 1 ? selected[0].DisplayName : $"These {selected.Count} apps";
            using var form = new PortsForm(name, action, selected.Count == 1 && selected[0].LastDestPort > 0 ? selected[0].LastDestPort.ToString() : "");
            if (form.ShowDialog(FindForm()) != DialogResult.OK) return;
            var duration = Duration;
            foreach (var p in selected) await _decide(p.AppPath, action, form.Ports, duration);
        }

        private void ExportRules()
        {
            using var dialog = new SaveFileDialog { Title = "Export rules", Filter = "EasyFW rules (*.json)|*.json", FileName = "EasyFW-rules.json" };
            if (dialog.ShowDialog(FindForm()) != DialogResult.OK) return;
            try
            {
                File.WriteAllBytes(dialog.FileName, RuleTransfer.Export(_service.Config.Rules));
                MessageBox.Show(FindForm(), $"Saved {_service.Config.Rules.Count} rule(s) to {dialog.FileName}.", "Export rules");
            }
            catch (Exception ex) { Fail(ex); }
        }

        private async Task ImportRules()
        {
            if (!_service.CanChange || !Guard.Unlock(FindForm(), "Importing rules")) return;
            using var dialog = new OpenFileDialog { Title = "Import rules", Filter = "EasyFW rules (*.json)|*.json|All files (*.*)|*.*" };
            if (dialog.ShowDialog(FindForm()) != DialogResult.OK) return;
            try
            {
                var rules = RuleTransfer.Parse(File.ReadAllBytes(dialog.FileName));
                if (rules.Count == 0)
                {
                    MessageBox.Show(FindForm(), "That file has no rules in it.", "Import rules");
                    return;
                }
                var replacing = rules.Count(r => _service.FindRule(r.AppPath) != null);
                var opening = rules.Count(r => r.Enabled && (r.Action == RuleAction.Allow || r.HasPorts));
                var answer = MessageBox.Show(FindForm(),
                    $"Import {rules.Count} rule(s) from {Path.GetFileName(dialog.FileName)}?\n\n" +
                    $"{rules.Count - replacing} new, {replacing} replacing your rule for the same app. Your other rules stay.\n\n" +
                    $"{opening} of them let apps use the network, so only import a file you trust.",
                    "Import rules", MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2);
                if (answer == DialogResult.Yes) await _service.ImportRulesAsync(rules);
            }
            catch (Exception ex) { Fail(ex); }
        }

        private async Task EditRule(AppRule rule)
        {
            if (!_service.CanChange || !Guard.Unlock(FindForm(), rule == null ? "Adding a rule" : "Changing a rule")) return;
            using var form = new RuleEditForm(rule);
            if (form.ShowDialog(FindForm()) != DialogResult.OK) return;
            try { await _service.SaveRuleAsync(form.Result); }
            catch (Exception ex) { Fail(ex); }
        }

        private async Task DeleteSelected()
        {
            var rules = SelectedRules();
            if (rules.Count == 0 || !Guard.Unlock(FindForm(), "Deleting a rule")) return;
            var name = rules.Count == 1 ? rules[0].DisplayName : $"{rules.Count} rules";
            if (MessageBox.Show(FindForm(), $"Delete the rule for {name}? While protection is on, the app goes back to being blocked and will ask again.",
                    "Delete rule", MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            try
            {
                foreach (var r in rules) await _service.DeleteRuleAsync(r);
            }
            catch (Exception ex) { Fail(ex); }
        }

        private void Fail(Exception ex)
        {
            Log.Write("Rule action failed: " + ex);
            MessageBox.Show(FindForm(), ex.Message, "EasyFW", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        private void UpdateButtons()
        {
            var can = _service.CanChange;
            _accept.Enabled = _block.Enabled = _acceptPorts.Enabled = _blockPorts.Enabled = can && _pending.SelectedItems.Count > 0;
            _duration.Enabled = can;
            _import.Enabled = can;
            _export.Enabled = _service.Config.Rules.Count > 0;
            _dismiss.Enabled = _pending.SelectedItems.Count > 0;
            _add.Enabled = can;
            _edit.Enabled = can && _rules.SelectedItems.Count == 1;
            _delete.Enabled = can && _rules.SelectedItems.Count > 0;
        }

        /// <summary>Host names and countries arrive in the background. Called every second while the tab shows.</summary>
        public void RefreshNames()
        {
            // Temporary rules count down, so their Expires cells change every minute.
            if (_dirty || IpInfo.Version != _infoVersion || AppSignature.Version != _signVersion || _service.Config.Rules.Any(r => r.IsTemporary)) RefreshData();
        }

        /// <summary>For changes while the tab isn't showing: it catches up when shown, instead of rebuilding unseen lists every second.</summary>
        public void MarkDirty() => _dirty = true;

        public void RefreshData()
        {
            _dirty = false;
            _infoVersion = IpInfo.Version;
            _signVersion = AppSignature.Version;
            var cfg = _service.Config;
            var pendingFilter = CurrentPendingFilter();
            var ruleFilter = CurrentRuleFilter();
            var pending = cfg.Pending.Where(pendingFilter.Matches).ToList();
            var rules = cfg.Rules.Where(ruleFilter.Matches).ToList();
            _pendingTitle.Text = "Pending requests " + CountText(pending.Count, cfg.Pending.Count);
            _rulesTitle.Text = "Rules " + CountText(rules.Count, cfg.Rules.Count);
            _emptyPending.Text = cfg.Pending.Count == 0 ? NoPendingText : NoMatchText;
            _emptyRules.Text = cfg.Rules.Count == 0 ? NoRulesText : NoMatchText;

            Rebuild(_pending, SortPending(pending), p => p.AppPath, PendingCells, null, p => NetRanges.IsLan(p.LastRemoteIp) ? Theme.LanRow : (Color?)null);
            var now = DateTime.UtcNow;
            Rebuild(_rules, rules.OrderBy(r => r.DisplayName, StringComparer.OrdinalIgnoreCase), r => r.Id, r => new[]
            {
                r.DisplayName, DecisionText(r), r.ExpiresText(now), HoursText(r), !r.Opens ? "-" : r.KeepInLockdown ? "Allowed" : "Blocked",
                r.Direction == RuleDirection.Both ? "In + Out" : r.Direction.ToString(), r.PortsText, r.NetworkText,
                YesNo(r.Enabled && r.Action == RuleAction.Allow && !r.NoInternet), YesNo(_service.UsesInternet(r.AppPath)), AppSignature.Text(r.AppPath),
                r.Enabled ? "Yes" : "No",
                r.Notes ?? "", r.CreatedUtc.ToLocalTime().ToString("g"), r.AppPath
            }, r => !RuleTranslator.InEffect(r, cfg, DateTime.Now) ? Theme.Closed : r.Action == RuleAction.Block ? Theme.Blocked : Theme.Good);

            ShowHint(_pending, _emptyPending);
            ShowHint(_rules, _emptyRules);
            UpdateButtons();
        }

        private string[] PendingCells(PendingRequest p) => new[]
        {
            p.DisplayName, p.DirectionText, YesNo(_service.UsesInternet(p.AppPath)), AppSignature.Text(p.AppPath), p.LastRemoteIp, IpInfo.HostName(p.LastRemoteIp), IpInfo.CountryText(p.LastRemoteIp), PortText(p.LastSourcePort), PortText(p.LastDestPort), p.LastProtocol ?? "", p.Attempts.ToString(),
            p.FirstSeenUtc.ToLocalTime().ToString("g"), p.AppPath
        };

        /// <summary>Newest first until a column header is clicked. Numbers, addresses and times sort by value, the rest as text.</summary>
        private IEnumerable<PendingRequest> SortPending(List<PendingRequest> rows)
        {
            if (_pendingSort < 0) return rows.OrderByDescending(p => p.LastSeenUtc);
            IComparable Key(PendingRequest p)
            {
                switch (_pendingSort)
                {
                    case 4: return IpKey(p.LastRemoteIp);
                    case 7: return p.LastSourcePort;
                    case 8: return p.LastDestPort;
                    case 10: return p.Attempts;
                    case 11: return p.FirstSeenUtc;
                    default:
                        var cells = PendingCells(p);
                        return _pendingSort < cells.Length ? cells[_pendingSort] ?? "" : "";
                }
            }
            var comparer = Comparer<IComparable>.Create((a, b) => a is string x && b is string y ? StringComparer.OrdinalIgnoreCase.Compare(x, y) : a.CompareTo(b));
            var sorted = _pendingAscending ? rows.OrderBy(Key, comparer) : rows.OrderByDescending(Key, comparer);
            return sorted.ThenByDescending(p => p.LastSeenUtc);
        }

        /// <summary>IPv4 before IPv6, each in numeric order; blank last.</summary>
        private static string IpKey(string ip)
        {
            if (!System.Net.IPAddress.TryParse(ip ?? "", out var a)) return "z";
            if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
            var bytes = a.GetAddressBytes();
            return (bytes.Length == 4 ? "4" : "6") + string.Concat(bytes.Select(b => b.ToString("x2")));
        }

        private void SortPendingBy(int column)
        {
            if (column == _pendingSort) _pendingAscending = !_pendingAscending;
            else
            {
                _pendingSort = column;
                _pendingAscending = column != 10 && column != 11;
            }
            for (var i = 0; i < _pending.Columns.Count; i++)
                _pending.Columns[i].Text = _pendingTitles[i] + (i != _pendingSort ? "" : _pendingAscending ? " ▲" : " ▼");
            RefreshData();
        }

        private static string HoursText(AppRule r) =>
            !r.Opens || !r.HasSchedule ? "Any time" : r.ScheduleText + (r.InSchedule(DateTime.Now) ? "" : " (closed now)");

        private static string DecisionText(AppRule r) =>
            (r.Action == RuleAction.Allow ? "Accept" : "Block") + (r.IsTemporary ? " (temporary)" : " Always");

        private static string PortText(int port) => port > 0 ? port.ToString() : "-";

        private static string YesNo(bool value) => value ? "Yes" : "No";

        private static string CountText(int shown, int total) => shown == total ? $"({total})" : $"({shown} of {total})";

        private static void ShowHint(ListView list, Label hint)
        {
            var empty = list.Items.Count == 0;
            list.Visible = !empty;
            hint.Visible = empty;
        }

        internal static void Rebuild<T>(ListView list, IEnumerable<T> rows, Func<T, string> key, Func<T, string[]> cells, Func<T, Color> color, Func<T, Color?> back = null)
        {
            var items = rows.ToList();
            list.BeginUpdate();
            try
            {
                // Same rows in the same order: change only the cells that differ, so the scroll position, selection and focus stay put.
                if (list.Items.Count == items.Count && items.Select((row, i) => list.Items[i].Name == key(row)).All(same => same))
                {
                    for (var i = 0; i < items.Count; i++)
                    {
                        var item = list.Items[i];
                        item.Tag = items[i];
                        var texts = cells(items[i]);
                        for (var c = 0; c < texts.Length && c < item.SubItems.Count; c++)
                            if (item.SubItems[c].Text != texts[c]) item.SubItems[c].Text = texts[c];
                        if (color != null && item.ForeColor != color(items[i])) item.ForeColor = color(items[i]);
                        if (back != null && item.BackColor != (back(items[i]) ?? list.BackColor)) item.BackColor = back(items[i]) ?? list.BackColor;
                    }
                    return;
                }

                var selected = new HashSet<string>(list.SelectedItems.Cast<ListViewItem>().Select(i => i.Name));
                var top = list.TopItem?.Index ?? 0;
                list.Items.Clear();
                foreach (var row in items)
                {
                    var item = new ListViewItem(cells(row)) { Tag = row, Name = key(row) };
                    if (color != null) item.ForeColor = color(row);
                    if (back?.Invoke(row) is Color b) item.BackColor = b;
                    item.Selected = selected.Contains(item.Name);
                    list.Items.Add(item);
                }
                if (top > 0 && list.Items.Count > 0)
                {
                    try { list.TopItem = list.Items[Math.Min(top, list.Items.Count - 1)]; }
                    catch (NullReferenceException) { }
                }
            }
            finally { list.EndUpdate(); }
        }
    }

    public sealed class RuleEditForm : Form
    {
        private readonly AppRule _original;
        private readonly TextBox _path = new TextBox { Dock = DockStyle.Fill };
        private readonly RadioButton _accept = new RadioButton { Text = "Accept", AutoSize = true, Checked = true };
        private readonly RadioButton _block = new RadioButton { Text = "Block", AutoSize = true };
        private readonly ComboBox _direction = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 160 };
        private readonly CheckBox _enabled = new CheckBox { Text = "Rule is active", AutoSize = true, Checked = true };
        private readonly ComboBox _keep = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 260 };
        private readonly CheckBox _scheduled = new CheckBox { Text = "Only at these times", AutoSize = true, Margin = new Padding(3, 4, 3, 0) };
        private readonly CheckBox[] _days = new[] { "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun" }
            .Select(d => new CheckBox { Text = d, AutoSize = true, Checked = true, Margin = new Padding(0, 2, 6, 0) }).ToArray();
        private readonly DateTimePicker _from = new DateTimePicker { Format = DateTimePickerFormat.Custom, CustomFormat = "HH:mm", ShowUpDown = true, Width = 70 };
        private readonly DateTimePicker _to = new DateTimePicker { Format = DateTimePickerFormat.Custom, CustomFormat = "HH:mm", ShowUpDown = true, Width = 70 };
        private readonly CheckBox _lockdownKeep = new CheckBox { Text = "Keeps working during a lockdown", AutoSize = true };
        /// <summary>Monday first on screen; bits are Sunday first.</summary>
        private static readonly DayOfWeek[] DayOrder = { DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Thursday, DayOfWeek.Friday, DayOfWeek.Saturday, DayOfWeek.Sunday };
        private readonly TextBox _notes = new TextBox { Dock = DockStyle.Fill };
        private readonly TextBox _ports = new TextBox { Dock = DockStyle.Fill };
        private readonly Label _portsHint = new Label { AutoSize = true, ForeColor = Theme.Muted, MaximumSize = new Size(440, 0), Margin = new Padding(3, 0, 3, 6) };
        private readonly CheckBox _internet = new CheckBox { Text = "Allow internet access", AutoSize = true, Checked = true, Margin = new Padding(3, 6, 3, 3) };
        private readonly RadioButton _lanAll = new RadioButton { Text = "All LAN", AutoSize = true, Checked = true };
        private readonly RadioButton _lanSome = new RadioButton { Text = "Only these subnets", AutoSize = true };
        private readonly RadioButton _lanNone = new RadioButton { Text = "No LAN", AutoSize = true };
        private readonly CheckedListBox _subnets = new CheckedListBox { CheckOnClick = true, IntegralHeight = false, Size = new Size(420, 84), Margin = new Padding(3, 0, 3, 3) };
        private readonly TextBox _newSubnet = new TextBox { Width = 170, Margin = new Padding(0, 3, 6, 3) };
        private readonly Button _addSubnet = new Button { Text = "Add subnet", AutoSize = true, Margin = new Padding(0, 1, 0, 1) };
        private readonly Label _networkHint = new Label
        {
            AutoSize = true, ForeColor = Theme.Muted, MaximumSize = new Size(440, 0), Margin = new Padding(3, 0, 3, 6),
            Text = "LAN is the networks of this PC's Ethernet and Wi-Fi adapters, plus link-local, broadcast and multicast so devices can find each other. It follows the network you're on. Internet is every other address, a VPN's included. Applies to Accept only."
        };

        private sealed class SubnetItem
        {
            public string Cidr;
            public string Note;
            public override string ToString() => string.IsNullOrEmpty(Note) ? Cidr : $"{Cidr}   ({Note})";
        }

        public AppRule Result { get; private set; }

        public RuleEditForm(AppRule rule)
        {
            _original = rule;
            Text = rule == null ? "Add rule" : "Edit rule";
            Font = Theme.Base;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            ShowInTaskbar = false;
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96, 96);
            ClientSize = new Size(600, 640);

            _direction.Items.AddRange(new object[] { "In + Out", "Outbound only", "Inbound only" });
            _direction.SelectedIndex = 0;

            var browse = new Button { Text = "Browse...", AutoSize = true, Margin = new Padding(6, 2, 0, 2) };
            browse.Click += (_, __) => Browse();
            var pathRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, AutoSize = true, Margin = Padding.Empty };
            pathRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            pathRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            pathRow.Controls.Add(_path, 0, 0);
            pathRow.Controls.Add(browse, 1, 0);

            var decision = new FlowLayoutPanel { AutoSize = true, Margin = Padding.Empty };
            decision.Controls.Add(_accept);
            decision.Controls.Add(_block);

            var grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, Padding = new Padding(14, 12, 14, 6) };
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            AddRow(grid, "Application", pathRow);
            AddRow(grid, "Decision", decision);
            if (rule?.IsTemporary == true) _keep.Items.Add("As it is: ends " + rule.ExpiresText(DateTime.UtcNow).ToLowerInvariant());
            foreach (var d in RuleDurations.All) _keep.Items.Add(RuleDurations.Text(d));
            _keep.SelectedIndex = 0;
            AddRow(grid, "Keep", _keep);
            var hours = new FlowLayoutPanel { AutoSize = true, Margin = Padding.Empty, WrapContents = true, MaximumSize = new Size(460, 0) };
            hours.Controls.Add(_scheduled);
            hours.SetFlowBreak(_scheduled, true);
            foreach (var d in _days) hours.Controls.Add(d);
            hours.Controls.Add(new Label { Text = "from", AutoSize = true, Margin = new Padding(0, 6, 4, 0) });
            hours.Controls.Add(_from);
            hours.Controls.Add(new Label { Text = "to", AutoSize = true, Margin = new Padding(6, 6, 4, 0) });
            hours.Controls.Add(_to);
            hours.Controls.Add(new Label { Text = "Outside these times the app is blocked. A \"to\" before \"from\" runs past midnight.", AutoSize = true, ForeColor = Theme.Muted, MaximumSize = new Size(440, 0), Margin = new Padding(3, 4, 3, 2) });
            AddRow(grid, "Hours", hours);
            AddRow(grid, "Lockdown", _lockdownKeep);
            _from.Value = DateTime.Today.AddHours(8);
            _to.Value = DateTime.Today.AddHours(22);
            void SyncHours()
            {
                var opens = _accept.Checked || !string.IsNullOrWhiteSpace(_ports.Text);
                _scheduled.Enabled = _lockdownKeep.Enabled = opens;
                foreach (var d in _days) d.Enabled = opens && _scheduled.Checked;
                _from.Enabled = _to.Enabled = opens && _scheduled.Checked;
            }
            _scheduled.CheckedChanged += (_, __) => SyncHours();
            _accept.CheckedChanged += (_, __) => SyncHours();
            _ports.TextChanged += (_, __) => SyncHours();
            Shown += (_, __) => SyncHours();
            AddRow(grid, "Direction", _direction);
            AddRow(grid, "Ports", _ports);
            AddRow(grid, "", _portsHint);
            AddRow(grid, "Internet", _internet);
            AddRow(grid, "LAN", NetworkChoices());
            AddRow(grid, "", _networkHint);
            AddRow(grid, "", _enabled);
            AddRow(grid, "Notes", _notes);

            var ok = new Button { Text = "Save", AutoSize = true, Margin = new Padding(6, 0, 0, 0) };
            var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, AutoSize = true, Margin = new Padding(6, 0, 0, 0) };
            ok.Click += (_, __) => Save();
            AcceptButton = ok;
            CancelButton = cancel;
            var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(14, 6, 14, 12) };
            buttons.Controls.Add(cancel);
            buttons.Controls.Add(ok);

            Controls.Add(grid);
            Controls.Add(buttons);

            if (rule != null)
            {
                _path.Text = rule.AppPath;
                _accept.Checked = rule.Action == RuleAction.Allow;
                _block.Checked = rule.Action == RuleAction.Block;
                _direction.SelectedIndex = (int)rule.Direction;
                _enabled.Checked = rule.Enabled;
                _lockdownKeep.Checked = rule.KeepInLockdown;
                if (rule.HasSchedule)
                {
                    _scheduled.Checked = true;
                    for (var i = 0; i < 7; i++) _days[i].Checked = (rule.ScheduleDays & (1 << (int)DayOrder[i])) != 0;
                    _from.Value = DateTime.Today.AddMinutes(rule.ScheduleFrom);
                    _to.Value = DateTime.Today.AddMinutes(rule.ScheduleTo);
                }
                _notes.Text = rule.Notes;
                _ports.Text = rule.Ports;
                _internet.Checked = !rule.NoInternet;
                _lanSome.Checked = rule.Lan == LanAccess.Selected;
                _lanNone.Checked = rule.Lan == LanAccess.None;
                _lanAll.Checked = rule.Lan == LanAccess.All;
            }
            FillSubnets(rule?.Lan == LanAccess.Selected ? rule.LanSubnets : null);
            _accept.CheckedChanged += (_, __) => UpdatePortsHint();
            foreach (var r in new[] { _lanAll, _lanSome, _lanNone }) r.CheckedChanged += (_, __) => UpdateNetwork();
            _addSubnet.Click += (_, __) => AddSubnet();
            UpdatePortsHint();
        }

        private Control NetworkChoices()
        {
            var choices = new FlowLayoutPanel { AutoSize = true, Margin = Padding.Empty, WrapContents = false };
            choices.Controls.AddRange(new Control[] { _lanAll, _lanSome, _lanNone });
            var add = new FlowLayoutPanel { AutoSize = true, Margin = Padding.Empty, WrapContents = false };
            add.Controls.Add(_newSubnet);
            add.Controls.Add(_addSubnet);
            var panel = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, AutoSize = true, Margin = Padding.Empty };
            panel.Controls.Add(choices, 0, 0);
            panel.Controls.Add(_subnets, 0, 1);
            panel.Controls.Add(add, 0, 2);
            return panel;
        }

        /// <summary>This PC's subnets, plus any the rule has that aren't connected right now, so they aren't lost on save.</summary>
        private void FillSubnets(IEnumerable<string> chosen)
        {
            var wanted = new HashSet<string>(chosen ?? Enumerable.Empty<string>());
            foreach (var (cidr, adapter) in NetRanges.LocalSubnets())
                _subnets.Items.Add(new SubnetItem { Cidr = cidr, Note = adapter }, wanted.Remove(cidr));
            foreach (var cidr in wanted)
                _subnets.Items.Add(new SubnetItem { Cidr = cidr, Note = "not connected now" }, true);
        }

        private void AddSubnet()
        {
            if (!NetRanges.TryNormalize(_newSubnet.Text, out var cidr))
            {
                MessageBox.Show(this, "Enter a subnet like 192.168.1.0/24, or a single address like 192.168.1.20.", Text);
                return;
            }
            var existing = _subnets.Items.Cast<SubnetItem>().ToList().FindIndex(i => i.Cidr == cidr);
            if (existing >= 0) _subnets.SetItemChecked(existing, true);
            else _subnets.Items.Add(new SubnetItem { Cidr = cidr, Note = "added" }, true);
            _newSubnet.Clear();
        }

        private void UpdateNetwork()
        {
            var accept = _accept.Checked;
            _internet.Enabled = _lanAll.Enabled = _lanSome.Enabled = _lanNone.Enabled = accept;
            _subnets.Enabled = _newSubnet.Enabled = _addSubnet.Enabled = accept && _lanSome.Checked;
        }

        private void UpdatePortsHint()
        {
            _portsHint.Text = _accept.Checked
                ? "Empty means all ports. With ports, the app can use only those. Example: 80, 443, 8000-8100"
                : "Empty means all ports are blocked. With ports, only those are blocked and the app can use all others.";
            UpdateNetwork();
        }

        private static void AddRow(TableLayoutPanel grid, string label, Control control)
        {
            var row = grid.RowCount++;
            grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            grid.Controls.Add(new Label { Text = label, AutoSize = true, Margin = new Padding(0, 7, 12, 3) }, 0, row);
            grid.Controls.Add(control, 1, row);
        }

        private void Browse()
        {
            using var dialog = new OpenFileDialog { Filter = "Programs (*.exe)|*.exe|All files (*.*)|*.*", Title = "Choose an application" };
            if (dialog.ShowDialog(this) == DialogResult.OK) _path.Text = dialog.FileName;
        }

        private void Save()
        {
            var path = AppPaths.Normalize(_path.Text);
            if (!AppPaths.IsRuleTarget(path))
            {
                MessageBox.Show(this, "Enter the full path of a program, for example C:\\Program Files\\App\\app.exe.", Text);
                return;
            }
            string ports;
            try { ports = PortList.Normalize(_ports.Text); }
            catch (FormatException ex)
            {
                MessageBox.Show(this, ex.Message, Text);
                return;
            }
            if (ports != null && path == AppPaths.PingApp)
            {
                MessageBox.Show(this, "Pings don't use ports, so leave Ports empty for this rule.", Text);
                return;
            }
            if (!AppPaths.IsPseudoApp(path) && !File.Exists(path)
                && MessageBox.Show(this, "That file doesn't exist right now. Save the rule anyway?", Text, MessageBoxButtons.YesNo) != DialogResult.Yes)
                return;

            Result = _original?.Clone() ?? new AppRule();
            Result.AppPath = path;
            Result.Action = _block.Checked ? RuleAction.Block : RuleAction.Allow;
            Result.Direction = (RuleDirection)_direction.SelectedIndex;
            Result.Enabled = _enabled.Checked;
            Result.KeepInLockdown = _lockdownKeep.Checked;
            Result.ScheduleDays = 0;
            if (_scheduled.Checked && _scheduled.Enabled)
            {
                var days = 0;
                for (var i = 0; i < 7; i++) if (_days[i].Checked) days |= 1 << (int)DayOrder[i];
                var from = _from.Value.Hour * 60 + _from.Value.Minute;
                var to = _to.Value.Hour * 60 + _to.Value.Minute;
                if (days == 0) { MessageBox.Show(this, "Tick at least one day, or untick \"Only at these times\".", Text); return; }
                if (from == to) { MessageBox.Show(this, "The start and end times are the same. Pick a range of time.", Text); return; }
                Result.ScheduleDays = days;
                Result.ScheduleFrom = from;
                Result.ScheduleTo = to;
            }
            var keepAsIs = _original?.IsTemporary == true && _keep.SelectedIndex == 0;
            if (!keepAsIs)
                Result.SetDuration(RuleDurations.All[_keep.SelectedIndex - (_original?.IsTemporary == true ? 1 : 0)], DateTime.UtcNow, SystemBoot.Utc());
            Result.Notes = _notes.Text.Trim();
            Result.Ports = ports;
            Result.NoInternet = !_internet.Checked;
            Result.Lan = _lanSome.Checked ? LanAccess.Selected : _lanNone.Checked ? LanAccess.None : LanAccess.All;
            Result.LanSubnets = _subnets.CheckedItems.Cast<SubnetItem>().Select(i => i.Cidr).ToList();
            try { Result.NormalizeNetwork(); }
            catch (FormatException ex)
            {
                MessageBox.Show(this, ex.Message, Text);
                return;
            }
            DialogResult = DialogResult.OK;
        }
    }
}
