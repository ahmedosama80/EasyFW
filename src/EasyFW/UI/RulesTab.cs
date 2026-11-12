using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using EasyFW.Core;

namespace EasyFW.UI
{
    public sealed class RulesTab : UserControl
    {
        private readonly FirewallService _service;
        private readonly Func<string, RuleAction, string, Task> _decide;
        private readonly ListView _pending = NewList(("Application", 170), ("Wants", 84), ("Remote IP", 130), ("Remote Host", 170), ("Country", 130), ("Src Port", 62), ("Dest Port", 66), ("Proto", 60), ("Attempts", 66), ("First seen", 130), ("Path", 360));
        private readonly ListView _rules = NewList(("Application", 170), ("Decision", 110), ("Direction", 80), ("Ports", 130), ("Network", 150), ("Enabled", 62), ("Notes", 200), ("Created", 130), ("Path", 300));
        private readonly Button _accept = ActionButton("Accept Always");
        private readonly Button _block = ActionButton("Block Always");
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

        public RulesTab(FirewallService service, Func<string, RuleAction, string, Task> decide)
        {
            _service = service;
            _decide = decide;

            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Padding = new Padding(8, 4, 8, 8) };
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            layout.Controls.Add(Toolbar(_pendingTitle, _accept, _block, _acceptPorts, _blockPorts, _dismiss,
                FilterGroup(UiHelpers.BarLabel("Search"), _pendingSearch, UiHelpers.BarLabel("Wants"), _pendingDirection, UiHelpers.BarLabel("Protocol"), _pendingProtocol)), 0, 0);
            layout.Controls.Add(WithHint(_pending, _emptyPending), 0, 1);
            layout.Controls.Add(Toolbar(_rulesTitle, _add, _edit, _delete, _export, _import,
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
            _pending.ContextMenuStrip = BuildPendingMenu();
            Flags.ShowInColumn(_pending, 4, 2);
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
            var copy = new ToolStripMenuItem("Copy row");
            copy.Click += (_, __) => UiHelpers.CopyRows(FindForm(),
                _pending.SelectedItems.Cast<ListViewItem>().Select(i => i.SubItems.Cast<ListViewItem.ListViewSubItem>().Select(c => c.Text)));
            menu.Items.Add(copy);
            menu.Opening += (_, e) =>
            {
                if (_pending.SelectedItems.Count == 0) e.Cancel = true;
                copy.Text = UiHelpers.CopyLabel(_pending.SelectedItems.Count);
            };
            return menu;
        }

        private List<PendingRequest> SelectedPending() => _pending.SelectedItems.Cast<ListViewItem>().Select(i => (PendingRequest)i.Tag).ToList();

        private List<AppRule> SelectedRules() => _rules.SelectedItems.Cast<ListViewItem>().Select(i => (AppRule)i.Tag).ToList();

        private async Task DecidePending(RuleAction action)
        {
            foreach (var p in SelectedPending()) await _decide(p.AppPath, action, null);
        }

        private async Task DecidePendingPorts(RuleAction action)
        {
            var selected = SelectedPending();
            if (selected.Count == 0) return;
            var name = selected.Count == 1 ? selected[0].DisplayName : $"These {selected.Count} apps";
            using var form = new PortsForm(name, action, selected.Count == 1 && selected[0].LastDestPort > 0 ? selected[0].LastDestPort.ToString() : "");
            if (form.ShowDialog(FindForm()) != DialogResult.OK) return;
            foreach (var p in selected) await _decide(p.AppPath, action, form.Ports);
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
            if (!_service.CanChange) return;
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
            if (!_service.CanChange) return;
            using var form = new RuleEditForm(rule);
            if (form.ShowDialog(FindForm()) != DialogResult.OK) return;
            try { await _service.SaveRuleAsync(form.Result); }
            catch (Exception ex) { Fail(ex); }
        }

        private async Task DeleteSelected()
        {
            var rules = SelectedRules();
            if (rules.Count == 0) return;
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
            if (IpInfo.Version != _infoVersion) RefreshData();
        }

        public void RefreshData()
        {
            _infoVersion = IpInfo.Version;
            var cfg = _service.Config;
            var pendingFilter = CurrentPendingFilter();
            var ruleFilter = CurrentRuleFilter();
            var pending = cfg.Pending.Where(pendingFilter.Matches).ToList();
            var rules = cfg.Rules.Where(ruleFilter.Matches).ToList();
            _pendingTitle.Text = "Pending requests " + CountText(pending.Count, cfg.Pending.Count);
            _rulesTitle.Text = "Permanent rules " + CountText(rules.Count, cfg.Rules.Count);
            _emptyPending.Text = cfg.Pending.Count == 0 ? NoPendingText : NoMatchText;
            _emptyRules.Text = cfg.Rules.Count == 0 ? NoRulesText : NoMatchText;

            Rebuild(_pending, pending.OrderByDescending(p => p.LastSeenUtc), p => p.AppPath, p => new[]
            {
                p.DisplayName, p.DirectionText, p.LastRemoteIp, IpInfo.HostName(p.LastRemoteIp), IpInfo.CountryText(p.LastRemoteIp), PortText(p.LastSourcePort), PortText(p.LastDestPort), p.LastProtocol ?? "", p.Attempts.ToString(),
                p.FirstSeenUtc.ToLocalTime().ToString("g"), p.AppPath
            }, null);
            Rebuild(_rules, rules.OrderBy(r => r.DisplayName, StringComparer.OrdinalIgnoreCase), r => r.Id, r => new[]
            {
                r.DisplayName, r.Action == RuleAction.Allow ? "Accept Always" : "Block Always",
                r.Direction == RuleDirection.Both ? "In + Out" : r.Direction.ToString(), r.PortsText, r.NetworkText, r.Enabled ? "Yes" : "No",
                r.Notes ?? "", r.CreatedUtc.ToLocalTime().ToString("g"), r.AppPath
            }, r => !r.Enabled ? Theme.Closed : r.Action == RuleAction.Block ? Theme.Blocked : Theme.Good);

            ShowHint(_pending, _emptyPending);
            ShowHint(_rules, _emptyRules);
            UpdateButtons();
        }

        private static string PortText(int port) => port > 0 ? port.ToString() : "-";

        private static string CountText(int shown, int total) => shown == total ? $"({total})" : $"({shown} of {total})";

        private static void ShowHint(ListView list, Label hint)
        {
            var empty = list.Items.Count == 0;
            list.Visible = !empty;
            hint.Visible = empty;
        }

        private static void Rebuild<T>(ListView list, IEnumerable<T> rows, Func<T, string> key, Func<T, string[]> cells, Func<T, Color> color)
        {
            var selected = new HashSet<string>(list.SelectedItems.Cast<ListViewItem>().Select(i => i.Name));
            list.BeginUpdate();
            try
            {
                list.Items.Clear();
                foreach (var row in rows)
                {
                    var item = new ListViewItem(cells(row)) { Tag = row, Name = key(row) };
                    if (color != null) item.ForeColor = color(row);
                    item.Selected = selected.Contains(item.Name);
                    list.Items.Add(item);
                }
            }
            finally { list.EndUpdate(); }
        }
    }

    public sealed class RuleEditForm : Form
    {
        private readonly AppRule _original;
        private readonly TextBox _path = new TextBox { Dock = DockStyle.Fill };
        private readonly RadioButton _accept = new RadioButton { Text = "Accept Always", AutoSize = true, Checked = true };
        private readonly RadioButton _block = new RadioButton { Text = "Block Always", AutoSize = true };
        private readonly ComboBox _direction = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 160 };
        private readonly CheckBox _enabled = new CheckBox { Text = "Rule is active", AutoSize = true, Checked = true };
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
            Text = "LAN is private and link-local addresses (10.x, 172.16-31.x, 192.168.x), plus local broadcast and multicast so devices can find each other. Internet is every other address. Applies to Accept Always only."
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
            ClientSize = new Size(580, 520);

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
