using System;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;
using EasyFW.Core;

namespace EasyFW.UI
{
    /// <summary>Lists the path and keyword rules, which decide for every matching app that has no rule of its own.</summary>
    public sealed class PatternsForm : Form
    {
        private readonly FirewallService _service;
        private readonly ListView _list = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, HideSelection = false };
        private readonly Button _add = new Button { Text = "Add...", AutoSize = true, Margin = new Padding(0, 0, 6, 0) };
        private readonly Button _edit = new Button { Text = "Edit...", AutoSize = true, Margin = new Padding(0, 0, 6, 0) };
        private readonly Button _delete = new Button { Text = "Delete", AutoSize = true, Margin = new Padding(0, 0, 6, 0) };

        public PatternsForm(FirewallService service)
        {
            _service = service;
            Text = "Path and keyword rules";
            Font = Theme.Base;
            StartPosition = FormStartPosition.CenterParent;
            ShowInTaskbar = false;
            MinimizeBox = false;
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96, 96);
            ClientSize = new Size(820, 420);

            foreach (var (title, width) in new[] { ("Pattern", 260), ("Kind", 90), ("Decision", 130), ("Enabled", 62), ("Matches now", 90), ("Notes", 190) })
                _list.Columns.Add(title, width);
            UiHelpers.EnableDoubleBuffer(_list);
            UiHelpers.ShowFullTextOnHover(_list);
            UiHelpers.RememberColumns(_list, "patterns", _service);

            var intro = new Label
            {
                Dock = DockStyle.Top, AutoSize = false, Height = 82, Padding = new Padding(10, 8, 10, 4), ForeColor = Theme.Muted,
                Text = "One rule for many apps. C:\\Games\\*.* covers every program in C:\\Games and its subfolders. A word with no \\ or *, such as steam, " +
                       "matches any app with that word in its path. An app with its own rule keeps it. A matching app gets its own rule the first time it " +
                       "tries to connect, so with Accept that first try is still blocked. Accept only applies to apps with a valid digital signature: " +
                       "an unsigned app stays in Pending requests for you to decide."
            };
            var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
            CancelButton = close;
            var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, Padding = new Padding(10, 8, 10, 10) };
            buttons.Controls.AddRange(new Control[] { _add, _edit, _delete });
            var right = new FlowLayoutPanel { Dock = DockStyle.Right, AutoSize = true, Padding = new Padding(0, 8, 10, 10), FlowDirection = FlowDirection.RightToLeft };
            right.Controls.Add(close);
            var bottom = new Panel { Dock = DockStyle.Bottom, Height = 46 };
            bottom.Controls.Add(buttons);
            bottom.Controls.Add(right);
            buttons.Dock = DockStyle.Fill;

            var host = new Panel { Dock = DockStyle.Fill, Padding = new Padding(10, 0, 10, 0) };
            host.Controls.Add(_list);
            Controls.Add(host);
            Controls.Add(intro);
            Controls.Add(bottom);

            _add.Click += (_, __) => Edit(null);
            _edit.Click += (_, __) => Edit(Selected);
            _list.DoubleClick += (_, __) => Edit(Selected);
            _delete.Click += (_, __) => Delete();
            _list.SelectedIndexChanged += (_, __) => UpdateButtons();
            var menu = new ContextMenuStrip();
            menu.Items.Add("Copy pattern", null, (_, __) =>
                UiHelpers.CopyPaths(this, _list.SelectedItems.Cast<ListViewItem>().Select(i => ((PatternRule)i.Tag).Pattern)));
            menu.Opening += (_, e) => e.Cancel = _list.SelectedItems.Count == 0;
            _list.ContextMenuStrip = menu;
            RefreshList();
        }

        private PatternRule Selected => _list.SelectedItems.Count > 0 ? (PatternRule)_list.SelectedItems[0].Tag : null;

        private void UpdateButtons()
        {
            _add.Enabled = _service.CanChange;
            _edit.Enabled = _delete.Enabled = _service.CanChange && _list.SelectedItems.Count == 1;
        }

        private void RefreshList()
        {
            var keep = Selected?.Id;
            _list.BeginUpdate();
            try
            {
                _list.Items.Clear();
                foreach (var p in _service.Config.Patterns.OrderBy(p => p.Pattern, StringComparer.OrdinalIgnoreCase))
                {
                    var item = new ListViewItem(new[]
                    {
                        p.Pattern, p.KindText, p.Action == RuleAction.Allow ? "Accept (signed only)" : "Block Always", p.Enabled ? "Yes" : "No",
                        _service.PatternPreview(p).Count.ToString(), p.Notes ?? ""
                    }) { Tag = p, ForeColor = !p.Enabled ? Theme.Closed : p.Action == RuleAction.Block ? Theme.Blocked : Theme.Good };
                    item.Selected = p.Id == keep;
                    _list.Items.Add(item);
                }
            }
            finally { _list.EndUpdate(); }
            UpdateButtons();
        }

        private void Edit(PatternRule pattern)
        {
            if (!_service.CanChange) return;
            using var form = new PatternEditForm(_service, pattern);
            if (form.ShowDialog(this) != DialogResult.OK) return;
            RefreshList();
        }

        private void Delete()
        {
            var p = Selected;
            if (p == null) return;
            if (MessageBox.Show(this, $"Delete the rule for {p.Pattern}? Rules it already gave to apps stay; delete those in the rules list if you want.",
                    Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            _service.DeletePattern(p);
            RefreshList();
        }
    }

    public sealed class PatternEditForm : Form
    {
        private readonly FirewallService _service;
        private readonly PatternRule _original;
        private readonly TextBox _pattern = new TextBox { Dock = DockStyle.Fill };
        private readonly RadioButton _accept = new RadioButton { Text = "Accept Always (signed apps only)", AutoSize = true };
        private readonly RadioButton _block = new RadioButton { Text = "Block Always", AutoSize = true, Checked = true };
        private readonly CheckBox _enabled = new CheckBox { Text = "Rule is active", AutoSize = true, Checked = true };
        private readonly TextBox _notes = new TextBox { Dock = DockStyle.Fill };
        private readonly Label _signedNote = new Label
        {
            AutoSize = true, ForeColor = Theme.Muted, MaximumSize = new Size(440, 0), Margin = new Padding(3, 0, 3, 6),
            Text = "Accept is given only to apps with a valid digital signature (Signed column: Yes). An unsigned or broken-signature app stays in Pending requests for you to decide. Block applies to every matching app."
        };
        private readonly Label _preview = new Label { AutoSize = true, ForeColor = Theme.Muted, MaximumSize = new Size(440, 0), Margin = new Padding(3, 0, 3, 6) };

        public PatternEditForm(FirewallService service, PatternRule pattern)
        {
            _service = service;
            _original = pattern;
            Text = pattern == null ? "Add path or keyword rule" : "Edit path or keyword rule";
            Font = Theme.Base;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            ShowInTaskbar = false;
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96, 96);
            ClientSize = new Size(580, 380);

            var browse = new Button { Text = "Folder...", AutoSize = true, Margin = new Padding(6, 2, 0, 2) };
            browse.Click += (_, __) => Browse();
            var row = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, AutoSize = true, Margin = Padding.Empty };
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            row.Controls.Add(_pattern, 0, 0);
            row.Controls.Add(browse, 1, 0);

            var decision = new FlowLayoutPanel { AutoSize = true, Margin = Padding.Empty };
            decision.Controls.Add(_accept);
            decision.Controls.Add(_block);

            var hint = new Label
            {
                AutoSize = true, ForeColor = Theme.Muted, MaximumSize = new Size(440, 0), Margin = new Padding(3, 0, 3, 6),
                Text = "Examples: C:\\Games\\*.*   ·   C:\\Tools\\*\\updater.exe   ·   *\\Temp\\*   ·   steam (a keyword: any path containing it). * is any text, ? is one character."
            };

            var grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, Padding = new Padding(14, 12, 14, 6) };
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            AddRow(grid, "Path or keyword", row);
            AddRow(grid, "", hint);
            AddRow(grid, "Decision", decision);
            AddRow(grid, "", _signedNote);
            AddRow(grid, "", _enabled);
            AddRow(grid, "Notes", _notes);
            AddRow(grid, "Matches now", _preview);

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

            if (pattern != null)
            {
                _pattern.Text = pattern.Pattern;
                _accept.Checked = pattern.Action == RuleAction.Allow;
                _block.Checked = pattern.Action == RuleAction.Block;
                _enabled.Checked = pattern.Enabled;
                _notes.Text = pattern.Notes;
            }
            _pattern.TextChanged += (_, __) => UpdatePreview();
            UpdatePreview();
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
            using var dialog = new FolderBrowserDialog { Description = "Choose a folder. Every program in it and its subfolders will match." };
            if (dialog.ShowDialog(this) == DialogResult.OK) _pattern.Text = dialog.SelectedPath.TrimEnd('\\') + "\\*.*";
        }

        private void UpdatePreview()
        {
            var text = _pattern.Text.Trim();
            if (text.Length == 0)
            {
                _preview.Text = "-";
                return;
            }
            var apps = _service.PatternPreview(new PatternRule { Pattern = text });
            var kind = PatternRule.IsKeywordText(text) ? "Keyword. " : "";
            _preview.Text = apps.Count == 0
                ? kind + "No app seen so far matches. It still applies to apps that connect later."
                : kind + $"{apps.Count} app(s) seen so far: " + string.Join(", ", apps.Take(6).Select(AppPaths.DisplayName)) + (apps.Count > 6 ? ", ..." : "") +
                  ". Apps that already have a rule keep it.";
        }

        private void Save()
        {
            var result = _original?.Clone() ?? new PatternRule();
            result.Pattern = _pattern.Text;
            result.Action = _accept.Checked ? RuleAction.Allow : RuleAction.Block;
            result.Enabled = _enabled.Checked;
            result.Notes = _notes.Text.Trim();
            try { _service.SavePattern(result); }
            catch (ArgumentException ex)
            {
                MessageBox.Show(this, ex.Message, Text);
                return;
            }
            DialogResult = DialogResult.OK;
        }
    }
}
