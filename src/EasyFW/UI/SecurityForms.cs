using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using EasyFW.Core;

namespace EasyFW.UI
{
    /// <summary>
    /// Asks for the password before a change, when one is set. A right answer is good for 5 minutes, so a run of changes asks once.
    /// It guards EasyFW's own window: someone with administrator rights can still change Windows Firewall directly.
    /// </summary>
    public static class Guard
    {
        private static DateTime _unlockedUntil;

        public static FirewallService Service { get; set; }

        /// <summary>Off in tests, so nothing waits for typing.</summary>
        public static bool Prompt { get; set; } = true;

        /// <param name="action">What needs the password, as a phrase: "Turning protection off".</param>
        public static bool Unlock(IWin32Window owner, string action)
        {
            var s = Service;
            if (s == null || !s.HasPassword || DateTime.UtcNow < _unlockedUntil) return true;
            if (!Prompt) return false;
            using var form = new PasswordPromptForm(action, s);
            if (form.ShowDialog(owner) != DialogResult.OK) return false;
            _unlockedUntil = DateTime.UtcNow.AddMinutes(5);
            return true;
        }

        public static void Lock() => _unlockedUntil = DateTime.MinValue;
    }

    internal static class DialogStyle
    {
        public static void Apply(Form f, string title)
        {
            f.Text = title;
            f.Font = Theme.Base;
            f.FormBorderStyle = FormBorderStyle.FixedDialog;
            f.MaximizeBox = f.MinimizeBox = false;
            f.ShowInTaskbar = false;
            f.StartPosition = FormStartPosition.CenterParent;
            f.AutoScaleMode = AutoScaleMode.Dpi;
            f.AutoScaleDimensions = new SizeF(96, 96);
            f.Icon = IconFactory.Tray(IconFactory.TrayState.On);
        }

        public static FlowLayoutPanel Buttons(params Button[] buttons)
        {
            var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(12, 6, 12, 12) };
            bar.Controls.AddRange(buttons);
            return bar;
        }

        public static Label Text(string text, int width = 440) =>
            new Label { Text = text, AutoSize = true, MaximumSize = new Size(width, 0), Margin = new Padding(3, 0, 3, 8) };
    }

    public sealed class PasswordPromptForm : Form
    {
        private readonly TextBox _password = new TextBox { UseSystemPasswordChar = true, Width = 260 };
        private readonly Label _error = new Label { AutoSize = true, ForeColor = Theme.Off };
        private int _fails;

        public PasswordPromptForm(string action, FirewallService service)
        {
            DialogStyle.Apply(this, "EasyFW password");
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            var layout = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, Padding = new Padding(14), WrapContents = false };
            layout.Controls.Add(new Label { Text = action + " needs the EasyFW password.", AutoSize = true, Font = Theme.Heading, Margin = new Padding(3, 0, 3, 8) });
            layout.Controls.Add(_password);
            layout.Controls.Add(_error);
            var ok = new Button { Text = "OK", AutoSize = true };
            var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, AutoSize = true };
            var buttons = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Anchor = AnchorStyles.Right, Margin = new Padding(0, 8, 0, 0) };
            buttons.Controls.Add(cancel);
            buttons.Controls.Add(ok);
            layout.Controls.Add(buttons);
            Controls.Add(layout);
            AcceptButton = ok;
            CancelButton = cancel;
            ok.Click += async (_, __) =>
            {
                if (service.CheckPassword(_password.Text))
                {
                    DialogResult = DialogResult.OK;
                    return;
                }
                _fails++;
                Log.Write("Wrong EasyFW password entered.");
                _password.SelectAll();
                if (_fails >= 5)
                {
                    // Slows down guessing.
                    ok.Enabled = false;
                    _error.Text = "Wrong password. Wait 30 seconds and try again.";
                    await Task.Delay(30000);
                    if (IsDisposed) return;
                    ok.Enabled = true;
                    _fails = 0;
                }
                _error.Text = "That password isn't right.";
            };
        }
    }

    /// <summary>Sets, changes or removes the password. Changing or removing one needs the current one.</summary>
    public sealed class PasswordSetForm : Form
    {
        private readonly TextBox _current = new TextBox { UseSystemPasswordChar = true, Width = 240 };
        private readonly TextBox _new = new TextBox { UseSystemPasswordChar = true, Width = 240 };
        private readonly TextBox _confirm = new TextBox { UseSystemPasswordChar = true, Width = 240 };
        private readonly Label _error = new Label { AutoSize = true, ForeColor = Theme.Off, MaximumSize = new Size(420, 0) };

        public PasswordSetForm(FirewallService service)
        {
            DialogStyle.Apply(this, "Password protection");
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            var has = service.HasPassword;
            var grid = new TableLayoutPanel { AutoSize = true, ColumnCount = 2, Padding = new Padding(14) };
            var intro = DialogStyle.Text(
                "With a password, EasyFW asks for it before protection is turned off, before EasyFW exits, before any rule or option changes, " +
                "and before a lockdown ends or a country is unblocked. It's good for 5 minutes after you type it.\n\n" +
                "It protects EasyFW's window. Someone with administrator rights can still change Windows Firewall directly.\n\n" +
                $"If you forget it, delete the \"PasswordHash\" line from {ConfigStore.DefaultFolder}\\config.json as an administrator, then restart EasyFW.");
            grid.Controls.Add(intro, 0, 0);
            grid.SetColumnSpan(intro, 2);
            var row = 1;
            void Add(string label, Control c)
            {
                grid.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left }, 0, row);
                grid.Controls.Add(c, 1, row++);
            }
            if (has) Add("Current password", _current);
            Add("New password", _new);
            Add("Type it again", _confirm);
            grid.Controls.Add(_error, 1, row++);

            var save = new Button { Text = has ? "Change" : "Set password", AutoSize = true };
            var remove = new Button { Text = "Remove password", AutoSize = true, Visible = has };
            var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, AutoSize = true };
            var buttons = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Anchor = AnchorStyles.Right, Margin = new Padding(0, 8, 0, 0) };
            buttons.Controls.Add(cancel);
            buttons.Controls.Add(save);
            buttons.Controls.Add(remove);
            grid.Controls.Add(buttons, 0, row);
            grid.SetColumnSpan(buttons, 2);
            Controls.Add(grid);
            AcceptButton = save;
            CancelButton = cancel;

            bool CurrentOk()
            {
                if (!has || service.CheckPassword(_current.Text)) return true;
                _error.Text = "The current password isn't right.";
                return false;
            }
            save.Click += (_, __) =>
            {
                if (!CurrentOk()) return;
                if (_new.Text.Length < 4) { _error.Text = "Use at least 4 characters."; return; }
                if (_new.Text != _confirm.Text) { _error.Text = "The two new passwords aren't the same."; return; }
                service.SetPassword(_new.Text);
                Guard.Lock();
                DialogResult = DialogResult.OK;
            };
            remove.Click += (_, __) =>
            {
                if (!CurrentOk()) return;
                service.SetPassword(null);
                DialogResult = DialogResult.OK;
            };
        }
    }

    /// <summary>Picks the countries to block for every app.</summary>
    public sealed class CountryBlockForm : Form
    {
        private readonly TextBox _search = new TextBox { Width = 220 };
        private readonly CheckedListBox _list = new CheckedListBox { CheckOnClick = true, IntegralHeight = false, Size = new Size(420, 320) };
        private readonly Label _count = new Label { AutoSize = true, ForeColor = Theme.Muted };
        private readonly HashSet<string> _chosen;
        private bool _filling;

        private sealed class Item
        {
            public string Code, Name;
            public override string ToString() => $"{Name} ({Code})";
        }

        private readonly List<Item> _all;

        public List<string> Chosen => _chosen.OrderBy(c => c).ToList();

        public CountryBlockForm(IEnumerable<string> blocked)
        {
            DialogStyle.Apply(this, "Blocked countries");
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            _chosen = new HashSet<string>(blocked, StringComparer.OrdinalIgnoreCase);
            _all = WorldGeo.Countries.Select(c => new Item { Code = c.ToUpperInvariant(), Name = IpInfo.CountryName(c) })
                .OrderBy(i => i.Name, StringComparer.CurrentCultureIgnoreCase).ToList();

            var layout = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, Padding = new Padding(14), WrapContents = false };
            layout.Controls.Add(DialogStyle.Text(
                "Tick a country to block all traffic to and from it, in and out, for every app, including apps you accepted. " +
                "Open connections to it are closed. Countries come from the DB-IP list beside EasyFW, so a few addresses can be placed wrongly."));
            var searchRow = new FlowLayoutPanel { AutoSize = true, Margin = new Padding(0, 0, 0, 4) };
            searchRow.Controls.Add(new Label { Text = "Search", AutoSize = true, Margin = new Padding(3, 6, 6, 0) });
            searchRow.Controls.Add(_search);
            layout.Controls.Add(searchRow);
            layout.Controls.Add(_list);
            layout.Controls.Add(_count);
            var save = new Button { Text = "Save", DialogResult = DialogResult.OK, AutoSize = true };
            var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, AutoSize = true };
            var buttons = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Anchor = AnchorStyles.Right, Margin = new Padding(0, 8, 0, 0) };
            buttons.Controls.Add(cancel);
            buttons.Controls.Add(save);
            layout.Controls.Add(buttons);
            Controls.Add(layout);
            AcceptButton = save;
            CancelButton = cancel;

            _list.ItemCheck += (_, e) =>
            {
                if (_filling) return;
                var item = (Item)_list.Items[e.Index];
                if (e.NewValue == CheckState.Checked) _chosen.Add(item.Code); else _chosen.Remove(item.Code);
                BeginInvoke((Action)ShowCount);
            };
            _search.TextChanged += (_, __) => Fill();
            Fill();
        }

        private void Fill()
        {
            _filling = true;
            _list.BeginUpdate();
            _list.Items.Clear();
            var text = _search.Text.Trim();
            // Ticked countries first, so they're easy to find and untick.
            foreach (var item in _all.Where(i => text.Length == 0 || i.Name.IndexOf(text, StringComparison.CurrentCultureIgnoreCase) >= 0 || i.Code.Equals(text, StringComparison.OrdinalIgnoreCase))
                         .OrderBy(i => _chosen.Contains(i.Code) ? 0 : 1))
                _list.Items.Add(item, _chosen.Contains(item.Code));
            _list.EndUpdate();
            _filling = false;
            ShowCount();
        }

        private void ShowCount() =>
            _count.Text = _chosen.Count == 0 ? "No countries blocked." : $"{_chosen.Count} blocked: " + string.Join(", ", _chosen.OrderBy(c => c));

        /// <summary>Asks for the password, shows the list, and applies the answer.</summary>
        public static async Task EditAsync(IWin32Window owner, FirewallService service)
        {
            if (!service.CanChange || !Guard.Unlock(owner, "Changing blocked countries")) return;
            using var form = new CountryBlockForm(service.Config.BlockedCountries);
            if (form.ShowDialog(owner) != DialogResult.OK) return;
            await ApplyAsync(owner, service, form.Chosen);
        }

        public static async Task ApplyAsync(IWin32Window owner, FirewallService service, List<string> countries)
        {
            try { await service.SetBlockedCountriesAsync(countries); }
            catch (Exception ex)
            {
                Log.Write("Blocking countries failed: " + ex);
                MessageBox.Show(owner, ex.Message, "Blocked countries", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }

    /// <summary>Chooses the apps that keep working during a lockdown.</summary>
    public sealed class LockdownForm : Form
    {
        private readonly CheckedListBox _list = new CheckedListBox { CheckOnClick = true, IntegralHeight = false, Size = new Size(460, 300) };

        private sealed class Item
        {
            public AppRule Rule;
            public override string ToString() => $"{Rule.DisplayName}    {Rule.AppPath}";
        }

        public List<string> KeepIds => _list.CheckedItems.Cast<Item>().Select(i => i.Rule.Id).ToList();

        /// <param name="starting">True when the lockdown starts on OK.</param>
        public LockdownForm(IEnumerable<AppRule> rules, bool starting)
        {
            DialogStyle.Apply(this, starting ? "Start lockdown" : "Lockdown apps");
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            var layout = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, Padding = new Padding(14), WrapContents = false };
            layout.Controls.Add(DialogStyle.Text(
                "A lockdown blocks every app at once, except the ones you tick here. Your rules aren't changed: when the lockdown ends, " +
                "everything goes back as it was. Open connections of blocked apps are closed. Essential Windows networking keeps working.", 460));
            var accepted = rules.Where(r => r.Opens).OrderBy(r => r.DisplayName, StringComparer.CurrentCultureIgnoreCase).ToList();
            foreach (var r in accepted) _list.Items.Add(new Item { Rule = r }, r.KeepInLockdown);
            layout.Controls.Add(_list);
            if (accepted.Count == 0) layout.Controls.Add(DialogStyle.Text("You have no accepted apps, so a lockdown blocks everything.", 460));
            var ok = new Button { Text = starting ? "Start lockdown" : "Save", DialogResult = DialogResult.OK, AutoSize = true };
            var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, AutoSize = true };
            var buttons = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Anchor = AnchorStyles.Right, Margin = new Padding(0, 8, 0, 0) };
            buttons.Controls.Add(cancel);
            buttons.Controls.Add(ok);
            layout.Controls.Add(buttons);
            Controls.Add(layout);
            AcceptButton = ok;
            CancelButton = cancel;
        }

        /// <summary>Starts or ends a lockdown. Ending one needs the password.</summary>
        public static async Task ToggleAsync(IWin32Window owner, FirewallService service)
        {
            if (!service.CanChange) return;
            try
            {
                if (service.Config.Lockdown)
                {
                    if (!Guard.Unlock(owner, "Ending the lockdown")) return;
                    await service.SetLockdownAsync(false);
                    return;
                }
                using var form = new LockdownForm(service.Config.Rules, true);
                if (form.ShowDialog(owner) != DialogResult.OK) return;
                await service.SetLockdownAppsAsync(form.KeepIds);
                await service.SetLockdownAsync(true);
            }
            catch (Exception ex)
            {
                Log.Write("Lockdown failed: " + ex);
                MessageBox.Show(owner, ex.Message, "Lockdown", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        public static async Task ChooseAppsAsync(IWin32Window owner, FirewallService service)
        {
            if (!service.CanChange || !Guard.Unlock(owner, "Changing lockdown apps")) return;
            using var form = new LockdownForm(service.Config.Rules, false);
            if (form.ShowDialog(owner) != DialogResult.OK) return;
            try { await service.SetLockdownAppsAsync(form.KeepIds); }
            catch (Exception ex) { MessageBox.Show(owner, ex.Message, "Lockdown", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        }
    }

    /// <summary>Chooses the blocklists of known bad addresses, and addresses never to block.</summary>
    public sealed class BlocklistForm : Form
    {
        private readonly FirewallService _service;
        private readonly ListView _lists = new ListView { View = View.Details, CheckBoxes = true, FullRowSelect = true, Size = new Size(640, 150), HeaderStyle = ColumnHeaderStyle.Nonclickable };
        private readonly TextBox _exceptions = new TextBox { Multiline = true, ScrollBars = ScrollBars.Vertical, Size = new Size(640, 70) };
        private readonly Label _status = new Label { AutoSize = true, ForeColor = Theme.Muted, MaximumSize = new Size(640, 0) };
        private readonly Button _save = new Button { Text = "Save", AutoSize = true };
        private readonly Button _update = new Button { Text = "Update now", AutoSize = true };

        public BlocklistForm(FirewallService service)
        {
            _service = service;
            DialogStyle.Apply(this, "Blocklists of bad addresses");
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            var layout = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, Padding = new Padding(14), WrapContents = false };
            layout.Controls.Add(DialogStyle.Text(
                "Tick a list to block every address on it, in and out, for every app, including apps you accepted. EasyFW downloads the lists " +
                "once a day from the sites that publish them (spamhaus.org, github.com, abuse.ch, emergingthreats.net) and keeps a copy, so they work offline. " +
                "Only public internet addresses are taken from a list, so your local network is never blocked. If an app tries a listed address, you get a notice.", 640));
            _lists.Columns.Add("List", 230);
            _lists.Columns.Add("Addresses", 80, HorizontalAlignment.Right);
            _lists.Columns.Add("Updated", 110);
            _lists.Columns.Add("About", 600);
            UiHelpers.ShowFullTextOnHover(_lists);
            layout.Controls.Add(_lists);
            layout.Controls.Add(new Label { Text = "Never block these addresses or subnets (one per line), for example a server you trust:", AutoSize = true, Margin = new Padding(3, 10, 3, 4) });
            layout.Controls.Add(_exceptions);
            layout.Controls.Add(_status);
            var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, AutoSize = true };
            var buttons = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Anchor = AnchorStyles.Right, Margin = new Padding(0, 8, 0, 0) };
            buttons.Controls.Add(cancel);
            buttons.Controls.Add(_save);
            buttons.Controls.Add(_update);
            layout.Controls.Add(buttons);
            Controls.Add(layout);
            AcceptButton = _save;
            CancelButton = cancel;

            _exceptions.Text = string.Join(Environment.NewLine, service.Config.BlocklistExceptions);
            Fill(service.Config.Blocklists);
            _save.Click += async (_, __) => await SaveAsync();
            _update.Click += async (_, __) => await UpdateAsync();
        }

        private void Fill(IEnumerable<string> chosen)
        {
            var on = new HashSet<string>(chosen);
            var folder = _service.BlocklistFolder ?? Blocklists.DefaultFolder;
            var kept = Blocklists.LoadKept(Blocklists.Sources.Select(x => x.Id), folder);
            _lists.Items.Clear();
            foreach (var source in Blocklists.Sources)
            {
                var when = Blocklists.KeptTimeUtc(source.Id, folder);
                var item = new ListViewItem(new[]
                {
                    source.Name,
                    kept.TryGetValue(source.Id, out var entries) ? entries.Count.ToString("N0") : "-",
                    when?.ToLocalTime().ToString("g") ?? "Not yet",
                    source.Description
                }) { Tag = source.Id, Checked = on.Contains(source.Id) };
                _lists.Items.Add(item);
            }
            _status.Text = _service.Blocklist.Count == 0 ? "No blocklist is in force." : $"In force now: {_service.Blocklist.Count:N0} addresses and ranges.";
        }

        private List<string> Chosen => _lists.Items.Cast<ListViewItem>().Where(i => i.Checked).Select(i => (string)i.Tag).ToList();

        private void Busy(bool busy, string text = null)
        {
            _save.Enabled = _update.Enabled = _lists.Enabled = _exceptions.Enabled = !busy;
            if (text != null) _status.Text = text;
            UseWaitCursor = busy;
        }

        private async Task SaveAsync()
        {
            Busy(true, "Downloading and applying the lists...");
            try
            {
                var problems = await _service.SetBlocklistsAsync(Chosen, _exceptions.Lines);
                if (problems.Length > 0)
                    MessageBox.Show(this, "Some lists didn't download, so they aren't in force yet. EasyFW tries again later.\n\n" + problems, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                DialogResult = DialogResult.OK;
            }
            catch (Exception ex)
            {
                Log.Write("Saving blocklists failed: " + ex);
                MessageBox.Show(this, ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
                Busy(false, "");
            }
        }

        private async Task UpdateAsync()
        {
            if (_service.Config.Blocklists.Count == 0)
            {
                MessageBox.Show(this, "Tick the lists you want and press Save first.", Text);
                return;
            }
            Busy(true, "Downloading...");
            try
            {
                var problems = await _service.UpdateBlocklistsAsync();
                if (problems.Length > 0) MessageBox.Show(this, problems, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            catch (Exception ex) { MessageBox.Show(this, ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error); }
            Busy(false);
            Fill(Chosen);
        }

        public static async Task EditAsync(IWin32Window owner, FirewallService service)
        {
            if (!service.CanChange || !Guard.Unlock(owner, "Changing blocklists")) return;
            using var form = new BlocklistForm(service);
            form.ShowDialog(owner);
            await Task.CompletedTask;
        }
    }
}
