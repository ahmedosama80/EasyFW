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
    /// <summary>
    /// Every port this PC listens on, whether the network can reach it, who connected to it, and the folders this PC shares.
    /// </summary>
    public sealed class PortsTab : UserControl
    {
        private static readonly Color OpenRow = Color.FromArgb(255, 247, 230);

        /// <summary>Reads the shares. Swappable for the demo and tests.</summary>
        public static Func<List<ShareInfo>> ShareReader { get; set; } = EasyFW.Platform.Shares.Read;

        private readonly FirewallService _service;
        private readonly ListView _ports = NewList(("Port", 56), ("Proto", 50), ("Service", 150), ("Program", 140), ("PID", 52), ("Listening on", 120),
            ("Firewall", 190), ("Connected now", 170), ("Tried (last hour)", 110), ("Path", 320));
        private readonly ListView _visitors = NewList(("Remote IP", 130), ("Remote Host", 200), ("Country", 130), ("Connected now", 100), ("Accepted", 70), ("Blocked", 70), ("Last attempt", 110));
        private readonly ListView _shares = NewList(("Share", 120), ("Folder", 260), ("Type", 90), ("In use by", 260), ("Description", 220));
        private readonly Label _portsTitle = Title();
        private readonly Label _visitorsTitle = Title();
        private readonly Label _sharesTitle = Title();
        private readonly Label _smbNote = new Label { AutoSize = true, Margin = new Padding(8, 8, 8, 0), MaximumSize = new Size(900, 0) };
        private readonly ComboBox _show = Combo("All", "Reachable from the network", "This PC only");
        private readonly ComboBox _protocol = Combo("All", "TCP", "UDP");
        private readonly TextBox _search = new TextBox { Width = 130, Margin = new Padding(4, 5, 6, 4) };
        private readonly CheckBox _adminShares = new CheckBox { Text = "Show Windows admin shares (C$, ADMIN$)", AutoSize = true, Margin = new Padding(12, 7, 6, 4) };
        private List<ListeningPort> _rows = new List<ListeningPort>();
        private List<ShareInfo> _shareRows = new List<ShareInfo>();
        private DateTime _nextShares = DateTime.MinValue;
        private bool _readingShares;
        private string _shareError;

        public string Summary { get; private set; } = "";

        public PortsTab(FirewallService service)
        {
            _service = service;
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 6, Padding = new Padding(6, 2, 6, 6) };
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 46));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 22));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 32));
            layout.Controls.Add(Bar(_portsTitle, UiHelpers.BarLabel("Show"), _show, UiHelpers.BarLabel("Protocol"), _protocol, UiHelpers.BarLabel("Search"), _search), 0, 0);
            layout.Controls.Add(_ports, 0, 1);
            layout.Controls.Add(Bar(_visitorsTitle), 0, 2);
            layout.Controls.Add(_visitors, 0, 3);
            layout.Controls.Add(Bar(_sharesTitle, _adminShares, _smbNote), 0, 4);
            layout.Controls.Add(_shares, 0, 5);
            Controls.Add(layout);
            _show.Width = 190;

            Flags.ShowInColumn(_visitors, 2, 0);
            foreach (var (list, name) in new[] { (_ports, "ports"), (_visitors, "port-visitors"), (_shares, "shares") })
            {
                UiHelpers.ShowFullTextOnHover(list);
                UiHelpers.RememberColumns(list, name, service);
            }
            _ports.ContextMenuStrip = PortsMenu();
            _shares.ContextMenuStrip = SharesMenu();
            _ports.SelectedIndexChanged += (_, __) => ShowVisitors();
            _show.SelectedIndexChanged += (_, __) => RefreshData();
            _protocol.SelectedIndexChanged += (_, __) => RefreshData();
            _search.TextChanged += (_, __) => RefreshData();
            _adminShares.CheckedChanged += (_, __) => ShowShares();
        }

        private static ListView NewList(params (string Title, int Width)[] columns)
        {
            var list = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, HideSelection = false, Margin = new Padding(0, 0, 0, 4) };
            foreach (var c in columns) list.Columns.Add(c.Title, c.Width);
            UiHelpers.EnableDoubleBuffer(list);
            return list;
        }

        private static Label Title() => new Label { AutoSize = true, Font = Theme.Heading, Margin = new Padding(0, 7, 12, 4) };

        private static ComboBox Combo(params object[] items)
        {
            var c = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 70, Margin = new Padding(4, 5, 6, 4) };
            c.Items.AddRange(items);
            c.SelectedIndex = 0;
            return c;
        }

        private static Control Bar(params Control[] controls)
        {
            var bar = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = true, Margin = Padding.Empty };
            bar.Controls.AddRange(controls);
            return bar;
        }

        // ---------- data ----------

        public void RefreshData()
        {
            var all = PortsView.Build(_service.LastEndpoints, _service.History.All);
            var text = _search.Text.Trim();
            _rows = all.Where(p =>
                    (_show.SelectedIndex == 0 || (_show.SelectedIndex == 1) == !p.LocalOnly)
                    && (_protocol.SelectedIndex == 0 || p.Protocol == (string)_protocol.SelectedItem)
                    && (text.Length == 0 || Cells(p).Any(c => c.IndexOf(text, StringComparison.OrdinalIgnoreCase) >= 0)))
                .ToList();
            var reachable = all.Count(p => !p.LocalOnly);
            var open = all.Count(p => !p.LocalOnly && IsOpen(p));
            _portsTitle.Text = $"Open ports ({_rows.Count}" + (_rows.Count != all.Count ? $" of {all.Count}" : "") + ")";
            Summary = $"{all.Count} ports listening: {reachable} reachable from the network, {open} of them let through by the firewall. {_shareRows.Count(s => !s.IsAdmin)} shared folder(s).";
            RulesTab.Rebuild(_ports, _rows, p => p.Key, Cells, p => p.LocalOnly ? Theme.Closed : IsOpen(p) ? Theme.Warn : SystemColors.WindowText,
                p => !p.LocalOnly && IsOpen(p) ? OpenRow : (Color?)null);
            ShowVisitors();

            if (DateTime.UtcNow >= _nextShares && !_readingShares) _ = ReadSharesAsync();
            ShowSmbNote();
        }

        private string[] Cells(ListeningPort p)
        {
            var visitors = p.Visitors.Values.ToList();
            var tried = visitors.Sum(v => v.Accepted + v.Blocked);
            var blocked = visitors.Sum(v => v.Blocked);
            return new[]
            {
                p.Port.ToString(), p.Protocol, p.Service, p.ProcessName ?? "", p.Pid.ToString(), p.ScopeText, FirewallText(p),
                p.ConnectedNow.Count == 0 ? "-" : $"{p.ConnectedNow.Count}: {string.Join(", ", p.ConnectedNow.Take(3))}{(p.ConnectedNow.Count > 3 ? ", ..." : "")}",
                tried == 0 ? "-" : blocked > 0 ? $"{tried} ({blocked} blocked)" : tried.ToString(),
                p.AppPath ?? ""
            };
        }

        private string Target(ListeningPort p) => AppPaths.RuleTarget(p.AppPath, p.Protocol);

        /// <summary>Whether another device could reach the port through the firewall now.</summary>
        private bool IsOpen(ListeningPort p)
        {
            if (p.LocalOnly) return false;
            if (!_service.IsEnabled) return true;
            if (IsEssential(p)) return true;
            return !string.IsNullOrEmpty(p.AppPath) && _service.Evaluate(Target(p), TrafficDirection.Inbound, p.Port) == Verdict.Accepted;
        }

        /// <summary>DHCP replies come in through the essential networking rules.</summary>
        private bool IsEssential(ListeningPort p) =>
            _service.Config.AllowEssentials && p.Protocol == "UDP" && (p.Port == 68 || p.Port == 546) && AppPaths.IsSharedServiceHost(p.AppPath);

        private string FirewallText(ListeningPort p)
        {
            if (p.LocalOnly) return "Can't be reached (this PC only)";
            if (!_service.IsEnabled) return "Not filtered: protection is off";
            if (IsEssential(p)) return "Open (essential networking)";
            if (string.IsNullOrEmpty(p.AppPath)) return "Blocked (program unknown)";
            if (!IsOpen(p)) return "Blocked";
            var rule = _service.FindRule(Target(p));
            return rule != null && rule.LimitsNetwork ? "Open: " + rule.NetworkText : "Open to the network";
        }

        private ListeningPort SelectedPort => _ports.SelectedItems.Count > 0 ? (ListeningPort)_ports.SelectedItems[0].Tag : null;

        private void ShowVisitors()
        {
            var port = SelectedPort;
            _visitorsTitle.Text = port == null
                ? "Who connected: pick a port above"
                : $"Who connected to {port.Protocol} {port.Port}" + (port.Service.Length > 0 ? $" ({port.Service})" : "") + $", {port.ProcessName}: now and in the last hour";
            var rows = port?.Visitors.Values.OrderByDescending(v => v.ConnectedNow).ThenByDescending(v => v.LastUtc).ToList() ?? new List<PortVisitor>();
            RulesTab.Rebuild(_visitors, rows, v => v.Ip, v => new[]
            {
                v.Ip, IpInfo.HostName(v.Ip), IpInfo.CountryText(v.Ip), v.ConnectedNow ? "Yes" : "No", v.Accepted.ToString(), v.Blocked.ToString(),
                v.LastUtc == DateTime.MinValue ? "-" : v.LastUtc.ToLocalTime().ToString("HH:mm:ss")
            }, v => v.ConnectedNow ? Theme.Good : v.Blocked > 0 && v.Accepted == 0 ? Theme.Blocked : SystemColors.WindowText);
        }

        private async Task ReadSharesAsync()
        {
            _readingShares = true;
            _nextShares = DateTime.UtcNow.AddSeconds(10);
            try
            {
                _shareRows = await Task.Run(ShareReader);
                _shareError = null;
            }
            catch (Exception ex)
            {
                _shareError = ex.Message;
                Log.Write("Can't read shares: " + ex.Message);
            }
            finally { _readingShares = false; }
            if (!IsDisposed) ShowShares();
        }

        private void ShowShares()
        {
            var shown = _shareRows.Where(s => _adminShares.Checked || !s.IsAdmin).OrderBy(s => s.IsAdmin).ThenBy(s => s.Name, StringComparer.OrdinalIgnoreCase).ToList();
            var inUse = shown.Count(s => s.Users.Count > 0);
            _sharesTitle.Text = _shareError != null ? "Shared folders: can't read them (" + _shareError + ")"
                : $"Shared folders ({shown.Count})" + (inUse > 0 ? $", {inUse} in use" : "");
            RulesTab.Rebuild(_shares, shown, s => s.Name, s => new[]
            {
                s.Name, s.Path, s.Type + (s.IsAdmin ? " (Windows)" : ""),
                s.Users.Count == 0 ? "-" : string.Join(", ", s.Users.Select(u => $"{u.Computer}{(u.User.Length > 0 ? " as " + u.User : "")}{(u.Files > 0 ? $" ({u.Files} file(s) open)" : "")}")),
                s.Description
            }, s => s.IsAdmin ? Theme.Closed : s.Users.Count > 0 ? Theme.Warn : SystemColors.WindowText);
        }

        private void ShowSmbNote()
        {
            if (!_service.IsEnabled)
            {
                _smbNote.Text = "Protection is off, so other devices can reach file sharing if Windows allows it.";
                _smbNote.ForeColor = Theme.Warn;
                return;
            }
            var open = _service.Evaluate(AppPaths.SystemApp, TrafficDirection.Inbound, 445) == Verdict.Accepted;
            _smbNote.Text = open
                ? "File sharing (port 445) is open to the network through your rule for Windows System, so these shares can be reached."
                : "EasyFW blocks file sharing (port 445) from other devices, so these shares can't be reached from the network.";
            _smbNote.ForeColor = open ? Theme.Warn : Theme.Good;
        }

        // ---------- menus ----------

        private ContextMenuStrip PortsMenu()
        {
            var menu = new ContextMenuStrip();
            menu.Items.Add("Copy row", null, (_, __) => UiHelpers.CopyRows(FindForm(), _ports.SelectedItems.Cast<ListViewItem>().Select(i => i.SubItems.Cast<ListViewItem.ListViewSubItem>().Select(c => c.Text))));
            menu.Items.Add(UiHelpers.CopyPathItem(FindForm, () => _ports.SelectedItems.Cast<ListViewItem>().Select(i => ((ListeningPort)i.Tag).AppPath)));
            menu.Items.Add("Show log (last hour)", null, (_, __) => { var p = SelectedPort; if (p?.AppPath != null) AppLogForm.Open(FindForm(), _service, Target(p)); });
            menu.Items.Add("Open file location", null, (_, __) =>
            {
                var path = SelectedPort?.AppPath;
                if (!string.IsNullOrEmpty(path) && File.Exists(path)) Process.Start("explorer.exe", $"/select,\"{path}\"");
            });
            menu.Opening += (_, e) => e.Cancel = _ports.SelectedItems.Count == 0;
            return menu;
        }

        private ContextMenuStrip SharesMenu()
        {
            var menu = new ContextMenuStrip();
            ShareInfo Selected() => _shares.SelectedItems.Count > 0 ? (ShareInfo)_shares.SelectedItems[0].Tag : null;
            menu.Items.Add("Open folder", null, (_, __) =>
            {
                var s = Selected();
                if (s != null && Directory.Exists(s.Path)) Process.Start("explorer.exe", $"\"{s.Path}\"");
            });
            menu.Items.Add(UiHelpers.CopyPathItem(FindForm, () => _shares.SelectedItems.Cast<ListViewItem>().Select(i => ((ShareInfo)i.Tag).Path)));
            var stop = new ToolStripMenuItem("Stop sharing...");
            stop.Click += (_, __) => StopSharing(Selected());
            menu.Items.Add(stop);
            menu.Opening += (_, e) =>
            {
                var s = Selected();
                if (s == null) { e.Cancel = true; return; }
                stop.Enabled = _service.Mode == RunMode.Live && s.Type != "Remote control (IPC)";
            };
            return menu;
        }

        private void StopSharing(ShareInfo share)
        {
            if (share == null || !Guard.Unlock(FindForm(), "Stopping a share")) return;
            var warning = share.IsAdmin ? "\n\nThis is one of Windows' own admin shares. Windows makes it again at the next restart." : "";
            var users = share.Users.Count > 0 ? $"\n\n{share.Users.Count} computer(s) are using it now and will be cut off." : "";
            if (MessageBox.Show(FindForm(), $"Stop sharing \"{share.Name}\" ({share.Path})? The folder and its files stay as they are.{users}{warning}",
                    "Stop sharing", MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            try
            {
                EasyFW.Platform.Shares.StopSharing(share.Name);
                Log.Write($"Stopped sharing {share.Name} ({share.Path}).");
                _nextShares = DateTime.MinValue;
                RefreshData();
            }
            catch (Exception ex)
            {
                Log.Write("Stop sharing failed: " + ex);
                MessageBox.Show(FindForm(), ex.Message, "Stop sharing", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}
