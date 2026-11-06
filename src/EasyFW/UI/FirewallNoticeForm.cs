using System.Drawing;
using System.Linq;
using System.Windows.Forms;
using EasyFW.Core;
using EasyFW.Platform;

namespace EasyFW.UI
{
    /// <summary>Says plainly that Windows Firewall does the filtering, and names the services involved.</summary>
    public sealed class FirewallNoticeForm : Form
    {
        private readonly CheckBox _hide = new CheckBox { Text = "Don't show this when EasyFW starts", AutoSize = true, Margin = new Padding(0, 6, 0, 0) };

        public bool HideAtStart => _hide.Checked;

        public FirewallNoticeForm(RunMode mode, bool hideAtStart)
        {
            Text = "EasyFW uses Windows Firewall";
            Font = Theme.Base;
            Icon = IconFactory.Tray(IconFactory.TrayState.On);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            ShowInTaskbar = false;
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96, 96);
            ClientSize = new Size(600, 420);
            _hide.Checked = hideAtStart;

            var ok = new Button { Text = "OK", AutoSize = true, DialogResult = DialogResult.OK, Anchor = AnchorStyles.Right, MinimumSize = new Size(80, 0) };
            AcceptButton = ok;
            CancelButton = ok;

            var page = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(20, 14, 20, 8) };
            page.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            page.Controls.Add(new Label { Text = "EasyFW runs on Windows Firewall", AutoSize = true, Font = Theme.Title, Margin = new Padding(0, 0, 0, 8) });
            page.Controls.Add(Para("EasyFW is not a separate firewall. Windows Firewall does all the blocking. EasyFW sets its rules and shows you what is happening."));
            page.Controls.Add(new Label { Text = "Windows services it uses", AutoSize = true, Font = Theme.Heading, Margin = new Padding(0, 4, 0, 4) });
            page.Controls.Add(ServiceTable());
            page.Controls.Add(Para("EasyFW can't work if these services are stopped."));
            page.Controls.Add(new Label { Text = "What happens", AutoSize = true, Font = Theme.Heading, Margin = new Padding(0, 4, 0, 4) });
            page.Controls.Add(Para(ModeText(mode)));

            var buttons = new TableLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, ColumnCount = 2, Padding = new Padding(20, 8, 20, 14) };
            buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            buttons.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            buttons.Controls.Add(_hide, 0, 0);
            buttons.Controls.Add(ok, 1, 0);

            Controls.Add(page);
            Controls.Add(buttons);
        }

        private static string ModeText(RunMode mode)
        {
            if (mode == RunMode.Demo) return "Demo mode: traffic is simulated and Windows Firewall isn't changed.";
            if (mode == RunMode.MonitorOnly) return "Monitor-only: EasyFW doesn't change Windows Firewall in this mode. It only shows connections.";
            return "•  When EasyFW starts, Windows Firewall is set to block all traffic, and its existing allow rules are switched off.\n" +
                   "•  When you exit EasyFW, those settings go back to how they were. This can take a couple of minutes.\n" +
                   "•  The Windows Firewall service itself keeps running the whole time, as it always does.";
        }

        private static Label Para(string text) => new Label
        {
            Text = text, AutoSize = true, UseMnemonic = false, MaximumSize = new Size(556, 0), Margin = new Padding(0, 0, 0, 10)
        };

        private static Control ServiceTable()
        {
            var rows = WindowsServiceInfo.ReadFirewallServices();
            var table = new TableLayoutPanel { AutoSize = true, ColumnCount = 3, RowCount = rows.Count + 1, Margin = new Padding(0, 0, 0, 8) };
            for (var i = 0; i < 3; i++) table.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            AddRow(table, 0, "Name", "Service name", "Status", Theme.Muted);
            foreach (var (row, index) in rows.Select((r, i) => (r, i)))
                AddRow(table, index + 1, row.DisplayName, row.ServiceName, row.Status, row.IsRunning ? Theme.Good : Theme.Off);
            return table;
        }

        private static void AddRow(TableLayoutPanel table, int rowIndex, string name, string serviceName, string status, Color statusColor)
        {
            var isHeader = rowIndex == 0;
            table.Controls.Add(Cell(name, isHeader ? Theme.Muted : SystemColors.ControlText), 0, rowIndex);
            table.Controls.Add(Cell(serviceName, isHeader ? Theme.Muted : SystemColors.ControlText), 1, rowIndex);
            table.Controls.Add(Cell(status, statusColor), 2, rowIndex);
        }

        private static Label Cell(string text, Color color) => new Label
        {
            Text = text, AutoSize = true, ForeColor = color, UseMnemonic = false, Margin = new Padding(0, 2, 24, 2)
        };
    }
}
