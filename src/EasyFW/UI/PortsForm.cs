using System;
using System.Drawing;
using System.Windows.Forms;
using EasyFW.Core;

namespace EasyFW.UI
{
    /// <summary>Asks which ports a decision applies to.</summary>
    public sealed class PortsForm : Form
    {
        private readonly TextBox _ports = new TextBox { Dock = DockStyle.Fill, Margin = new Padding(0, 0, 0, 4) };

        public string Ports { get; private set; }

        public PortsForm(string appName, RuleAction action, string suggestion)
        {
            var accept = action == RuleAction.Allow;
            Text = accept ? "Accept on certain ports" : "Block on certain ports";
            Font = Theme.Base;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            ShowInTaskbar = false;
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96, 96);
            ClientSize = new Size(460, 200);

            var save = new Button { Text = accept ? "Accept" : "Block", AutoSize = true, MinimumSize = new Size(80, 0), Margin = new Padding(6, 0, 0, 0) };
            var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel, MinimumSize = new Size(80, 0), Margin = new Padding(6, 0, 0, 0) };
            save.Click += (_, __) => Save();
            AcceptButton = save;
            CancelButton = cancel;

            var page = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(16, 14, 16, 4) };
            page.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            page.Controls.Add(Para(accept
                ? $"{appName} can use only these ports. Everything else stays blocked."
                : $"{appName} can't use these ports. It can use every other port.", SystemColors.ControlText));
            page.Controls.Add(_ports);
            page.Controls.Add(Para("Separate with commas, and use a dash for a range: 80, 443, 8000-8100", Theme.Muted));
            page.Controls.Add(Para("Applies to TCP and UDP. Outgoing traffic is matched on the other computer's port, incoming on this PC's port.", Theme.Muted));

            var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(16, 6, 16, 12) };
            buttons.Controls.Add(cancel);
            buttons.Controls.Add(save);

            Controls.Add(page);
            Controls.Add(buttons);

            _ports.Text = suggestion ?? "";
            ActiveControl = _ports;
            _ports.SelectAll();
        }

        private static Label Para(string text, Color color) => new Label
        {
            Text = text, AutoSize = true, ForeColor = color, UseMnemonic = false, MaximumSize = new Size(428, 0), Margin = new Padding(0, 0, 0, 8)
        };

        private void Save()
        {
            try { Ports = PortList.Normalize(_ports.Text); }
            catch (FormatException ex)
            {
                MessageBox.Show(this, ex.Message, Text);
                return;
            }
            if (Ports == null)
            {
                MessageBox.Show(this, "Enter at least one port.", Text);
                return;
            }
            DialogResult = DialogResult.OK;
        }
    }
}
