using System.Drawing;
using System.Windows.Forms;
using EasyFW.Core;

namespace EasyFW.UI
{
    public enum ExitChoice { Cancel, TurnOff, KeepOn }

    /// <summary>Asks what happens to protection when the app closes, since the two choices leave the PC in very different states.</summary>
    public sealed class ExitChoiceForm : Form
    {
        public ExitChoice Choice { get; private set; } = ExitChoice.Cancel;

        public ExitChoiceForm()
        {
            Text = "Exit EasyFW";
            Font = Theme.Base;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            ShowInTaskbar = false;
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96, 96);
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;

            var page = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false, Padding = new Padding(16, 14, 16, 8) };
            page.Controls.Add(new Label { Text = "What should happen to protection when EasyFW closes?", AutoSize = true, Font = Theme.Heading, Margin = new Padding(0, 0, 0, 12) });

            var turnOff = Choice_("Turn off protection and exit", ExitChoice.TurnOff);
            page.Controls.Add(turnOff);
            page.Controls.Add(Hint("Windows Firewall goes back to the settings it had before EasyFW. This can take a minute."));

            page.Controls.Add(Choice_("Keep protection on and exit", ExitChoice.KeepOn));
            page.Controls.Add(Hint("Windows Firewall keeps blocking every app without an Accept Always rule, even with EasyFW closed. " +
                "New apps are blocked without asking until EasyFW runs again. To undo it, start EasyFW and exit with the first choice, or run EasyFW.exe --restore."));

            var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel, MinimumSize = new Size(80, 0) };
            var bottom = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 6, 0, 0) };
            bottom.Controls.Add(cancel);
            page.Controls.Add(bottom);

            Controls.Add(page);
            AcceptButton = turnOff;
            CancelButton = cancel;
        }

        private Button Choice_(string text, ExitChoice choice)
        {
            var button = new Button { Text = text, AutoSize = true, MinimumSize = new Size(260, 30), Margin = new Padding(0, 0, 0, 4) };
            button.Click += (_, __) =>
            {
                Choice = choice;
                DialogResult = DialogResult.OK;
            };
            return button;
        }

        private static Label Hint(string text) =>
            new Label { Text = text, AutoSize = true, ForeColor = Theme.Muted, MaximumSize = new Size(440, 0), Margin = new Padding(2, 0, 0, 12) };
    }
}
