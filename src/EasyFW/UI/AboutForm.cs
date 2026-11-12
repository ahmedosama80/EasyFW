using System;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;
using EasyFW.Core;

namespace EasyFW.UI
{
    public sealed class AboutForm : Form
    {
        public AboutForm()
        {
            Text = "About EasyFW";
            Font = Theme.Base;
            Icon = IconFactory.Tray(IconFactory.TrayState.On);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            ShowInTaskbar = false;
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96, 96);
            ClientSize = new Size(440, 330);

            var ok = new Button { Text = "OK", AutoSize = true, DialogResult = DialogResult.OK, MinimumSize = new Size(80, 0), Anchor = AnchorStyles.Right };
            AcceptButton = ok;
            CancelButton = ok;

            var email = new LinkLabel { Text = AppInfo.Email, AutoSize = true, Margin = new Padding(0, 0, 0, 12) };
            email.LinkClicked += (_, __) => OpenEmail();

            var page = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(20, 14, 20, 8) };
            page.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            page.Controls.Add(new Label { Text = "EasyFW " + AppInfo.Version, AutoSize = true, Font = Theme.Title, Margin = new Padding(0, 0, 0, 6) });
            page.Controls.Add(Para(AppInfo.Brief, 10));
            page.Controls.Add(new Label { Text = AppInfo.NonCommercial, AutoSize = true, Font = Theme.Heading, Margin = new Padding(0, 0, 0, 10) });
            page.Controls.Add(Para("Developed by " + AppInfo.Developer, 2));
            page.Controls.Add(email);
            page.Controls.Add(Para("Ask for a commercial license at the address above.", 12));
            // DB-IP's license (CC BY 4.0) asks for this credit with a link wherever its data is shown.
            var dbip = new LinkLabel { Text = "IP Geolocation by DB-IP", AutoSize = true, Margin = new Padding(0, 0, 0, 2) };
            dbip.LinkClicked += (_, __) => Open("https://db-ip.com");
            page.Controls.Add(dbip);
            page.Controls.Add(Para("Flag icons by Mark James (famfamfam.com).", 0));

            var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(20, 6, 20, 14) };
            buttons.Controls.Add(ok);

            Controls.Add(page);
            Controls.Add(buttons);
        }

        private static Label Para(string text, int below) => new Label
        {
            Text = text, AutoSize = true, UseMnemonic = false, MaximumSize = new Size(400, 0), Margin = new Padding(0, 0, 0, below)
        };

        private void Open(string url)
        {
            try { Process.Start(url); }
            catch (Exception ex)
            {
                Log.Write("Could not open link: " + ex.Message);
                MessageBox.Show(this, "No web browser is set up. The address is " + url + ".", Text);
            }
        }

        private void OpenEmail()
        {
            try { Process.Start("mailto:" + AppInfo.Email + "?subject=EasyFW%20commercial%20license"); }
            catch (Exception ex)
            {
                Log.Write("Could not open email: " + ex.Message);
                MessageBox.Show(this, "No email program is set up. The address is " + AppInfo.Email + ".", Text);
            }
        }
    }
}
