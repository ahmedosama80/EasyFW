using System;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;
using EasyFW.Core;

namespace EasyFW.UI
{
    /// <summary>Asks where this PC is, for the world map: a country, and a city if it's on the list.</summary>
    public sealed class LocationForm : Form
    {
        private const string WholeCountry = "(anywhere in the country)";
        private readonly ComboBox _country = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 300, MaxDropDownItems = 20 };
        private readonly ComboBox _city = new ComboBox { DropDownStyle = ComboBoxStyle.DropDown, Width = 300, MaxDropDownItems = 20, AutoCompleteMode = AutoCompleteMode.SuggestAppend, AutoCompleteSource = AutoCompleteSource.ListItems };
        private readonly Label _cityHint = new Label { AutoSize = true, ForeColor = Theme.Muted, MaximumSize = new Size(420, 0) };

        private sealed class CountryItem
        {
            public string Code, Name;
            public override string ToString() => Name;
        }

        public string Country { get; private set; }
        /// <summary>Null for the whole country.</summary>
        public string City { get; private set; }
        /// <summary>The user asked to go back to the detected location.</summary>
        public bool UseDetected { get; private set; }

        public LocationForm(MapLocation current, string publicIp, string detectedCountry)
        {
            Text = "Your location";
            Font = Theme.Base;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = false;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96, 96);
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            Icon = IconFactory.Tray(IconFactory.TrayState.On);

            var detected = publicIp == null
                ? "EasyFW couldn't find your public IP, so it can't tell where you are."
                : detectedCountry == null
                    ? $"Your public IP is {publicIp}, but its country isn't known."
                    : $"Your public IP is {publicIp}, which is in {IpInfo.CountryName(detectedCountry)}. The country is known, the city isn't.";

            var layout = new TableLayoutPanel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, ColumnCount = 2, Padding = new Padding(14), Location = Point.Empty };
            layout.Controls.Add(new Label { Text = "Where is this PC? The world map draws its lines from here.", AutoSize = true, Font = Theme.Heading, Margin = new Padding(3, 0, 3, 6) }, 0, 0);
            layout.SetColumnSpan(layout.GetControlFromPosition(0, 0), 2);
            var info = new Label { Text = detected, AutoSize = true, ForeColor = Theme.Muted, MaximumSize = new Size(440, 0), Margin = new Padding(3, 0, 3, 12) };
            layout.Controls.Add(info, 0, 1);
            layout.SetColumnSpan(info, 2);
            layout.Controls.Add(new Label { Text = "Country", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 2);
            layout.Controls.Add(_country, 1, 2);
            layout.Controls.Add(new Label { Text = "City", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 3);
            layout.Controls.Add(_city, 1, 3);
            layout.Controls.Add(_cityHint, 1, 4);

            var buttons = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Anchor = AnchorStyles.Right, Margin = new Padding(0, 12, 0, 0) };
            var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, AutoSize = true };
            var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, AutoSize = true };
            var auto = new Button { Text = detectedCountry != null ? "Use my public IP" : "Find it automatically", AutoSize = true };
            buttons.Controls.Add(cancel);
            buttons.Controls.Add(ok);
            buttons.Controls.Add(auto);
            layout.Controls.Add(buttons, 0, 5);
            layout.SetColumnSpan(buttons, 2);
            Controls.Add(layout);
            AcceptButton = ok;
            CancelButton = cancel;

            var items = WorldGeo.Countries.Select(c => new CountryItem { Code = c.ToUpperInvariant(), Name = IpInfo.CountryName(c) })
                .OrderBy(c => c.Name, StringComparer.CurrentCultureIgnoreCase).ToArray();
            _country.Items.AddRange(items);
            _country.SelectedIndexChanged += (_, __) => FillCities(null);
            var start = items.FirstOrDefault(i => i.Code == current.Country);
            _country.SelectedItem = start ?? items.FirstOrDefault();
            FillCities(current.City);

            ok.Click += (_, __) =>
            {
                Country = (_country.SelectedItem as CountryItem)?.Code;
                var city = _city.Text.Trim();
                City = city.Length == 0 || city == WholeCountry ? null : WorldGeo.FindCity(Country, city)?.Name;
            };
            auto.Click += (_, __) =>
            {
                UseDetected = true;
                DialogResult = DialogResult.OK;
            };
        }

        private void FillCities(string select)
        {
            var code = (_country.SelectedItem as CountryItem)?.Code;
            var cities = WorldGeo.CitiesOf(code);
            _city.BeginUpdate();
            _city.Items.Clear();
            _city.Items.Add(WholeCountry);
            foreach (var c in cities) _city.Items.Add(c.Name);
            _city.EndUpdate();
            _city.SelectedItem = cities.FirstOrDefault(c => c.Name == select)?.Name ?? WholeCountry;
            _cityHint.Text = cities.Count == 0
                ? "No cities listed for this country. The map uses its middle."
                : "Pick the nearest city. If yours isn't listed, pick the nearest one or the whole country.";
        }
    }
}
