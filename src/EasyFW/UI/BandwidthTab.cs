using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using EasyFW.Core;

namespace EasyFW.UI
{
    /// <summary>Live data rates: the whole PC, internet and LAN, a graph of the last minutes, and every app.</summary>
    public sealed class BandwidthTab : UserControl
    {
        internal static readonly Color InternetColor = Color.FromArgb(37, 99, 235), LanColor = Color.FromArgb(22, 163, 74);

        private readonly FirewallService _service;
        private readonly Label _problem = new Label { Dock = DockStyle.Top, AutoSize = false, Height = 30, TextAlign = ContentAlignment.MiddleLeft, BackColor = Theme.BannerBack, ForeColor = Theme.BannerText, Padding = new Padding(10, 0, 0, 0), Visible = false };
        private readonly RateTiles _tiles;
        private readonly RateGraph _graph;
        private readonly ComboBox _span = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 110, Margin = new Padding(4, 5, 6, 4) };
        private readonly CheckBox _activeOnly = new CheckBox { Text = "Only apps using the network now", AutoSize = true, Checked = true, Margin = new Padding(12, 7, 6, 4) };
        private readonly ListView _list = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, HideSelection = false };
        private static readonly (string Title, int Width, Func<AppRate, IComparable> Key)[] Columns =
        {
            ("App", 160, a => a.Name), ("Down", 90, a => a.Down), ("Up", 90, a => a.Up),
            ("Internet down", 100, a => a.InternetDown), ("Internet up", 95, a => a.InternetUp), ("LAN down", 90, a => a.LanDown), ("LAN up", 85, a => a.LanUp),
            ("Received", 85, a => a.TotalDown), ("Sent", 85, a => a.TotalUp), ("Path", 320, a => a.AppPath)
        };
        private int _sortColumn = -1;
        private bool _ascending;

        public string Summary { get; private set; } = "";

        public BandwidthTab(FirewallService service)
        {
            _service = service;
            _tiles = new RateTiles { Dock = DockStyle.Top, Height = 84 };
            _graph = new RateGraph { Dock = DockStyle.Top, Height = 190 };
            foreach (var c in Columns) _list.Columns.Add(c.Title, c.Width, c.Title == "App" || c.Title == "Path" ? HorizontalAlignment.Left : HorizontalAlignment.Right);
            UiHelpers.EnableDoubleBuffer(_list);
            UiHelpers.ShowFullTextOnHover(_list);
            UiHelpers.RememberColumns(_list, "bandwidth", service);
            _list.ColumnClick += (_, e) =>
            {
                if (e.Column == _sortColumn) _ascending = !_ascending;
                else { _sortColumn = e.Column; _ascending = e.Column == 0 || e.Column == 9; }
                for (var i = 0; i < Columns.Length; i++) _list.Columns[i].Text = Columns[i].Title + (i == _sortColumn ? _ascending ? " ▲" : " ▼" : "");
                RefreshData();
            };
            _list.ContextMenuStrip = Menu();

            _span.Items.AddRange(new object[] { "Last 2 minutes", "Last 10 minutes" });
            _span.SelectedIndex = 0;
            _span.SelectedIndexChanged += (_, __) => RefreshData();
            _activeOnly.CheckedChanged += (_, __) => RefreshData();
            var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(6, 2, 6, 0) };
            bar.Controls.Add(new Label { Text = "Apps", AutoSize = true, Font = Theme.Heading, Margin = new Padding(0, 7, 12, 4) });
            bar.Controls.Add(_activeOnly);
            bar.Controls.Add(UiHelpers.BarLabel("Graph"));
            bar.Controls.Add(_span);

            var host = new Panel { Dock = DockStyle.Fill, Padding = new Padding(6, 0, 6, 6) };
            host.Controls.Add(_list);
            Controls.Add(host);
            Controls.Add(bar);
            Controls.Add(_graph);
            Controls.Add(_tiles);
            Controls.Add(_problem);
        }

        public void RefreshData()
        {
            var meter = _service.Bandwidth;
            _problem.Text = meter.Problem ?? "";
            _problem.Visible = meter.Problem != null;
            _tiles.Now = meter.Now;
            _tiles.Invalidate();
            var seconds = _span.SelectedIndex == 1 ? 600 : 120;
            _graph.Points = meter.History.Skip(Math.Max(0, meter.History.Count - seconds)).ToList();
            _graph.Seconds = seconds;
            _graph.Invalidate();

            IEnumerable<AppRate> apps = meter.Apps;
            if (_activeOnly.Checked) apps = apps.Where(a => a.Down + a.Up > 0);
            if (_sortColumn >= 0)
            {
                var key = Columns[_sortColumn].Key;
                apps = _ascending ? apps.OrderBy(key) : apps.OrderByDescending(key);
            }
            RulesTab.Rebuild(_list, apps.ToList(), a => a.AppPath.Length > 0 ? a.AppPath : a.Name, a => new[]
            {
                a.Name, BandwidthMeter.Text(a.Down), BandwidthMeter.Text(a.Up), BandwidthMeter.Text(a.InternetDown), BandwidthMeter.Text(a.InternetUp),
                BandwidthMeter.Text(a.LanDown), BandwidthMeter.Text(a.LanUp), BandwidthMeter.Bytes(a.TotalDown), BandwidthMeter.Bytes(a.TotalUp), a.AppPath
            }, a => a.Down + a.Up > 0 ? SystemColors.WindowText : Theme.Closed);

            var now = meter.Now;
            Summary = $"{meter.Apps.Count(a => a.Down + a.Up > 0)} app(s) using the network now, {meter.Apps.Count} since EasyFW started.";
        }

        private ContextMenuStrip Menu()
        {
            var menu = new ContextMenuStrip();
            AppRate Selected() => _list.SelectedItems.Count > 0 ? (AppRate)_list.SelectedItems[0].Tag : null;
            menu.Items.Add("Copy row", null, (_, __) => UiHelpers.CopyRows(FindForm(), _list.SelectedItems.Cast<ListViewItem>().Select(i => i.SubItems.Cast<ListViewItem.ListViewSubItem>().Select(c => c.Text))));
            menu.Items.Add(UiHelpers.CopyPathItem(FindForm, () => _list.SelectedItems.Cast<ListViewItem>().Select(i => ((AppRate)i.Tag).AppPath)));
            menu.Items.Add("Show log (last hour)", null, (_, __) => { var a = Selected(); if (!string.IsNullOrEmpty(a?.AppPath)) AppLogForm.Open(FindForm(), _service, a.AppPath); });
            menu.Items.Add("Open file location", null, (_, __) =>
            {
                var path = Selected()?.AppPath;
                if (!string.IsNullOrEmpty(path) && File.Exists(path)) Process.Start("explorer.exe", $"/select,\"{path}\"");
            });
            menu.Opening += (_, e) => e.Cancel = _list.SelectedItems.Count == 0;
            return menu;
        }
    }

    /// <summary>Six figures in a row: total, internet and LAN, each down and up.</summary>
    internal sealed class RateTiles : Control
    {
        public RatePoint Now { get; set; }
        private readonly Font _label = new Font("Segoe UI Semibold", 8f), _value = new Font("Segoe UI Semibold", 16f);

        public RateTiles()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) { _label.Dispose(); _value.Dispose(); }
            base.Dispose(disposing);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(SystemColors.Control);
            var tiles = new (string Label, double Value, Color Accent)[]
            {
                ("TOTAL ↓ DOWN", Now.Down, Color.FromArgb(71, 85, 105)), ("TOTAL ↑ UP", Now.Up, Color.FromArgb(71, 85, 105)),
                ("INTERNET ↓", Now.InternetDown, BandwidthTab.InternetColor), ("INTERNET ↑", Now.InternetUp, BandwidthTab.InternetColor),
                ("LAN ↓", Now.LanDown, BandwidthTab.LanColor), ("LAN ↑", Now.LanUp, BandwidthTab.LanColor),
            };
            const int gap = 8;
            var width = (Width - 12 - gap * (tiles.Length - 1)) / (float)tiles.Length;
            for (var i = 0; i < tiles.Length; i++)
            {
                var box = new RectangleF(6 + i * (width + gap), 8, width, Height - 14);
                using (var back = new SolidBrush(Color.White)) g.FillRectangle(back, box);
                using (var border = new Pen(Color.FromArgb(226, 232, 240))) g.DrawRectangle(border, box.X, box.Y, box.Width, box.Height);
                using (var accent = new SolidBrush(tiles[i].Accent)) g.FillRectangle(accent, box.X, box.Y, 4, box.Height);
                using (var muted = new SolidBrush(Theme.Muted)) g.DrawString(tiles[i].Label, _label, muted, box.X + 12, box.Y + 8);
                using (var ink = new SolidBrush(Color.FromArgb(15, 23, 42))) g.DrawString(BandwidthMeter.Text(tiles[i].Value), _value, ink, box.X + 10, box.Y + 26);
            }
        }
    }

    /// <summary>Internet and LAN rates over the last minutes: solid for down, dashed for up.</summary>
    internal sealed class RateGraph : Control
    {
        public List<RatePoint> Points { get; set; } = new List<RatePoint>();
        public int Seconds { get; set; } = 120;
        private readonly Font _small = new Font("Segoe UI", 8f);

        public RateGraph()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _small.Dispose();
            base.Dispose(disposing);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(SystemColors.Control);
            var plot = new Rectangle(70, 26, Math.Max(10, Width - 84), Math.Max(10, Height - 48));
            using (var back = new SolidBrush(Color.White)) g.FillRectangle(back, plot);

            var series = new (string Name, Func<RatePoint, double> Value, Color Color, bool Dashed)[]
            {
                ("Internet down", p => p.InternetDown, BandwidthTab.InternetColor, false), ("Internet up", p => p.InternetUp, BandwidthTab.InternetColor, true),
                ("LAN down", p => p.LanDown, BandwidthTab.LanColor, false), ("LAN up", p => p.LanUp, BandwidthTab.LanColor, true),
            };
            // A round top for the scale: 1, 2 or 5 times a power of ten.
            var peak = Math.Max(1000, Points.Count == 0 ? 0 : Points.Max(p => Math.Max(Math.Max(p.InternetDown, p.InternetUp), Math.Max(p.LanDown, p.LanUp))));
            var step = Math.Pow(10, Math.Floor(Math.Log10(peak)));
            var top = new[] { 1, 2, 5, 10 }.Select(m => m * step).First(v => v >= peak);

            using (var grid = new Pen(Color.FromArgb(232, 236, 241)))
            using (var muted = new SolidBrush(Theme.Muted))
            {
                for (var i = 0; i <= 4; i++)
                {
                    var y = plot.Bottom - plot.Height * i / 4f;
                    g.DrawLine(grid, plot.Left, y, plot.Right, y);
                    var label = BandwidthMeter.Text(top * i / 4);
                    g.DrawString(label, _small, muted, plot.Left - 6 - g.MeasureString(label, _small).Width, y - 7);
                }
                g.DrawString(Seconds >= 600 ? "-10 min" : "-2 min", _small, muted, plot.Left, plot.Bottom + 3);
                const string now = "now";
                g.DrawString(now, _small, muted, plot.Right - g.MeasureString(now, _small).Width, plot.Bottom + 3);
            }

            var x = (float)plot.Left;
            foreach (var s in series)
            {
                using var pen = new Pen(s.Color, 1.8f);
                if (s.Dashed) pen.DashPattern = new[] { 3f, 2f };
                g.DrawLine(pen, x, 12, x + 22, 12);
                using var ink = new SolidBrush(Color.FromArgb(51, 65, 85));
                g.DrawString(s.Name, _small, ink, x + 26, 5);
                x += 40 + g.MeasureString(s.Name, _small).Width;
            }

            if (Points.Count < 2) return;
            var last = Points[Points.Count - 1].TimeUtc;
            foreach (var s in series)
            {
                var pts = Points.Select(p => new PointF(
                    plot.Right - (float)((last - p.TimeUtc).TotalSeconds / Seconds * plot.Width),
                    plot.Bottom - (float)(Math.Min(top, s.Value(p)) / top * plot.Height))).Where(p => p.X >= plot.Left).ToArray();
                if (pts.Length < 2) continue;
                using var pen = new Pen(s.Color, 1.8f) { LineJoin = LineJoin.Round };
                if (s.Dashed) pen.DashPattern = new[] { 3f, 2f };
                g.DrawLines(pen, pts);
            }
        }
    }
}
