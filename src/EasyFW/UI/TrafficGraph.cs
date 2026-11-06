using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Linq;
using System.Windows.Forms;
using EasyFW.Core;

namespace EasyFW.UI
{
    /// <summary>Live area chart of accepted and blocked connections per 10 seconds.</summary>
    public sealed class TrafficGraph : Control
    {
        private static readonly Color SurfaceTop = ColorTranslator.FromHtml("#3F3A86");
        private static readonly Color SurfaceBottom = ColorTranslator.FromHtml("#37326F");
        private static readonly Color AxisBand = ColorTranslator.FromHtml("#4A4592");
        private static readonly Color Grid = Color.FromArgb(40, 255, 255, 255);
        private static readonly Color Ink = ColorTranslator.FromHtml("#F2F1FB");
        private static readonly Color InkMuted = ColorTranslator.FromHtml("#C9C6EE");
        private static readonly Color AcceptedLine = ColorTranslator.FromHtml("#4790E0");
        private static readonly Color AcceptedLow = ColorTranslator.FromHtml("#6A4FE0");
        private static readonly Color BlockedLine = ColorTranslator.FromHtml("#E05A9F");
        private static readonly Color BlockedLow = ColorTranslator.FromHtml("#B23FB8");

        private readonly TrafficHistory _history;
        private readonly Font _small = new Font("Segoe UI", 8.25f);
        private int _hoverIndex = -1;

        public TrafficGraph(TrafficHistory history)
        {
            _history = history;
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            Dock = DockStyle.Top;
            Height = 170;
            AccessibleName = "Accepted and blocked connections per 10 seconds";
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _small.Dispose();
            base.Dispose(disposing);
        }

        private float Px(float value) => value * DeviceDpi / 96f;

        private RectangleF PlotArea() => new RectangleF(Px(40), Px(30), Math.Max(1, Width - Px(40) - Px(30)), Math.Max(1, Height - Px(30) - Px(24)));

        private float Step(RectangleF plot) => plot.Width / (TrafficHistory.Capacity - 1);

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            var plot = PlotArea();
            var fromEnd = (int)Math.Round((plot.Right - e.X) / Step(plot));
            var index = _history.Samples.Count - 1 - Math.Max(0, fromEnd);
            if (index < 0 || !plot.Contains(e.Location)) index = -1;
            if (index == _hoverIndex) return;
            _hoverIndex = index;
            Invalidate();
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            if (_hoverIndex < 0) return;
            _hoverIndex = -1;
            Invalidate();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

            var bounds = new Rectangle(0, 0, Width, Height);
            if (Width <= 0 || Height <= 0) return;
            using (var surface = new LinearGradientBrush(bounds, SurfaceTop, SurfaceBottom, LinearGradientMode.Vertical))
                g.FillRectangle(surface, bounds);

            var plot = PlotArea();
            using (var band = new SolidBrush(AxisBand))
                g.FillRectangle(band, 0, plot.Bottom, Width, Height - plot.Bottom);

            var samples = _history.Samples;
            var axisMax = TrafficHistory.AxisMax(samples.Count == 0 ? 0 : samples.Max(s => Math.Max(s.Accepted, s.Blocked)));
            DrawYAxis(g, plot, axisMax);
            DrawTimeAxis(g, plot);

            if (samples.Count == 0)
            {
                TextRenderer.DrawText(g, $"Collecting the first {TrafficHistory.IntervalSeconds} seconds...", Font, Rectangle.Round(plot), InkMuted,
                    TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
            }
            else
            {
                DrawSeries(g, plot, axisMax, s => s.Accepted, AcceptedLine, AcceptedLow);
                DrawSeries(g, plot, axisMax, s => s.Blocked, BlockedLine, BlockedLow);
                DrawMarkers(g, plot, axisMax, _hoverIndex >= 0 && _hoverIndex < samples.Count ? _hoverIndex : samples.Count - 1);
            }
            DrawLegend(g);
        }

        private PointF Point(RectangleF plot, int axisMax, int index, int value) => new PointF(
            plot.Right - (_history.Samples.Count - 1 - index) * Step(plot),
            plot.Bottom - plot.Height * value / axisMax);

        private void DrawSeries(Graphics g, RectangleF plot, int axisMax, Func<TrafficSample, int> value, Color line, Color low)
        {
            var samples = _history.Samples;
            var points = samples.Select((s, i) => Point(plot, axisMax, i, value(s))).ToArray();
            if (points.Length < 2) return;

            using var curve = new GraphicsPath();
            AddSmoothCurve(curve, points);
            using var area = new GraphicsPath();
            area.AddLine(points[0].X, plot.Bottom, points[0].X, points[0].Y);
            AddSmoothCurve(area, points);
            area.AddLine(points[points.Length - 1].X, points[points.Length - 1].Y, points[points.Length - 1].X, plot.Bottom);
            area.CloseFigure();

            var fillRect = new RectangleF(plot.X, plot.Y - 1, plot.Width, plot.Height + 2);
            using (var fill = new LinearGradientBrush(fillRect, Color.FromArgb(175, line), Color.FromArgb(150, low), LinearGradientMode.Vertical))
                g.FillPath(fill, area);
            using (var pen = new Pen(line, Px(1.5f)))
                g.DrawPath(pen, curve);
        }

        /// <summary>Monotone curve: smooth like the reference, but never dips below zero or peaks above the real count.</summary>
        private static void AddSmoothCurve(GraphicsPath path, IReadOnlyList<PointF> p)
        {
            var dx = p[1].X - p[0].X;
            var slopes = new float[p.Count - 1];
            for (var i = 0; i < slopes.Length; i++) slopes[i] = (p[i + 1].Y - p[i].Y) / dx;

            var tangents = new float[p.Count];
            tangents[0] = slopes[0];
            tangents[p.Count - 1] = slopes[slopes.Length - 1];
            for (var i = 1; i < p.Count - 1; i++)
                tangents[i] = slopes[i - 1] * slopes[i] <= 0 ? 0 : 2 * slopes[i - 1] * slopes[i] / (slopes[i - 1] + slopes[i]);

            for (var i = 0; i < p.Count - 1; i++)
            {
                path.AddBezier(p[i],
                    new PointF(p[i].X + dx / 3, p[i].Y + tangents[i] * dx / 3),
                    new PointF(p[i + 1].X - dx / 3, p[i + 1].Y - tangents[i + 1] * dx / 3),
                    p[i + 1]);
            }
        }

        private void DrawMarkers(Graphics g, RectangleF plot, int axisMax, int index)
        {
            var sample = _history.Samples[index];
            var accepted = Point(plot, axisMax, index, sample.Accepted);
            var blocked = Point(plot, axisMax, index, sample.Blocked);
            if (index == _hoverIndex)
            {
                using var cross = new Pen(Color.FromArgb(130, Ink), 1);
                g.DrawLine(cross, accepted.X, plot.Top, accepted.X, plot.Bottom);
            }
            DrawDot(g, accepted, AcceptedLine);
            DrawDot(g, blocked, BlockedLine);
        }

        private void DrawDot(Graphics g, PointF at, Color color)
        {
            var r = Px(4);
            using var fill = new SolidBrush(color);
            using var ring = new Pen(SurfaceBottom, Px(2));
            g.FillEllipse(fill, at.X - r, at.Y - r, r * 2, r * 2);
            g.DrawEllipse(ring, at.X - r, at.Y - r, r * 2, r * 2);
        }

        private void DrawYAxis(Graphics g, RectangleF plot, int axisMax)
        {
            using var pen = new Pen(Grid, 1);
            foreach (var value in new[] { axisMax, axisMax / 2, 0 })
            {
                var y = plot.Bottom - plot.Height * value / axisMax;
                if (value > 0) g.DrawLine(pen, plot.Left, y, plot.Right, y);
                var label = new Rectangle(0, (int)(y - Px(9)), (int)(plot.Left - Px(6)), (int)Px(18));
                TextRenderer.DrawText(g, value.ToString(), _small, label, InkMuted, TextFormatFlags.Right | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
            }
        }

        private void DrawTimeAxis(Graphics g, RectangleF plot)
        {
            var samples = _history.Samples;
            var latest = samples.Count > 0 ? samples[samples.Count - 1].TimeUtc : TrafficHistory.Floor(DateTime.UtcNow);
            var labelWidth = TextRenderer.MeasureText("00:00:00", _small).Width;
            var minutes = Step(plot) * 60 / TrafficHistory.IntervalSeconds >= labelWidth * 1.5f ? 1 : 2;
            var band = new RectangleF(plot.X, plot.Bottom, plot.Width, Height - plot.Bottom);
            for (var k = 0; k < TrafficHistory.Capacity; k++)
            {
                var t = latest.AddSeconds(-TrafficHistory.IntervalSeconds * k);
                if (t.Second != 0 || t.Minute % minutes != 0) continue;
                var x = plot.Right - k * Step(plot);
                if (x - labelWidth / 2f < 0 || x + labelWidth / 2f > Width) continue;
                var label = new Rectangle((int)(x - labelWidth / 2f), (int)band.Y, labelWidth, (int)band.Height);
                TextRenderer.DrawText(g, t.ToLocalTime().ToString("HH:mm:ss"), _small, label, InkMuted, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
            }
        }

        private void DrawLegend(Graphics g)
        {
            var samples = _history.Samples;
            var hovering = _hoverIndex >= 0 && _hoverIndex < samples.Count;
            var sample = hovering ? samples[_hoverIndex] : samples.Count > 0 ? samples[samples.Count - 1] : default;
            var x = (int)Px(10);
            x = DrawLegendItem(g, x, AcceptedLine, $"Accepted  {sample.Accepted}");
            x = DrawLegendItem(g, x + (int)Px(14), BlockedLine, $"Blocked  {sample.Blocked}");

            var note = hovering
                ? "at " + sample.TimeUtc.ToLocalTime().ToString("HH:mm:ss")
                : $"connections per {TrafficHistory.IntervalSeconds} seconds, last {TrafficHistory.Capacity * TrafficHistory.IntervalSeconds / 60} minutes";
            TextRenderer.DrawText(g, note, _small, new Rectangle(x + (int)Px(14), 0, Math.Max(0, Width - x), (int)Px(28)), InkMuted,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding | TextFormatFlags.EndEllipsis);
        }

        private int DrawLegendItem(Graphics g, int x, Color color, string text)
        {
            var size = Px(10);
            var top = (Px(28) - size) / 2;
            using (var swatch = new SolidBrush(color))
                g.FillEllipse(swatch, x, top, size, size);
            x += (int)(size + Px(6));
            var width = TextRenderer.MeasureText(text, Font).Width;
            TextRenderer.DrawText(g, text, Font, new Rectangle(x, 0, width, (int)Px(28)), Ink, TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
            return x + width;
        }
    }
}
