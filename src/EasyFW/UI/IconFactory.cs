using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;

namespace EasyFW.UI
{
    public static class IconFactory
    {
        public enum TrayState { On, Pending, Off }

        private static readonly Dictionary<TrayState, Icon> Cache = new Dictionary<TrayState, Icon>();

        [DllImport("user32.dll")]
        private static extern bool DestroyIcon(IntPtr handle);

        public static Icon Tray(TrayState state)
        {
            if (Cache.TryGetValue(state, out var icon)) return icon;
            using (var bmp = Shield(32, state))
            {
                var h = bmp.GetHicon();
                using (var temp = Icon.FromHandle(h)) icon = (Icon)temp.Clone();
                DestroyIcon(h);
            }
            Cache[state] = icon;
            return icon;
        }

        public static Bitmap Shield(int size, TrayState state)
        {
            var color = state == TrayState.On ? Theme.Good : state == TrayState.Pending ? Theme.Warn : Theme.Off;
            var bmp = new Bitmap(size, size);
            using var g = Graphics.FromImage(bmp);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            float s = size / 32f;
            using (var path = new GraphicsPath())
            {
                path.AddLines(new[] { new PointF(16 * s, 1 * s), new PointF(29 * s, 6 * s) });
                path.AddBezier(29 * s, 6 * s, 29 * s, 18 * s, 25 * s, 26 * s, 16 * s, 31 * s);
                path.AddBezier(16 * s, 31 * s, 7 * s, 26 * s, 3 * s, 18 * s, 3 * s, 6 * s);
                path.CloseFigure();
                using var fill = new SolidBrush(color);
                g.FillPath(fill, path);
            }
            using var pen = new Pen(Color.White, 3.2f * s) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round };
            switch (state)
            {
                case TrayState.On:
                    g.DrawLines(pen, new[] { new PointF(10 * s, 16 * s), new PointF(14.5f * s, 21 * s), new PointF(22 * s, 11 * s) });
                    break;
                case TrayState.Pending:
                    g.DrawLine(pen, 16 * s, 9 * s, 16 * s, 17 * s);
                    using (var dot = new SolidBrush(Color.White)) g.FillEllipse(dot, 14 * s, 21 * s, 4 * s, 4 * s);
                    break;
                default:
                    g.DrawLine(pen, 11 * s, 11 * s, 21 * s, 21 * s);
                    g.DrawLine(pen, 21 * s, 11 * s, 11 * s, 21 * s);
                    break;
            }
            return bmp;
        }
    }

    public static class Theme
    {
        public static readonly Color Good = Color.FromArgb(21, 128, 61);
        public static readonly Color Warn = Color.FromArgb(180, 83, 9);
        public static readonly Color Off = Color.FromArgb(185, 28, 28);
        public static readonly Color Blocked = Color.FromArgb(185, 28, 28);
        public static readonly Color BlockedRow = Color.FromArgb(254, 242, 242);
        public static readonly Color Closed = Color.FromArgb(107, 114, 128);
        public static readonly Color Header = Color.FromArgb(248, 250, 252);
        public static readonly Color BannerBack = Color.FromArgb(254, 243, 199);
        public static readonly Color BannerText = Color.FromArgb(120, 53, 15);
        public static readonly Color Muted = Color.FromArgb(75, 85, 99);
        public static readonly Font Base = new Font("Segoe UI", 9f);
        public static readonly Font Title = new Font("Segoe UI Semibold", 13f);
        public static readonly Font Heading = new Font("Segoe UI Semibold", 10f);
    }
}
