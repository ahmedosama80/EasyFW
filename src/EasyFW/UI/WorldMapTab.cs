using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Linq;
using System.Windows.Forms;
using EasyFW.Core;

namespace EasyFW.UI
{
    /// <summary>
    /// A world map of where this PC's traffic goes and comes from, drawn like an operations-centre wall screen:
    /// outgoing, incoming and blocked arcs, open connections animated, and a timeline to look back 30 minutes.
    /// </summary>
    public sealed class WorldMapTab : Control
    {
        private static readonly Color BackTop = Hex("#0B1730"), BackBottom = Hex("#050B18"), PanelBack = Hex("#0A1528"), PanelLine = Hex("#1B2D4C"),
            TileBack = Hex("#0F1F38"), LandDot = Hex("#1F3B62"), Ink = Hex("#E8F0FB"), InkMuted = Hex("#8FA4C3"), InkFaint = Hex("#5A6E8D"),
            OutColor = Hex("#22D3EE"), InColor = Hex("#C084FC"), BlockColor = Hex("#FB4D6D"), HomeColor = Hex("#34D399"), ReplayColor = Hex("#FBBF24");

        private const int TimelineMinutes = 30, TimelineBuckets = 60, TimelineHeight = 84;
        private static readonly int[] WindowChoices = { 1, 5, 15, 30 };

        private readonly FirewallService _service;
        private readonly Timer _timer = new Timer { Interval = 33 };
        private readonly Stopwatch _clock = Stopwatch.StartNew();
        private readonly Dictionary<string, string> _countries = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly List<(Rectangle Bounds, Action Click)> _buttons = new List<(Rectangle, Action)>();
        private readonly List<Arc> _arcs = new List<Arc>();
        private readonly List<Node> _nodes = new List<Node>();
        private readonly Font _titleFont = new Font("Segoe UI Semibold", 11f), _small = new Font("Segoe UI", 8f), _smallBold = new Font("Segoe UI Semibold", 8f),
            _body = new Font("Segoe UI", 9f), _value = new Font("Segoe UI Semibold", 17f), _label = new Font("Segoe UI Semibold", 7.5f);

        private GeoSnapshot _snap = new GeoSnapshot();
        private GeoBucket[] _timeline = new GeoBucket[TimelineBuckets];
        private DateTime _nowUtc = DateTime.UtcNow;
        private int _window = 5;
        private double _offset;
        private string _home = "DE";
        private MapLocation _location;
        private bool _asked;

        /// <summary>Off in tests, so a dialog never waits for a click.</summary>
        public static bool AskForLocation { get; set; } = true;
        private int _infoVersion = -1;
        private Bitmap _background;
        private Rectangle _panel, _mapArea, _timelineRect, _bars;
        private RectangleF _map;
        private Node _hover;
        private Point _mouse;
        private bool _dragging;

        public string Summary { get; private set; } = "";

        /// <summary>Minutes back from now that the map shows. 0 is live.</summary>
        public double Offset
        {
            get => _offset;
            set { _offset = Math.Max(0, Math.Min(TimelineMinutes, value)); RefreshData(); }
        }

        /// <summary>How many minutes of attempts the map shows.</summary>
        public int WindowMinutes
        {
            get => _window;
            set { _window = WindowChoices.Contains(value) ? value : 5; RefreshData(); }
        }

        public WorldMapTab(FirewallService service)
        {
            _service = service;
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            BackColor = BackBottom;
            _timer.Tick += (_, __) =>
            {
                var form = FindForm();
                if (Visible && form != null && form.Visible && form.WindowState != FormWindowState.Minimized) Invalidate();
            };
            _timer.Start();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _timer.Dispose();
                _background?.Dispose();
                foreach (var f in new[] { _titleFont, _small, _smallBold, _body, _value, _label }) f.Dispose();
            }
            base.Dispose(disposing);
        }

        // ---------- data ----------

        public void RefreshData()
        {
            if (IpInfo.Version != _infoVersion)
            {
                _countries.Clear();
                _infoVersion = IpInfo.Version;
            }
            _nowUtc = DateTime.UtcNow;
            var live = _offset <= 0;
            var to = _nowUtc.AddMinutes(-_offset);
            var events = _service.History.All;
            var active = live ? _service.Connections.Query(new ConnectionFilter(), ConnectionColumn.Time, false) : null;
            _snap = GeoTraffic.Build(events, active, to.AddMinutes(-_window), to, live, Country);
            _timeline = GeoTraffic.Timeline(events, _nowUtc, TimeSpan.FromMinutes(TimelineMinutes), TimelineBuckets, Country);
            var location = _service.Location;
            _home = location.Country;
            _location = location;
            MaybeAskLocation();
            BuildScene();
            Summary = $"World map: {_snap.Countries.Count} countries, {_snap.Out} outgoing, {_snap.In} incoming, {_snap.Blocked} blocked" +
                      (live ? $", {_snap.Active} open now (last {_window} min, live)" : $" ({When(_snap.FromUtc)} to {When(_snap.ToUtc)})");
            Invalidate();
        }

        private string Country(string ip)
        {
            if (!_countries.TryGetValue(ip, out var code))
            {
                if (_countries.Count > 50000) _countries.Clear();
                _countries[ip] = code = IpInfo.CountryCode(ip);
            }
            return code;
        }

        private static string When(DateTime utc) => utc.ToLocalTime().ToString("HH:mm");

        // ---------- layout ----------

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            InvalidateBackground();
            BuildScene();
        }

        private void InvalidateBackground()
        {
            _background?.Dispose();
            _background = null;
        }

        private void DoLayout()
        {
            var panelWidth = Math.Max(250, Math.Min(310, Width / 4));
            _panel = new Rectangle(Width - panelWidth, 0, panelWidth, Height);
            _mapArea = new Rectangle(0, 0, Width - panelWidth, Math.Max(0, Height - TimelineHeight));
            _timelineRect = new Rectangle(0, _mapArea.Bottom, _mapArea.Width, TimelineHeight);
            _bars = new Rectangle(_timelineRect.X + 18, _timelineRect.Y + 28, Math.Max(1, _timelineRect.Width - 36), TimelineHeight - 48);

            const double aspect = 360 / (WorldGeo.North - WorldGeo.South);
            var avail = new RectangleF(_mapArea.X + 14, _mapArea.Y + 52, Math.Max(1, _mapArea.Width - 28), Math.Max(1, _mapArea.Height - 60));
            var w = (float)Math.Min(avail.Width, avail.Height * aspect);
            var h = (float)(w / aspect);
            _map = new RectangleF(avail.X + (avail.Width - w) / 2, avail.Y + (avail.Height - h) / 2, w, h);
        }

        private PointF Project(double lat, double lon) => new PointF(
            _map.X + (float)((lon + 180) / 360 * _map.Width),
            _map.Y + (float)((WorldGeo.North - lat) / (WorldGeo.North - WorldGeo.South) * _map.Height));

        private void Unproject(Point p, out double lat, out double lon)
        {
            lon = (p.X - _map.X) / _map.Width * 360 - 180;
            lat = WorldGeo.North - (p.Y - _map.Y) / _map.Height * (WorldGeo.North - WorldGeo.South);
        }

        private PointF HomePoint => _location != null ? Project(_location.Lat, _location.Lon) : Project(50, 10);

        // ---------- scene ----------

        private sealed class Arc
        {
            public PointF A, C1, C2, B;
            public float Length, Seed, StopAt = 1f;
            public Color Color;
            public int Count;
            public bool Dashed, Active;
            public float Strength;
        }

        private sealed class Node
        {
            public GeoFlow Flow;
            public PointF At;
            public float Radius;
        }

        private void BuildScene()
        {
            DoLayout();
            _arcs.Clear();
            _nodes.Clear();
            if (_map.Width < 10) return;
            var home = HomePoint;
            var windowSeconds = Math.Max(60, (_snap.ToUtc - _snap.FromUtc).TotalSeconds);
            var rank = 0;
            foreach (var flow in _snap.Countries)
            {
                if (!WorldGeo.TryLocate(flow.Country, out var lat, out var lon)) continue;
                var at = Project(lat, lon);
                _nodes.Add(new Node { Flow = flow, At = at, Radius = 3.5f + (float)Math.Min(9, Math.Sqrt(flow.Total) * 0.8) });
                if (rank++ >= 45 || flow.Country == _home) continue;

                var recency = (float)Math.Max(0, 1 - (_snap.ToUtc - flow.LastUtc).TotalSeconds / windowSeconds);
                var seed = (flow.Country[0] * 31 + flow.Country[1]) % 100 / 100f;
                if (flow.Out > 0) _arcs.Add(MakeArc(home, at, 0.30f, OutColor, flow.Out, false, flow.ActiveOut > 0, recency, seed, 1f));
                if (flow.In > 0) _arcs.Add(MakeArc(at, home, -0.20f, InColor, flow.In, false, flow.ActiveIn > 0, recency, seed + 0.3f, 1f));
                if (flow.Blocked > 0)
                {
                    var inbound = flow.InBlocked >= flow.OutBlocked;
                    _arcs.Add(inbound
                        ? MakeArc(at, home, -0.42f, BlockColor, flow.Blocked, true, false, recency, seed + 0.6f, 0.9f)
                        : MakeArc(home, at, 0.42f, BlockColor, flow.Blocked, true, false, recency, seed + 0.6f, 0.12f));
                }
            }
        }

        /// <param name="bend">How far the arc rises, as a share of its length. Out, in and blocked rise by different amounts so they don't overlap.</param>
        private static Arc MakeArc(PointF a, PointF b, float bend, Color color, int count, bool dashed, bool active, float recency, float seed, float stopAt)
        {
            var dx = b.X - a.X;
            var dy = b.Y - a.Y;
            var length = (float)Math.Sqrt(dx * dx + dy * dy);
            var nx = -dy / Math.Max(1, length);
            var ny = dx / Math.Max(1, length);
            if (ny > 0) { nx = -nx; ny = -ny; }   // always rise towards the top of the screen
            var height = Math.Max(16, Math.Abs(bend) * length);
            var mid = new PointF((a.X + b.X) / 2 + nx * height, (a.Y + b.Y) / 2 + ny * height);
            return new Arc
            {
                A = a, B = b,
                C1 = new PointF(a.X + 2f / 3 * (mid.X - a.X), a.Y + 2f / 3 * (mid.Y - a.Y)),
                C2 = new PointF(b.X + 2f / 3 * (mid.X - b.X), b.Y + 2f / 3 * (mid.Y - b.Y)),
                Length = length + height, Color = color, Count = count, Dashed = dashed, Active = active, Seed = seed, StopAt = stopAt,
                Strength = active ? 1f : 0.35f + 0.65f * recency
            };
        }

        private static PointF At(Arc arc, float t)
        {
            var u = 1 - t;
            return new PointF(
                u * u * u * arc.A.X + 3 * u * u * t * arc.C1.X + 3 * u * t * t * arc.C2.X + t * t * t * arc.B.X,
                u * u * u * arc.A.Y + 3 * u * u * t * arc.C1.Y + 3 * u * t * t * arc.C2.Y + t * t * t * arc.B.Y);
        }

        // ---------- painting ----------

        protected override void OnPaint(PaintEventArgs e)
        {
            if (_background == null || _background.Size != ClientSize)
            {
                DoLayout();
                _background?.Dispose();
                _background = Width > 0 && Height > 0 ? BuildBackground() : null;
                BuildScene();
            }
            var g = e.Graphics;
            if (_background != null) g.DrawImageUnscaled(_background, 0, 0);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
            _buttons.Clear();
            var time = (float)_clock.Elapsed.TotalSeconds;

            g.SetClip(_mapArea);
            DrawArcs(g, time);
            DrawNodes(g, time);
            DrawHome(g, time);
            DrawHeader(g, time);
            DrawLegend(g);
            g.ResetClip();
            DrawTimeline(g);
            DrawPanel(g);
            if (_hover != null) DrawTooltip(g, _hover);
        }

        private Bitmap BuildBackground()
        {
            var bmp = new Bitmap(Width, Height);
            using var g = Graphics.FromImage(bmp);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (var back = new LinearGradientBrush(new Rectangle(0, 0, Width, Height), BackTop, BackBottom, 90f)) g.FillRectangle(back, 0, 0, Width, Height);

            if (_map.Width > 10)
            {
                using (var glowPath = new GraphicsPath())
                {
                    glowPath.AddEllipse(_map.X - _map.Width * 0.08f, _map.Y - _map.Height * 0.25f, _map.Width * 1.16f, _map.Height * 1.5f);
                    using var glow = new PathGradientBrush(glowPath) { CenterColor = Color.FromArgb(70, 24, 72, 150), SurroundColors = new[] { Color.FromArgb(0, 24, 72, 150) } };
                    g.FillPath(glow, glowPath);
                }
                using (var grid = new Pen(Color.FromArgb(22, 130, 170, 230)))
                {
                    for (var lon = -150; lon <= 150; lon += 30) g.DrawLine(grid, Project(WorldGeo.North, lon), Project(WorldGeo.South, lon));
                    for (var lat = -40; lat <= 80; lat += 20) g.DrawLine(grid, Project(lat, -180), Project(lat, 180));
                }
                using (var equator = new Pen(Color.FromArgb(40, 130, 170, 230)) { DashStyle = DashStyle.Dot })
                    g.DrawLine(equator, Project(0, -180), Project(0, 180));

                var spacing = Math.Max(4.2f, _map.Width / 190f);
                var r = spacing * 0.34f;
                using var dot = new SolidBrush(LandDot);
                for (var y = _map.Top + spacing / 2; y < _map.Bottom; y += spacing)
                for (var x = _map.Left + spacing / 2; x < _map.Right; x += spacing)
                {
                    var lon = (x - _map.X) / _map.Width * 360 - 180;
                    var lat = WorldGeo.North - (y - _map.Y) / _map.Height * (WorldGeo.North - WorldGeo.South);
                    if (WorldGeo.IsLandFast(lon, lat)) g.FillEllipse(dot, x - r, y - r, r * 2, r * 2);
                }
            }

            using (var panel = new SolidBrush(PanelBack)) g.FillRectangle(panel, _panel);
            using (var line = new Pen(PanelLine)) g.DrawLine(line, _panel.X, 0, _panel.X, Height);
            using (var tl = new SolidBrush(Color.FromArgb(150, PanelBack))) g.FillRectangle(tl, _timelineRect);
            using (var line = new Pen(PanelLine)) g.DrawLine(line, _timelineRect.X, _timelineRect.Y, _timelineRect.Right, _timelineRect.Y);
            return bmp;
        }

        private void DrawArcs(Graphics g, float time)
        {
            foreach (var arc in _arcs)
            {
                var weight = 1.1f + (float)Math.Min(2.4, Math.Log10(arc.Count + 1) * 1.3);
                var alpha = (int)(255 * arc.Strength);
                using (var glow = new Pen(Color.FromArgb(alpha / 6, arc.Color), weight * 4.5f) { StartCap = LineCap.Round, EndCap = LineCap.Round })
                    g.DrawBezier(glow, arc.A, arc.C1, arc.C2, arc.B);
                using (var core = new Pen(Color.FromArgb(Math.Max(60, alpha * 3 / 4), arc.Color), weight))
                {
                    if (arc.Dashed) core.DashPattern = new[] { 3f, 2.2f };
                    g.DrawBezier(core, arc.A, arc.C1, arc.C2, arc.B);
                }

                // Packets travelling along the arc. Blocked ones stop at the firewall with a flash.
                var particles = arc.Active ? Math.Min(5, 2 + (int)Math.Log(arc.Count + 1, 2)) : Math.Min(3, 1 + (int)Math.Log10(arc.Count + 1));
                var speed = (arc.Active ? 170f : 110f) / Math.Max(60, arc.Length);
                for (var i = 0; i < particles; i++)
                {
                    var t = (time * speed + arc.Seed + i / (float)particles) % 1f;
                    if (arc.StopAt < 1f)
                    {
                        // Blocked: the packet travels to the firewall in the first 60% of its cycle, then flashes there.
                        if (t > 0.6f)
                        {
                            var phase = (t - 0.6f) / 0.4f;
                            var p = At(arc, arc.StopAt);
                            var rr = 3 + phase * 9;
                            using var ring = new Pen(Color.FromArgb((int)(200 * (1 - phase) * arc.Strength), arc.Color), 1.4f);
                            g.DrawEllipse(ring, p.X - rr, p.Y - rr, rr * 2, rr * 2);
                            continue;
                        }
                        t = t / 0.6f * arc.StopAt;
                    }
                    Comet(g, arc, t, alpha);
                }
                if (arc.StopAt < 1f) Blocker(g, At(arc, arc.StopAt), arc.Color, alpha);
            }
        }

        private static void Comet(Graphics g, Arc arc, float t, int alpha)
        {
            for (var k = 4; k >= 0; k--)
            {
                var tt = t - k * 0.012f;
                if (tt < 0) continue;
                var p = At(arc, tt);
                var size = k == 0 ? 2.6f : 2.2f - k * 0.35f;
                using var b = new SolidBrush(Color.FromArgb(Math.Max(10, alpha * (5 - k) / 5), k == 0 ? Color.White : arc.Color));
                g.FillEllipse(b, p.X - size, p.Y - size, size * 2, size * 2);
            }
            var head = At(arc, t);
            using var halo = new SolidBrush(Color.FromArgb(alpha / 4, arc.Color));
            g.FillEllipse(halo, head.X - 6, head.Y - 6, 12, 12);
        }

        /// <summary>A small crossed ring: the firewall that stopped the attempt.</summary>
        private static void Blocker(Graphics g, PointF p, Color color, int alpha)
        {
            using var back = new SolidBrush(Color.FromArgb(220, BackBottom));
            using var pen = new Pen(Color.FromArgb(Math.Max(120, alpha), color), 1.4f);
            g.FillEllipse(back, p.X - 5, p.Y - 5, 10, 10);
            g.DrawEllipse(pen, p.X - 5, p.Y - 5, 10, 10);
            g.DrawLine(pen, p.X - 2.4f, p.Y - 2.4f, p.X + 2.4f, p.Y + 2.4f);
            g.DrawLine(pen, p.X + 2.4f, p.Y - 2.4f, p.X - 2.4f, p.Y + 2.4f);
        }

        private void DrawNodes(Graphics g, float time)
        {
            var labelled = 0;
            foreach (var node in _nodes.AsEnumerable().Reverse())
            {
                var f = node.Flow;
                var r = node.Radius;
                var main = f.Blocked > f.Out + f.In ? BlockColor : f.In > f.Out ? InColor : OutColor;
                if (f.Active > 0)
                {
                    var phase = (time * 0.6f + node.At.X * 0.01f) % 1f;
                    var pr = r + 2 + phase * 14;
                    using var pulse = new Pen(Color.FromArgb((int)(150 * (1 - phase)), main), 1.2f);
                    g.DrawEllipse(pulse, node.At.X - pr, node.At.Y - pr, pr * 2, pr * 2);
                }
                using (var glow = new SolidBrush(Color.FromArgb(45, main))) g.FillEllipse(glow, node.At.X - r - 4, node.At.Y - r - 4, (r + 4) * 2, (r + 4) * 2);
                using (var fill = new SolidBrush(Color.FromArgb(235, BackBottom))) g.FillEllipse(fill, node.At.X - r, node.At.Y - r, r * 2, r * 2);

                // A ring split by share: outgoing, incoming, blocked.
                var parts = new[] { (f.Out, OutColor), (f.In, InColor), (f.Blocked, BlockColor) };
                var total = Math.Max(1, parts.Sum(p => p.Item1));
                var start = -90f;
                foreach (var (n, color) in parts)
                {
                    if (n <= 0) continue;
                    var sweep = 360f * n / total;
                    using var pen = new Pen(color, Math.Max(2f, r * 0.42f));
                    g.DrawArc(pen, node.At.X - r, node.At.Y - r, r * 2, r * 2, start, Math.Max(1f, sweep - (sweep < 360 ? 3 : 0)));
                    start += sweep;
                }
                using (var centre = new SolidBrush(Color.FromArgb(230, Color.White))) g.FillEllipse(centre, node.At.X - 1.3f, node.At.Y - 1.3f, 2.6f, 2.6f);
            }

            var taken = new List<RectangleF>();
            foreach (var node in _nodes.Take(12))
            {
                if (node == _hover) continue;
                var text = $"{node.Flow.Country}  {Compact(node.Flow.Total)}";
                var size = g.MeasureString(text, _smallBold);
                var box = new RectangleF(node.At.X + node.Radius + 5, node.At.Y - size.Height / 2 - 1, size.Width + 4, size.Height + 2);
                if (!_mapArea.Contains(Rectangle.Round(box))) box.X = node.At.X - node.Radius - 5 - box.Width;
                if (taken.Any(t => t.IntersectsWith(box))) box.X = node.At.X - node.Radius - 5 - box.Width;
                if (taken.Any(t => t.IntersectsWith(box))) continue;
                taken.Add(box);
                using (var path = Rounded(box, 4))
                using (var back = new SolidBrush(Color.FromArgb(200, 8, 18, 36)))
                using (var border = new Pen(Color.FromArgb(60, InkMuted)))
                {
                    g.FillPath(back, path);
                    g.DrawPath(border, path);
                }
                using var ink = new SolidBrush(Ink);
                g.DrawString(text, _smallBold, ink, box.X + 2, box.Y + 1);
                if (++labelled >= 10) break;
            }
        }

        private void DrawHome(Graphics g, float time)
        {
            var p = HomePoint;
            for (var i = 0; i < 3; i++)
            {
                var phase = (time * 0.45f + i / 3f) % 1f;
                var r = 5 + phase * 26;
                using var ring = new Pen(Color.FromArgb((int)(170 * (1 - phase)), HomeColor), 1.5f);
                g.DrawEllipse(ring, p.X - r, p.Y - r, r * 2, r * 2);
            }
            using (var glow = new SolidBrush(Color.FromArgb(70, HomeColor))) g.FillEllipse(glow, p.X - 10, p.Y - 10, 20, 20);
            using (var dot = new SolidBrush(HomeColor)) g.FillEllipse(dot, p.X - 5, p.Y - 5, 10, 10);
            using (var core = new SolidBrush(Color.White)) g.FillEllipse(core, p.X - 2, p.Y - 2, 4, 4);

            var text = "THIS PC";
            var size = g.MeasureString(text, _label);
            var box = new RectangleF(p.X - size.Width / 2 - 5, p.Y + 13, size.Width + 10, size.Height + 2);
            using (var path = Rounded(box, 5))
            using (var back = new SolidBrush(Color.FromArgb(220, 6, 40, 34)))
            using (var border = new Pen(Color.FromArgb(160, HomeColor)))
            {
                g.FillPath(back, path);
                g.DrawPath(border, path);
            }
            using var ink = new SolidBrush(HomeColor);
            g.DrawString(text, _label, ink, box.X + 5, box.Y + 1);
        }

        private void DrawHeader(Graphics g, float time)
        {
            using var ink = new SolidBrush(Ink);
            using var muted = new SolidBrush(InkMuted);
            const string title = "GLOBAL CONNECTIONS";
            g.DrawString(title, _titleFont, ink, 16, 12);
            var titleWidth = g.MeasureString(title, _titleFont).Width;

            var live = _snap.Live;
            var pill = new RectangleF(16 + titleWidth + 8, 14, live ? 54 : 128, 20);
            var color = live ? HomeColor : ReplayColor;
            using (var path = Rounded(pill, 10))
            using (var back = new SolidBrush(Color.FromArgb(40, color)))
            using (var border = new Pen(Color.FromArgb(150, color)))
            {
                g.FillPath(back, path);
                g.DrawPath(border, path);
            }
            var blink = live ? (int)(140 + 115 * Math.Sin(time * 4)) : 255;
            using (var dot = new SolidBrush(Color.FromArgb(Math.Max(0, Math.Min(255, blink)), color))) g.FillEllipse(dot, pill.X + 8, pill.Y + 6.5f, 7, 7);
            using (var pillInk = new SolidBrush(color)) g.DrawString(live ? "LIVE" : "BACK TO LIVE  ›", _smallBold, pillInk, pill.X + 19, pill.Y + 3);
            if (!live) _buttons.Add((Rectangle.Round(pill), () => Offset = 0));

            var sub = live
                ? $"Last {Minutes(_window)} and every connection open now"
                : $"Looking back: {When(_snap.FromUtc)} – {When(_snap.ToUtc)}, {Minutes(_window)} of attempts · open connections are only known live";
            g.DrawString(sub, _small, muted, 17, 34);
            DrawLocationChip(g);
        }

        /// <summary>Top right of the map: where this PC is, how that was found, and the public IP. Click to change.</summary>
        private void DrawLocationChip(Graphics g)
        {
            if (_location == null) return;
            var place = _location.Text.ToUpperInvariant();
            var detail = (PublicIp.Address != null ? "PUBLIC IP " + PublicIp.Address + " · " : "") + _location.SourceText.ToUpperInvariant() + " · CHANGE ▾";
            var width = Math.Max(g.MeasureString(place, _smallBold).Width, g.MeasureString(detail, _label).Width) + 34;
            var chip = new RectangleF(_mapArea.Right - width - 14, 10, width, 38);
            using (var path = Rounded(chip, 8))
            using (var back = new SolidBrush(Color.FromArgb(200, 6, 30, 28)))
            using (var border = new Pen(Color.FromArgb(150, HomeColor)))
            {
                g.FillPath(back, path);
                g.DrawPath(border, path);
            }
            // A map pin.
            using (var pin = new SolidBrush(HomeColor))
            {
                g.FillEllipse(pin, chip.X + 10, chip.Y + 9, 10, 10);
                g.FillPolygon(pin, new[] { new PointF(chip.X + 11, chip.Y + 16), new PointF(chip.X + 19, chip.Y + 16), new PointF(chip.X + 15, chip.Y + 26) });
            }
            using (var hole = new SolidBrush(Color.FromArgb(255, 6, 30, 28))) g.FillEllipse(hole, chip.X + 13, chip.Y + 12, 4, 4);
            using (var ink = new SolidBrush(Ink)) g.DrawString(place, _smallBold, ink, chip.X + 26, chip.Y + 4);
            using (var muted = new SolidBrush(HomeColor)) g.DrawString(detail, _label, muted, chip.X + 26, chip.Y + 20);
            _buttons.Add((Rectangle.Round(chip), ChooseLocation));
        }

        private static string Minutes(int m) => m == 1 ? "1 minute" : $"{m} minutes";

        private void DrawLegend(Graphics g)
        {
            var items = new (string Text, Color Color, int Kind)[]
            {
                ("Outgoing", OutColor, 0), ("Incoming", InColor, 0), ("Blocked", BlockColor, 1), ("Open now", Color.White, 2), ("This PC", HomeColor, 3)
            };
            var x = 16f;
            var y = _mapArea.Bottom - 26f;
            using var ink = new SolidBrush(InkMuted);
            using (var back = new SolidBrush(Color.FromArgb(170, 6, 13, 27)))
            using (var path = Rounded(new RectangleF(8, y - 6, 470, 24), 6))
                g.FillPath(back, path);
            foreach (var (text, color, kind) in items)
            {
                switch (kind)
                {
                    case 0:
                        using (var pen = new Pen(color, 2f)) g.DrawLine(pen, x, y + 6, x + 18, y + 6);
                        break;
                    case 1:
                        using (var pen = new Pen(color, 2f) { DashPattern = new[] { 2f, 1.5f } }) g.DrawLine(pen, x, y + 6, x + 12, y + 6);
                        Blocker(g, new PointF(x + 16, y + 6), color, 255);
                        break;
                    case 2:
                        using (var b = new SolidBrush(color)) g.FillEllipse(b, x + 6, y + 3, 6, 6);
                        using (var pen = new Pen(Color.FromArgb(150, color))) g.DrawEllipse(pen, x + 2, y - 1, 14, 14);
                        break;
                    default:
                        using (var b = new SolidBrush(color)) g.FillEllipse(b, x + 5, y + 2, 8, 8);
                        break;
                }
                g.DrawString(text, _small, ink, x + 24, y - 1);
                x += 24 + g.MeasureString(text, _small).Width + 14;
            }
        }

        private void DrawTimeline(Graphics g)
        {
            using var muted = new SolidBrush(InkMuted);
            using var faint = new SolidBrush(InkFaint);
            g.DrawString("TIMELINE · LAST 30 MINUTES · drag to look back", _label, muted, _timelineRect.X + 18, _timelineRect.Y + 9);

            // Window length chips on the right.
            var x = (float)_timelineRect.Right - 18;
            foreach (var m in WindowChoices.Reverse())
            {
                var text = m + " MIN";
                var w = g.MeasureString(text, _label).Width + 14;
                x -= w;
                var chip = new RectangleF(x, _timelineRect.Y + 6, w, 18);
                var on = m == _window;
                using (var path = Rounded(chip, 9))
                using (var back = new SolidBrush(on ? Color.FromArgb(60, OutColor) : Color.FromArgb(25, InkMuted)))
                using (var border = new Pen(on ? Color.FromArgb(180, OutColor) : Color.FromArgb(60, InkMuted)))
                {
                    g.FillPath(back, path);
                    g.DrawPath(border, path);
                }
                using (var chipInk = new SolidBrush(on ? Ink : InkMuted)) g.DrawString(text, _label, chipInk, chip.X + 7, chip.Y + 2);
                var minutes = m;
                _buttons.Add((Rectangle.Round(chip), () => WindowMinutes = minutes));
                x -= 6;
            }
            g.DrawString("SHOW", _label, faint, x - 34, _timelineRect.Y + 9);

            var max = Math.Max(1, _timeline.Max(b => b.Total));
            var barWidth = _bars.Width / (float)TimelineBuckets;
            for (var i = 0; i < _timeline.Length; i++)
            {
                var b = _timeline[i];
                var bx = _bars.X + i * barWidth + 1;
                var bottom = (float)_bars.Bottom;
                foreach (var (n, color) in new[] { (b.Out, OutColor), (b.In, InColor), (b.Blocked, BlockColor) })
                {
                    if (n == 0) continue;
                    var h = Math.Max(1.5f, _bars.Height * n / (float)max);
                    using var brush = new SolidBrush(Color.FromArgb(190, color));
                    g.FillRectangle(brush, bx, bottom - h, Math.Max(1, barWidth - 2), h);
                    bottom -= h;
                }
            }
            using (var baseLine = new Pen(PanelLine)) g.DrawLine(baseLine, _bars.X, _bars.Bottom, _bars.Right, _bars.Bottom);

            float X(double minutesAgo) => _bars.X + (float)((TimelineMinutes - minutesAgo) / TimelineMinutes * _bars.Width);
            var endX = X(_offset);
            var startX = Math.Max(_bars.X, X(_offset + _window));
            var color2 = _offset <= 0 ? HomeColor : ReplayColor;
            using (var sel = new SolidBrush(Color.FromArgb(28, color2))) g.FillRectangle(sel, startX, _bars.Y - 2, Math.Max(2, endX - startX), _bars.Height + 4);
            using (var pen = new Pen(color2, 1.6f)) g.DrawLine(pen, endX, _bars.Y - 4, endX, _bars.Bottom + 2);
            using (var knob = new SolidBrush(color2)) g.FillEllipse(knob, endX - 4.5f, _bars.Y - 8, 9, 9);

            foreach (var m in new[] { 30, 20, 10 })
                g.DrawString($"-{m} min", _small, faint, X(m) - (m == 30 ? 0 : 16), _bars.Bottom + 2);
            const string now = "Now";
            g.DrawString(now, _small, faint, _bars.Right - g.MeasureString(now, _small).Width, _bars.Bottom + 2);
        }

        private void DrawPanel(Graphics g)
        {
            var p = _panel;
            var x = p.X + 16;
            var width = p.Width - 32;
            var y = 14f;
            using var ink = new SolidBrush(Ink);
            using var muted = new SolidBrush(InkMuted);
            using var faint = new SolidBrush(InkFaint);
            g.DrawString("OVERVIEW", _label, muted, x, y);
            y += 20;

            var live = _snap.Live;
            var tiles = new (string Label, string Value, Color Accent)[]
            {
                ("OPEN NOW", live ? Compact(_snap.Active) : "–", HomeColor),
                ("COUNTRIES", _snap.Countries.Count.ToString(), Hex("#60A5FA")),
                ("OUTGOING", Compact(_snap.Out), OutColor),
                ("INCOMING", Compact(_snap.In), InColor),
                ("BLOCKED", Compact(_snap.Blocked), BlockColor),
                ("LOCAL NETWORK", Compact(_snap.Lan), InkMuted),
            };
            var tileWidth = (width - 10) / 2f;
            for (var i = 0; i < tiles.Length; i++)
            {
                var box = new RectangleF(x + i % 2 * (tileWidth + 10), y + i / 2 * 66, tileWidth, 58);
                using (var path = Rounded(box, 6))
                using (var back = new SolidBrush(TileBack))
                using (var border = new Pen(Color.FromArgb(70, PanelLine)))
                {
                    g.FillPath(back, path);
                    g.DrawPath(border, path);
                }
                using (var accent = new SolidBrush(tiles[i].Accent)) g.FillRectangle(accent, box.X, box.Y + 10, 3, box.Height - 20);
                g.DrawString(tiles[i].Label, _label, muted, box.X + 12, box.Y + 8);
                g.DrawString(tiles[i].Value, _value, ink, box.X + 10, box.Y + 22);
            }
            y += 3 * 66 + 10;

            g.DrawString("TOP COUNTRIES", _label, muted, x, y);
            y += 20;
            var top = _snap.Countries.Take(Math.Max(0, (int)((p.Bottom - y - 50) / 34))).ToList();
            if (top.Count == 0)
                g.DrawString(live ? "No internet traffic in this window yet." : "No internet traffic in this window.", _small, faint, x, y);
            var max = Math.Max(1, top.Select(c => c.Total).DefaultIfEmpty(1).Max());
            foreach (var c in top)
            {
                var flag = Flags.For(c.Country);
                if (flag != null) g.DrawImage(flag, x, y + 3, 16, 11);
                var name = IpInfo.CountryName(c.Country);
                var total = Compact(c.Total);
                var totalWidth = g.MeasureString(total, _smallBold).Width;
                using (var fmt = new StringFormat { Trimming = StringTrimming.EllipsisCharacter, FormatFlags = StringFormatFlags.NoWrap })
                    g.DrawString(name, _body, ink, new RectangleF(x + 22, y, width - 26 - totalWidth, 18), fmt);
                g.DrawString(total, _smallBold, ink, x + width - totalWidth, y + 1);

                var barX = x + 22f;
                var full = (width - 22) * c.Total / (float)max;
                using (var track = new SolidBrush(Color.FromArgb(40, InkMuted))) g.FillRectangle(track, barX, y + 20, width - 22, 4);
                foreach (var (n, color) in new[] { (c.Out, OutColor), (c.In, InColor), (c.Blocked, BlockColor) })
                {
                    if (n == 0) continue;
                    var w = full * n / Math.Max(1, c.Total);
                    using var b = new SolidBrush(color);
                    g.FillRectangle(b, barX, y + 20, w, 4);
                    barX += w;
                }
                y += 34;
            }

            if (_snap.Unknown > 0) g.DrawString($"Unknown location: {Compact(_snap.Unknown)}", _small, faint, x, p.Bottom - 22);
            var blockedCountries = _service.Config.BlockedCountries;
            if (blockedCountries.Count > 0)
            {
                using var red = new SolidBrush(BlockColor);
                using var fmt = new StringFormat { Trimming = StringTrimming.EllipsisCharacter, FormatFlags = StringFormatFlags.NoWrap };
                g.DrawString("BLOCKED COUNTRIES: " + string.Join(" · ", blockedCountries), _label, red, new RectangleF(x, p.Bottom - 40, width, 16), fmt);
            }
        }

        private void DrawTooltip(Graphics g, Node node)
        {
            var f = node.Flow;
            var lines = new List<(string Text, Color Color)>
            {
                ($"Outgoing  {f.Out:N0}", OutColor),
                ($"Incoming  {f.In:N0}", InColor),
                ($"Blocked   {f.Blocked:N0}", BlockColor),
            };
            if (_snap.Live) lines.Add(($"Open now  {f.Active:N0}", HomeColor));
            lines.Add(($"{f.Ips.Count:N0} address(es)", InkMuted));
            var apps = string.Join(", ", f.TopApps(3));
            if (apps.Length > 0) lines.Add(("Apps: " + apps, InkMuted));

            var title = IpInfo.CountryName(f.Country);
            var width = Math.Max(g.MeasureString(title, _titleFont).Width + 30, lines.Max(l => g.MeasureString(l.Text, _small).Width)) + 24;
            width = Math.Min(width, 340);
            var height = 34 + lines.Count * 16 + 8;
            var box = new RectangleF(_mouse.X + 16, _mouse.Y + 12, width, height);
            if (box.Right > Width - 4) box.X = _mouse.X - 16 - width;
            if (box.Bottom > Height - 4) box.Y = Height - 4 - height;

            using (var path = Rounded(box, 8))
            using (var back = new SolidBrush(Color.FromArgb(240, 9, 20, 40)))
            using (var border = new Pen(Color.FromArgb(150, OutColor)))
            {
                g.FillPath(back, path);
                g.DrawPath(border, path);
            }
            var flag = Flags.For(f.Country);
            if (flag != null) g.DrawImage(flag, box.X + 12, box.Y + 12, 16, 11);
            using (var ink = new SolidBrush(Ink)) g.DrawString(title, _titleFont, ink, box.X + 32, box.Y + 6);
            var y = box.Y + 32;
            using var fmt = new StringFormat { Trimming = StringTrimming.EllipsisCharacter, FormatFlags = StringFormatFlags.NoWrap };
            foreach (var (text, color) in lines)
            {
                using var b = new SolidBrush(color);
                g.DrawString(text, _small, b, new RectangleF(box.X + 12, y, box.Width - 20, 16), fmt);
                y += 16;
            }
        }

        // ---------- mouse ----------

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            _mouse = e.Location;
            if (_dragging)
            {
                SeekTo(e.X);
                return;
            }
            var hover = _mapArea.Contains(e.Location)
                ? _nodes.Where(n => Distance(n.At, e.Location) <= n.Radius + 5).OrderBy(n => Distance(n.At, e.Location)).FirstOrDefault()
                : null;
            Cursor = hover != null || _buttons.Any(b => b.Bounds.Contains(e.Location)) || _bars.Contains(e.Location) ? Cursors.Hand : Cursors.Default;
            if (hover != _hover || hover != null)
            {
                _hover = hover;
                Invalidate();
            }
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            _hover = null;
            Invalidate();
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            if (e.Button == MouseButtons.Right && _mapArea.Contains(e.Location))
            {
                ShowLocationMenu(e.Location);
                return;
            }
            if (e.Button != MouseButtons.Left) return;
            var button = _buttons.FirstOrDefault(b => b.Bounds.Contains(e.Location));
            if (button.Click != null)
            {
                button.Click();
                return;
            }
            var bars = _bars;
            bars.Inflate(0, 10);
            if (bars.Contains(e.Location))
            {
                _dragging = true;
                Capture = true;
                SeekTo(e.X);
            }
        }

        protected override void OnMouseUp(MouseEventArgs e)
        {
            base.OnMouseUp(e);
            _dragging = false;
            Capture = false;
        }

        private void SeekTo(int x)
        {
            var minutesAgo = TimelineMinutes - (x - _bars.X) / (double)_bars.Width * TimelineMinutes;
            minutesAgo = Math.Round(minutesAgo * 2) / 2;
            Offset = minutesAgo < 0.5 ? 0 : minutesAgo;
        }

        private static double Distance(PointF a, Point b) => Math.Sqrt((a.X - b.X) * (a.X - b.X) + (a.Y - b.Y) * (a.Y - b.Y));

        private void ShowLocationMenu(Point at)
        {
            var menu = new ContextMenuStrip();
            Unproject(at, out var lat, out var lon);
            var nearest = WorldGeo.Nearest(lat, lon);
            menu.Items.Add($"Put this PC in {IpInfo.CountryName(nearest)}", null, (_, __) => SetHome(nearest, null));
            menu.Items.Add("Choose country and city...", null, (_, __) => ChooseLocation());
            menu.Items.Add(PublicIp.Country != null ? $"Use my public IP ({IpInfo.CountryName(PublicIp.Country)})" : "Find it automatically", null, (_, __) => SetHome(null, null));
            menu.Items.Add(new ToolStripSeparator());
            // The country under the mouse, or the nearest one.
            var target = _hover?.Flow.Country ?? nearest;
            var name = IpInfo.CountryName(target);
            var blocked = _service.Config.BlockedCountries.Contains(target);
            var owner = FindForm();
            menu.Items.Add(blocked ? $"Unblock {name}" : $"Block all traffic with {name}", null, async (_, __) =>
            {
                if (!_service.CanChange) return;
                var list = _service.Config.BlockedCountries.ToList();
                if (blocked)
                {
                    if (!Guard.Unlock(owner, "Unblocking a country")) return;
                    list.Remove(target);
                }
                else
                {
                    if (MessageBox.Show(owner, $"Block all traffic to and from {name}, for every app, including apps you accepted?", "Block country",
                            MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
                    list.Add(target);
                }
                await CountryBlockForm.ApplyAsync(owner, _service, list);
                RefreshData();
            }).Enabled = _service.CanChange;
            menu.Items.Add("Blocked countries...", null, async (_, __) =>
            {
                await CountryBlockForm.EditAsync(owner, _service);
                RefreshData();
            }).Enabled = _service.CanChange;
            menu.Closed += (_, __) => BeginInvoke((Action)menu.Dispose);
            menu.Show(this, at);
        }

        /// <summary>Asks once, the first time the map shows, when neither the user nor the public IP has said where this PC is.</summary>
        private void MaybeAskLocation()
        {
            if (_asked || !AskForLocation || !Visible || _location == null) return;
            if (_location.Source == LocationSource.Chosen || _location.Source == LocationSource.PublicIp) return;
            // Still looking it up: wait for the answer before asking.
            if (!_service.Config.NoPublicIpLookup && !PublicIp.Failed) return;
            _asked = true;
            BeginInvoke((Action)ChooseLocation);
        }

        public void ChooseLocation()
        {
            _asked = true;
            using var form = new LocationForm(_service.Location, PublicIp.Address, PublicIp.Country);
            if (form.ShowDialog(FindForm()) != DialogResult.OK) return;
            if (form.UseDetected) SetHome(null, null);
            else SetHome(form.Country, form.City);
        }

        private void SetHome(string country, string city)
        {
            _service.SetMapHome(country, city);
            RefreshData();
        }

        // ---------- helpers ----------

        private static string Compact(int n) => n >= 1_000_000 ? (n / 1_000_000.0).ToString("0.#") + "M" : n >= 10_000 ? (n / 1000.0).ToString("0.#") + "k" : n.ToString("N0");

        private static GraphicsPath Rounded(RectangleF r, float radius)
        {
            var d = radius * 2;
            var path = new GraphicsPath();
            path.AddArc(r.X, r.Y, d, d, 180, 90);
            path.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            path.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            path.CloseFigure();
            return path;
        }

        private static Color Hex(string hex) => ColorTranslator.FromHtml(hex);
    }
}
