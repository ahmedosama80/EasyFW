using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using EasyFW.Core;

namespace EasyFW.UI
{
    /// <summary>
    /// Country flags from the famfamfam sprite (public domain icons by Mark James; Guernsey by Damien Guard, CC BY 2.5),
    /// and drawing of the Country column with its flag.
    /// </summary>
    public static class Flags
    {
        // Positions in the sprite, from legacy-icons/famfamfam-flags 1.0.0. Each flag is 16x11 unless a size follows.
        private const string Layout =
            "me:0,0,16,12;ky:16,0;af:0,12;ag:16,12;ai:32,0;al:32,11;am:0,23;an:16,23;ao:32,23;ar:0,34;as:16,34;at:32,34;au:48,0;aw:48,11;ax:48,22;az:48,33;" +
            "ba:0,45;bb:16,45;bd:32,45;be:48,45;bf:64,0;bg:64,11;bh:64,22;bi:64,33;bj:64,44;bm:0,56;bn:16,56;bo:32,56;br:48,56;bs:64,56;bt:0,67;bv:16,67;" +
            "bw:32,67;by:48,67;bz:64,67;ca:80,0;cc:80,22;cd:80,33;cf:80,44;cg:80,55;zm:80,66;ci:0,78;ck:16,78;cl:32,78;cm:48,78;cn:64,78;co:80,78;cr:96,0;" +
            "cs:96,11;cu:96,22;cv:96,33;cx:96,44;cy:96,55;cz:96,66;de:96,77;dj:0,89;dk:16,89;dm:32,89;do:48,89;dz:64,89;ec:80,89;ee:96,89;eg:0,100;eh:16,100;" +
            "er:48,100;es:64,100;et:80,100;eu:96,100;fi:112,11;fj:112,22;fk:112,33;fm:112,44;fo:112,55;fr:112,66;mf:112,66;ga:112,77;gb:112,88;gd:112,99;" +
            "ge:0,111;gf:16,111;gg:32,111;gh:48,111;gi:64,111;gl:80,111;gm:96,111;gn:112,111;gp:128,0;gq:128,11;gr:128,22;gs:128,33;gt:128,44;gu:128,55;" +
            "gw:128,66;gy:128,77;hk:128,88;hm:128,99;hn:128,110;hr:0,122;ht:16,122;hu:32,122;id:48,122;ie:64,122;il:80,122;in:96,122;io:112,122;iq:128,122;" +
            "ir:0,133;is:16,133;it:32,133;je:48,133;jm:64,133;jo:80,133;jp:96,133;ke:112,133;kg:128,133;kh:144,0;ki:144,11;km:144,22;kn:144,33;kp:144,44;" +
            "kr:144,55;kw:144,66;ae:144,77;kz:144,88;la:144,99;lb:144,110;lc:144,121;li:144,132;lk:0,144;lr:16,144;ls:32,144;lt:48,144;lu:64,144;lv:80,144;" +
            "ly:96,144;ma:112,144;mc:128,144;md:144,144;ad:160,0;mg:160,11;mh:160,22;mk:160,33;ml:160,44;mm:160,55;mn:160,66;mo:160,77;mp:160,88;mq:160,99;" +
            "mr:160,110;ms:160,121;mt:160,132;mu:160,143;mv:0,155;mw:16,155;mx:32,155;my:48,155;mz:64,155;na:80,155;nc:96,155;ne:112,155;nf:128,155;" +
            "ng:144,155;ni:160,155;nl:176,0;bq:176,0;no:176,11;za:176,22;nr:176,33;nu:176,44;nz:176,55;om:176,66;pa:176,77;pe:176,88;pf:176,99;pg:176,110;" +
            "ph:176,121;pk:176,132;pl:176,143;pm:176,154;pn:0,166;pr:16,166;ps:32,166;pt:48,166;pw:64,166;py:80,166;qa:96,166;re:112,166;ro:128,166;" +
            "rs:144,166;ru:160,166;rw:176,166;sa:0,177;sb:16,177;sc:32,177;sd:64,177;se:80,177;sg:96,177;sh:112,177;si:128,177;sj:144,177;sk:160,177;" +
            "sl:176,177;sm:192,0;sn:192,11;so:192,22;sr:192,33;st:192,44;sv:192,55;sy:192,66;sz:192,77;tc:192,88;td:192,99;tf:192,110;tg:192,121;th:192,132;" +
            "tj:192,143;tk:192,154;tl:192,165;tm:192,176;tn:0,188;to:16,188;tr:32,188;tt:48,188;tv:64,188;tw:80,188;tz:96,188;ua:112,188;ug:128,188;" +
            "um:144,188;us:160,188;uy:176,188;uz:192,188;va:208,0;vc:208,11;ve:208,22;vg:208,33;vi:208,44;vn:208,55;vu:208,66;wf:208,88;ws:208,99;" +
            "ye:208,110;yt:208,121;zw:208,132;ch:208,143,11,11;np:208,154,9,11";

        private static readonly Dictionary<string, Rectangle> Places = ParseLayout();
        private static readonly Dictionary<string, Bitmap> Cache = new Dictionary<string, Bitmap>(StringComparer.OrdinalIgnoreCase);
        private static Bitmap _sprite;

        public static IReadOnlyCollection<string> Codes => Places.Keys;

        private static Dictionary<string, Rectangle> ParseLayout()
        {
            var places = new Dictionary<string, Rectangle>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in Layout.Split(';'))
            {
                var colon = entry.IndexOf(':');
                var n = Array.ConvertAll(entry.Substring(colon + 1).Split(','), int.Parse);
                places[entry.Substring(0, colon)] = new Rectangle(n[0], n[1], n.Length > 2 ? n[2] : 16, n.Length > 3 ? n[3] : 11);
            }
            return places;
        }

        private static Bitmap Sprite()
        {
            if (_sprite != null) return _sprite;
            using var stream = typeof(Flags).Assembly.GetManifestResourceStream("EasyFW.flags.png");
            if (stream == null) return null;
            return _sprite = new Bitmap(stream);
        }

        /// <returns>Null for a country with no flag in the set.</returns>
        public static Image For(string code)
        {
            if (string.IsNullOrEmpty(code) || !Places.TryGetValue(code, out var place)) return null;
            if (Cache.TryGetValue(code, out var flag)) return flag;
            var sprite = Sprite();
            if (sprite == null) return null;
            flag = sprite.Clone(place, sprite.PixelFormat);
            Cache[code] = flag;
            return flag;
        }

        /// <summary>
        /// Draws a flag before the country name in one column. Turning on owner drawing loses the row colours in the default drawing
        /// of the other cells, so every cell after the first is drawn here too.
        /// </summary>
        /// <param name="ipColumn">The column holding the address the country belongs to.</param>
        /// <param name="rowBack">The background of a row by index, or null for the item's own.</param>
        public static void ShowInColumn(ListView list, int countryColumn, int ipColumn, Func<int, Color?> rowBack = null)
        {
            list.OwnerDraw = true;
            list.DrawColumnHeader += (_, e) => e.DrawDefault = true;
            list.DrawItem += (_, e) => { };
            list.DrawSubItem += (_, e) =>
            {
                if (e.Item == null || e.ColumnIndex == 0)
                {
                    e.DrawDefault = true;
                    return;
                }
                var selected = e.Item.Selected;
                var back = selected ? (list.Focused ? SystemColors.Highlight : SystemColors.Control) : rowBack?.Invoke(e.ItemIndex) ?? e.Item.BackColor;
                var fore = selected && list.Focused ? SystemColors.HighlightText : e.Item.ForeColor;
                using (var brush = new SolidBrush(back)) e.Graphics.FillRectangle(brush, e.Bounds);
                var text = e.SubItem?.Text ?? "";
                var textBounds = e.Bounds;
                textBounds.X += 6;
                textBounds.Width -= 12;
                var align = TextFormatFlags.Left;
                if (e.ColumnIndex == countryColumn)
                {
                    var ip = ipColumn < e.Item.SubItems.Count ? e.Item.SubItems[ipColumn].Text : null;
                    var flag = For(IpInfo.CountryCode(ip));
                    if (flag != null)
                    {
                        e.Graphics.DrawImage(flag, textBounds.X, e.Bounds.Y + (e.Bounds.Height - flag.Height) / 2, flag.Width, flag.Height);
                        textBounds.X += 20;
                        textBounds.Width -= 20;
                    }
                }
                else if (list.Columns[e.ColumnIndex].TextAlign == HorizontalAlignment.Right) align = TextFormatFlags.Right;
                else if (list.Columns[e.ColumnIndex].TextAlign == HorizontalAlignment.Center) align = TextFormatFlags.HorizontalCenter;
                TextRenderer.DrawText(e.Graphics, text, list.Font, textBounds, fore,
                    align | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine);
            };
            // Owner-drawn rows can keep stale text where the mouse passes, unless the row repaints.
            list.MouseMove += (_, e) =>
            {
                var item = list.GetItemAt(e.X, e.Y);
                if (item != null) list.Invalidate(item.Bounds);
            };
        }
    }
}
