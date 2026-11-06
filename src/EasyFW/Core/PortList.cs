using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace EasyFW.Core
{
    /// <summary>Port lists like "80, 443, 8000-8100". The tidy form is also the format Windows Firewall takes.</summary>
    public static class PortList
    {
        /// <returns>Sorted and merged ports, or null when the text is empty.</returns>
        /// <exception cref="FormatException">The text isn't a valid port list.</exception>
        public static string Normalize(string text)
        {
            var ranges = Parse(text);
            if (ranges.Count == 0) return null;
            var merged = new List<(int Low, int High)>();
            foreach (var r in ranges.OrderBy(x => x.Low))
            {
                var last = merged.Count - 1;
                if (last >= 0 && r.Low <= merged[last].High + 1)
                    merged[last] = (merged[last].Low, Math.Max(merged[last].High, r.High));
                else
                    merged.Add(r);
            }
            return string.Join(",", merged.Select(r => r.Low == r.High ? r.Low.ToString() : $"{r.Low}-{r.High}"));
        }

        public static bool Contains(string ports, int port) => Parse(ports).Any(r => port >= r.Low && port <= r.High);

        private static List<(int Low, int High)> Parse(string text)
        {
            var parts = Regex.Replace(text ?? "", @"\s*-\s*", "-").Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries);
            return parts.Select(ParseRange).ToList();
        }

        private static (int Low, int High) ParseRange(string part)
        {
            var ends = part.Split('-');
            if (ends.Length > 2 || !TryPort(ends[0], out var low)) throw Bad(part);
            var high = low;
            if (ends.Length == 2 && !TryPort(ends[1], out high)) throw Bad(part);
            if (high < low) throw Bad(part);
            return (low, high);
        }

        private static bool TryPort(string text, out int port) => int.TryParse(text, out port) && port >= 1 && port <= 65535;

        private static FormatException Bad(string part) =>
            new FormatException($"\"{part}\" isn't a valid port. Use numbers from 1 to 65535, for example 80, 443, 8000-8100.");
    }
}
