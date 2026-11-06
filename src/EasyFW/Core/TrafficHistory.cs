using System;
using System.Collections.Generic;

namespace EasyFW.Core
{
    public struct TrafficSample
    {
        /// <summary>Start of the 10-second window this sample covers.</summary>
        public DateTime TimeUtc { get; set; }
        public int Accepted { get; set; }
        public int Blocked { get; set; }
    }

    /// <summary>Accepted and blocked connection counts per 10 seconds, for the live graph. Touched only from the UI thread.</summary>
    public sealed class TrafficHistory
    {
        public const int IntervalSeconds = 10;
        public const int Capacity = 60;

        private readonly List<TrafficSample> _samples = new List<TrafficSample>();
        private DateTime _windowStartUtc;

        public IReadOnlyList<TrafficSample> Samples => _samples;

        public void Add(TrafficSample sample)
        {
            _samples.Add(sample);
            if (_samples.Count > Capacity) _samples.RemoveRange(0, _samples.Count - Capacity);
        }

        /// <summary>Closes the current window once it has ended. Windows missed during sleep count as zero, so the time axis stays true.</summary>
        /// <returns>True if a sample was added.</returns>
        public bool SampleIfDue(DateTime nowUtc, ConnectionStore store)
        {
            var currentStart = Floor(nowUtc);
            if (_windowStartUtc == default)
            {
                _windowStartUtc = currentStart;
                return false;
            }
            if (currentStart <= _windowStartUtc) return false;

            var counts = store.TakeCounts();
            Add(new TrafficSample { TimeUtc = _windowStartUtc, Accepted = counts.Accepted, Blocked = counts.Blocked });
            for (var t = _windowStartUtc.AddSeconds(IntervalSeconds); t < currentStart; t = t.AddSeconds(IntervalSeconds))
                Add(new TrafficSample { TimeUtc = t });
            _windowStartUtc = currentStart;
            return true;
        }

        public static DateTime Floor(DateTime utc)
        {
            var ticks = TimeSpan.FromSeconds(IntervalSeconds).Ticks;
            return new DateTime(utc.Ticks - utc.Ticks % ticks, DateTimeKind.Utc);
        }

        /// <summary>A round axis top that halves to a whole number, so the middle label is never a fraction.</summary>
        public static int AxisMax(int value)
        {
            for (var scale = 1; ; scale *= 10)
            {
                foreach (var step in new[] { 4, 10, 20 })
                {
                    if (value <= step * scale) return step * scale;
                }
            }
        }
    }
}
