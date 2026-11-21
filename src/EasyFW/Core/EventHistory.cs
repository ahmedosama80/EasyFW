using System;
using System.Collections.Generic;
using System.Linq;

namespace EasyFW.Core
{
    /// <summary>
    /// Every connection attempt the firewall reported in the last hour, one entry per attempt, for an app's log.
    /// Kept in memory only, and capped so a burst can't use up memory. Touched only from the UI thread.
    /// </summary>
    public sealed class EventHistory
    {
        public const int Minutes = 60;
        private readonly int _capacity;
        private readonly Queue<FirewallEvent> _events = new Queue<FirewallEvent>();

        public EventHistory(int capacity = 200000) { _capacity = capacity; }

        public int Count => _events.Count;

        /// <summary>The time of the oldest event kept, which is later than an hour ago when the cap has dropped some.</summary>
        public DateTime? OldestUtc => _events.Count > 0 ? _events.Peek().TimeUtc : (DateTime?)null;

        public void Add(FirewallEvent e)
        {
            _events.Enqueue(e);
            while (_events.Count > _capacity) _events.Dequeue();
            Trim(e.TimeUtc);
        }

        private void Trim(DateTime nowUtc)
        {
            var cutoff = nowUtc.AddMinutes(-Minutes);
            while (_events.Count > 0 && _events.Peek().TimeUtc < cutoff) _events.Dequeue();
        }

        /// <summary>The app's events in the last hour, newest first.</summary>
        /// <param name="ruleTarget">A rule target, so "Ping (ICMP)" finds the pings that the System process sent.</param>
        public List<FirewallEvent> ForApp(string ruleTarget, DateTime nowUtc)
        {
            Trim(nowUtc);
            return _events.Where(e => AppPaths.Same(AppPaths.RuleTarget(e.AppPath, e.Protocol), ruleTarget)).Reverse().ToList();
        }

        /// <summary>Every event kept, oldest first. Enumerate on the UI thread only.</summary>
        public IEnumerable<FirewallEvent> All => _events;

        public void Clear() => _events.Clear();
    }
}
