using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace EasyFW.Core
{
    /// <summary>
    /// This PC's address as the internet sees it, asked of a public "what is my IP" service over HTTPS.
    /// Only the request itself leaves the PC; nothing about the PC is sent.
    /// </summary>
    public static class PublicIp
    {
        /// <summary>Tried in order until one answers with a public address.</summary>
        public static readonly string[] Services = { "https://api.ipify.org", "https://checkip.amazonaws.com", "https://icanhazip.com" };

        private static readonly object Gate = new object();
        private static Task _running;

        /// <summary>Null until a lookup succeeds.</summary>
        public static string Address { get; private set; }
        public static DateTime? CheckedUtc { get; private set; }
        public static bool Failed { get; private set; }

        /// <summary>Raised on the thread that ran the lookup.</summary>
        public static event Action Changed;

        /// <summary>Swappable for tests: fetches one service's text.</summary>
        public static Func<string, Task<string>> Fetch { get; set; } = DefaultFetch;

        /// <summary>Two-letter country of the public address, or null.</summary>
        public static string Country => Address == null ? null : IpInfo.CountryCode(Address) is string c && c != "LAN" ? c : null;

        public static Task RefreshAsync()
        {
            lock (Gate)
            {
                if (_running != null && !_running.IsCompleted) return _running;
                return _running = Task.Run(LookUpAsync);
            }
        }

        private static async Task LookUpAsync()
        {
            foreach (var url in Services)
            {
                try
                {
                    var text = (await Fetch(url).ConfigureAwait(false) ?? "").Trim();
                    if (!IsPublic(text)) continue;
                    Set(text);
                    return;
                }
                catch (Exception ex) when (ex is WebException || ex is TimeoutException || ex is OperationCanceledException || ex is InvalidOperationException)
                {
                    Log.Write($"Public IP lookup at {url} failed: {ex.Message}");
                }
            }
            Failed = true;
            CheckedUtc = DateTime.UtcNow;
            Changed?.Invoke();
        }

        /// <summary>Also used by tests and the screenshots.</summary>
        public static void Set(string address)
        {
            var changed = address != Address;
            Address = address;
            Failed = address == null;
            CheckedUtc = DateTime.UtcNow;
            if (changed) Log.Write("Public IP: " + (address ?? "unknown"));
            Changed?.Invoke();
        }

        public static bool IsPublic(string text) =>
            IPAddress.TryParse(text ?? "", out var a)
            && (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 || text.Count(c => c == '.') == 3)
            && NetRanges.IsPublicAddress(text);

        private static async Task<string> DefaultFetch(string url)
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            var request = (HttpWebRequest)WebRequest.Create(url);
            request.Timeout = request.ReadWriteTimeout = 8000;
            request.UserAgent = "EasyFW";
            request.Proxy = WebRequest.DefaultWebProxy;
            var call = request.GetResponseAsync();
            if (await Task.WhenAny(call, Task.Delay(9000)).ConfigureAwait(false) != call)
            {
                request.Abort();
                throw new TimeoutException("no answer in 9 seconds");
            }
            using var response = await call.ConfigureAwait(false);
            using var reader = new System.IO.StreamReader(response.GetResponseStream());
            var text = await reader.ReadToEndAsync().ConfigureAwait(false);
            return text.Length > 100 ? text.Substring(0, 100) : text;
        }
    }
}
