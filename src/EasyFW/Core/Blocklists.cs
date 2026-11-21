using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace EasyFW.Core
{
    /// <summary>A public list of known bad addresses.</summary>
    public sealed class BlocklistSource
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public string[] Urls { get; set; }
    }

    /// <summary>
    /// Known bad addresses from public lists, downloaded once a day and kept in %ProgramData%\EasyFW\blocklists,
    /// so blocking carries on offline and across restarts. Only public internet addresses are kept: a list that names
    /// a LAN or reserved range can't cut off the local network.
    /// </summary>
    public static class Blocklists
    {
        public const string Tag = "[blocklist]";
        /// <summary>Most lists hold a few thousand entries. Anything far beyond this is a broken download.</summary>
        public const int MaxEntries = 200000;

        public static readonly BlocklistSource[] Sources =
        {
            new BlocklistSource
            {
                Id = "spamhaus-drop", Name = "Spamhaus DROP",
                Description = "Networks taken over by criminals and spammers. Very few mistakes; safe for everyone.",
                Urls = new[] { "https://www.spamhaus.org/drop/drop_v4.json", "https://www.spamhaus.org/drop/drop_v6.json" }
            },
            new BlocklistSource
            {
                Id = "firehol-level1", Name = "FireHOL Level 1",
                Description = "Attackers, malware and abuse from several trusted lists, chosen to avoid false hits.",
                Urls = new[] { "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset" }
            },
            new BlocklistSource
            {
                Id = "feodo", Name = "abuse.ch Feodo Tracker",
                Description = "Control servers of banking trojans and botnets such as Emotet, Dridex and QakBot.",
                Urls = new[] { "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt" }
            },
            new BlocklistSource
            {
                Id = "et-compromised", Name = "Emerging Threats compromised hosts",
                Description = "Hosts seen attacking others recently. Changes often, so an odd false hit is possible.",
                Urls = new[] { "https://rules.emergingthreats.net/blockrules/compromised-ips.txt" }
            },
        };

        public static BlocklistSource Find(string id) => Sources.FirstOrDefault(s => s.Id == id);

        public static string DefaultFolder => Path.Combine(ConfigStore.DefaultFolder, "blocklists");

        /// <summary>Swappable for tests: the text at a URL.</summary>
        public static Func<string, Task<string>> Fetch { get; set; } = DefaultFetch;

        private static readonly Regex Address = new Regex(@"(?<![\w.:])((?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:/\d{1,3})?)(?![\w.:])", RegexOptions.Compiled);

        /// <summary>
        /// Reads any of the usual formats: one address or CIDR per line, with "#" or ";" comments, or Spamhaus's one JSON object per line.
        /// Keeps public addresses only, as CIDRs, each once.
        /// </summary>
        public static List<string> Parse(string text)
        {
            var result = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var raw in (text ?? "").Split('\n'))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line[0] == '#' || line[0] == ';' || line.StartsWith("//")) continue;
                var m = Address.Match(line);
                if (!m.Success || !NetRanges.TryNormalize(m.Groups[1].Value, out var cidr) || !IsSafe(cidr) || !seen.Add(cidr)) continue;
                result.Add(cidr);
                if (result.Count >= MaxEntries) break;
            }
            return result;
        }

        /// <summary>
        /// Leaves out anything that touches the LAN, loopback, multicast or reserved space, and ranges so wide a mistake would cut off much of the internet.
        /// </summary>
        public static bool IsSafe(string cidr)
        {
            if (!NetRanges.TryRange(cidr, out var v6, out var first, out var last)) return false;
            var prefix = int.Parse(cidr.Substring(cidr.IndexOf('/') + 1));
            if (prefix < (v6 ? 19 : 8)) return false;
            return NetRanges.IsPublicAddress(NetRanges.ToAddress(first, v6)) && NetRanges.IsPublicAddress(NetRanges.ToAddress(last, v6));
        }

        /// <summary>Downloads a list and keeps it. A list that comes back nearly empty is treated as a failed download and the old copy stays.</summary>
        /// <returns>How many entries it has.</returns>
        public static async Task<int> DownloadAsync(BlocklistSource source, string folder)
        {
            var entries = new List<string>();
            foreach (var url in source.Urls)
            {
                var text = await Fetch(url).ConfigureAwait(false);
                entries.AddRange(Parse(text));
            }
            entries = entries.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (entries.Count < 5) throw new InvalidDataException($"{source.Name} came back with {entries.Count} usable entries, so the download is probably broken.");
            Directory.CreateDirectory(folder);
            var path = Path.Combine(folder, source.Id + ".txt");
            var temp = path + ".new";
            File.WriteAllLines(temp, new[] { $"# {source.Name}, downloaded {DateTime.UtcNow:u}" }.Concat(entries));
            if (File.Exists(path)) File.Delete(path);
            File.Move(temp, path);
            return entries.Count;
        }

        /// <summary>The kept copy of each list, by id. Lists never downloaded are left out.</summary>
        public static Dictionary<string, List<string>> LoadKept(IEnumerable<string> ids, string folder)
        {
            var result = new Dictionary<string, List<string>>();
            foreach (var id in ids ?? Enumerable.Empty<string>())
            {
                var path = folder == null ? null : Path.Combine(folder, id + ".txt");
                if (path == null || !File.Exists(path)) continue;
                try { result[id] = Parse(File.ReadAllText(path)); }
                catch (IOException ex) { Log.Write($"Could not read blocklist {id}: {ex.Message}"); }
            }
            return result;
        }

        public static DateTime? KeptTimeUtc(string id, string folder)
        {
            var path = folder == null ? null : Path.Combine(folder, id + ".txt");
            return path != null && File.Exists(path) ? File.GetLastWriteTimeUtc(path) : (DateTime?)null;
        }

        private static async Task<string> DefaultFetch(string url)
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            var request = (HttpWebRequest)WebRequest.Create(url);
            request.UserAgent = "EasyFW/" + AppInfo.Version;
            request.Timeout = request.ReadWriteTimeout = 60000;
            request.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
            using var response = await request.GetResponseAsync().ConfigureAwait(false);
            using var stream = response.GetResponseStream();
            // Lists are a few hundred KB. A cap keeps a bad answer from filling memory.
            var buffer = new MemoryStream();
            var chunk = new byte[81920];
            int read;
            while ((read = await stream.ReadAsync(chunk, 0, chunk.Length).ConfigureAwait(false)) > 0)
            {
                buffer.Write(chunk, 0, read);
                if (buffer.Length > 20_000_000) throw new InvalidDataException("The list is far bigger than expected.");
            }
            return Encoding.UTF8.GetString(buffer.ToArray());
        }
    }

    /// <summary>The addresses blocked from the chosen lists, with the list each came from, quick to look up.</summary>
    public sealed class BlocklistIndex
    {
        private readonly (BigInteger First, BigInteger Last, string List)[] _v4, _v6;
        private readonly ConcurrentDictionary<string, string> _cache = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public static readonly BlocklistIndex Empty = new BlocklistIndex(new List<string>(), new List<(BigInteger, BigInteger, string, bool)>());

        /// <summary>The one in force, for list columns that have no service at hand.</summary>
        public static BlocklistIndex Current { get; set; } = Empty;

        /// <summary>CIDRs for the Windows rules, each once.</summary>
        public IReadOnlyList<string> Entries { get; }

        public int Count => Entries.Count;

        private BlocklistIndex(List<string> entries, List<(BigInteger First, BigInteger Last, string List, bool V6)> ranges)
        {
            Entries = entries;
            _v4 = ranges.Where(r => !r.V6).OrderBy(r => r.First).Select(r => (r.First, r.Last, r.List)).ToArray();
            _v6 = ranges.Where(r => r.V6).OrderBy(r => r.First).Select(r => (r.First, r.Last, r.List)).ToArray();
        }

        /// <param name="byList">Entries by list id.</param>
        /// <param name="exceptions">Addresses or CIDRs never to block. Any listed range that touches one is left out.</param>
        public static BlocklistIndex Build(Dictionary<string, List<string>> byList, IEnumerable<string> exceptions)
        {
            var allowed = (exceptions ?? Enumerable.Empty<string>())
                .Select(e => NetRanges.TryRange(e, out var v6, out var f, out var l) ? (Ok: true, V6: v6, F: f, L: l) : (Ok: false, V6: false, F: BigInteger.Zero, L: BigInteger.Zero))
                .Where(e => e.Ok).ToList();
            var entries = new List<string>();
            var ranges = new List<(BigInteger, BigInteger, string, bool)>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var pair in byList)
            {
                var name = Blocklists.Find(pair.Key)?.Name ?? pair.Key;
                foreach (var cidr in pair.Value)
                {
                    if (!NetRanges.TryRange(cidr, out var v6, out var first, out var last)) continue;
                    if (allowed.Any(a => a.V6 == v6 && a.F <= last && first <= a.L)) continue;
                    ranges.Add((first, last, name, v6));
                    if (seen.Add(cidr)) entries.Add(cidr);
                }
            }
            return new BlocklistIndex(entries, ranges);
        }

        /// <summary>The name of the list an address is on, or null.</summary>
        public string Match(string ip)
        {
            if (string.IsNullOrEmpty(ip) || Entries.Count == 0) return null;
            return _cache.GetOrAdd(ip, Find);
        }

        private string Find(string ip)
        {
            if (_cache.Count > 50000) _cache.Clear();
            if (!NetRanges.TryRange(IpText.Normalize(ip), out var v6, out var n, out _)) return null;
            var table = v6 ? _v6 : _v4;
            // Ranges can overlap between lists, so look back from the last start at or before the address.
            int lo = 0, hi = table.Length - 1, at = -1;
            while (lo <= hi)
            {
                var mid = (lo + hi) >> 1;
                if (table[mid].First <= n) { at = mid; lo = mid + 1; }
                else hi = mid - 1;
            }
            for (var i = at; i >= 0 && i > at - 64; i--)
                if (table[i].First <= n && n <= table[i].Last) return table[i].List;
            return null;
        }
    }
}
