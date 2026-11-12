using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace EasyFW.Core
{
    /// <summary>
    /// Country by IP address, from the DB-IP "IP to Country Lite" CSV: one "first,last,code" range per line, sorted, IPv4 before IPv6.
    /// Everything is looked up offline, so no address leaves the PC.
    /// </summary>
    public sealed class CountryDb
    {
        private readonly uint[] _v4First, _v4Last;
        private readonly ushort[] _v4Code;
        private readonly ulong[] _v6FirstHi, _v6FirstLo, _v6LastHi, _v6LastLo;
        private readonly ushort[] _v6Code;
        private readonly string[] _codes;

        private CountryDb(List<uint> v4First, List<uint> v4Last, List<ushort> v4Code,
            List<ulong> v6FirstHi, List<ulong> v6FirstLo, List<ulong> v6LastHi, List<ulong> v6LastLo, List<ushort> v6Code, List<string> codes)
        {
            _v4First = v4First.ToArray(); _v4Last = v4Last.ToArray(); _v4Code = v4Code.ToArray();
            _v6FirstHi = v6FirstHi.ToArray(); _v6FirstLo = v6FirstLo.ToArray(); _v6LastHi = v6LastHi.ToArray(); _v6LastLo = v6LastLo.ToArray();
            _v6Code = v6Code.ToArray();
            _codes = codes.ToArray();
        }

        public int Count => _v4First.Length + _v6FirstHi.Length;

        /// <exception cref="InvalidDataException">The file isn't a sorted DB-IP country CSV.</exception>
        public static CountryDb Load(Stream csv)
        {
            var v4First = new List<uint>(400000); var v4Last = new List<uint>(400000); var v4Code = new List<ushort>(400000);
            var v6FirstHi = new List<ulong>(400000); var v6FirstLo = new List<ulong>(400000);
            var v6LastHi = new List<ulong>(400000); var v6LastLo = new List<ulong>(400000); var v6Code = new List<ushort>(400000);
            var codes = new List<string>();
            var codeIndex = new Dictionary<string, ushort>(StringComparer.Ordinal);
            using var reader = new StreamReader(csv);
            string line;
            var number = 0;
            while ((line = reader.ReadLine()) != null)
            {
                number++;
                if (line.Length == 0) continue;
                var parts = line.Split(',');
                if (parts.Length != 3 || parts[2].Length != 2
                    || !IPAddress.TryParse(parts[0], out var first) || !IPAddress.TryParse(parts[1], out var last)
                    || first.AddressFamily != last.AddressFamily)
                    throw new InvalidDataException($"Line {number} of the country file isn't \"first,last,code\".");
                var code = parts[2].ToUpperInvariant();
                if (!codeIndex.TryGetValue(code, out var index))
                {
                    index = (ushort)codes.Count;
                    codeIndex[code] = index;
                    codes.Add(code);
                }
                if (first.AddressFamily == AddressFamily.InterNetwork)
                {
                    var f = V4(first);
                    if (v4First.Count > 0 && f <= v4Last[v4Last.Count - 1]) throw Unsorted(number);
                    v4First.Add(f); v4Last.Add(V4(last)); v4Code.Add(index);
                }
                else
                {
                    V6(first, out var fh, out var fl);
                    V6(last, out var lh, out var ll);
                    var n = v6LastHi.Count;
                    if (n > 0 && Compare(fh, fl, v6LastHi[n - 1], v6LastLo[n - 1]) <= 0) throw Unsorted(number);
                    v6FirstHi.Add(fh); v6FirstLo.Add(fl); v6LastHi.Add(lh); v6LastLo.Add(ll); v6Code.Add(index);
                }
            }
            return new CountryDb(v4First, v4Last, v4Code, v6FirstHi, v6FirstLo, v6LastHi, v6LastLo, v6Code, codes);
        }

        private static InvalidDataException Unsorted(int number) => new InvalidDataException($"The country file isn't in order at line {number}.");

        /// <returns>The two-letter code, or null if the address isn't listed. DB-IP marks private and reserved ranges ZZ.</returns>
        public string Find(IPAddress address)
        {
            if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                var v = V4(address);
                int lo = 0, hi = _v4First.Length - 1;
                while (lo <= hi)
                {
                    var mid = (lo + hi) >> 1;
                    if (v < _v4First[mid]) hi = mid - 1;
                    else if (v > _v4Last[mid]) lo = mid + 1;
                    else return _codes[_v4Code[mid]];
                }
                return null;
            }
            if (address.AddressFamily != AddressFamily.InterNetworkV6) return null;
            V6(address, out var h, out var l);
            int a = 0, b = _v6FirstHi.Length - 1;
            while (a <= b)
            {
                var mid = (a + b) >> 1;
                if (Compare(h, l, _v6FirstHi[mid], _v6FirstLo[mid]) < 0) b = mid - 1;
                else if (Compare(h, l, _v6LastHi[mid], _v6LastLo[mid]) > 0) a = mid + 1;
                else return _codes[_v6Code[mid]];
            }
            return null;
        }

        private static uint V4(IPAddress a)
        {
            var b = a.GetAddressBytes();
            return (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
        }

        private static void V6(IPAddress a, out ulong hi, out ulong lo)
        {
            var b = a.GetAddressBytes();
            hi = lo = 0;
            for (var i = 0; i < 8; i++) hi = hi << 8 | b[i];
            for (var i = 8; i < 16; i++) lo = lo << 8 | b[i];
        }

        private static int Compare(ulong ah, ulong al, ulong bh, ulong bl) => ah != bh ? ah.CompareTo(bh) : al.CompareTo(bl);
    }

    /// <summary>
    /// Host names and countries for the IP columns. Host names come from reverse DNS, looked up in the background a few at a time
    /// and cached, so a busy list never waits on DNS. <see cref="Version"/> changes whenever something new is known, for the lists to repaint.
    /// </summary>
    public static class IpInfo
    {
        public const string FileName = "dbip-country-lite.csv.gz";
        private const int Workers = 4;
        private const int MaxNames = 20000;

        private static readonly ConcurrentDictionary<string, string> Names = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentQueue<string> Queue = new ConcurrentQueue<string>();
        private static readonly ConcurrentDictionary<string, string> CountryNames = new ConcurrentDictionary<string, string>(StringComparer.Ordinal);
        private static volatile CountryDb _db;
        private static int _workers, _version, _loading;

        public static int Version => Volatile.Read(ref _version);
        public static bool CountriesLoaded => _db != null;

        /// <summary>Swappable for tests. Returns null or empty when the address has no name.</summary>
        public static Func<IPAddress, string> Resolver { get; set; } = ReverseDns;

        /// <summary>Loads the country file beside the exe in the background. Safe to call more than once.</summary>
        public static void LoadCountries(string path = null)
        {
            if (Interlocked.Exchange(ref _loading, 1) == 1) return;
            path ??= Path.Combine(AppDomain.CurrentDomain.BaseDirectory, FileName);
            Task.Run(() =>
            {
                try
                {
                    if (!File.Exists(path))
                    {
                        Log.Write("No country file at " + path + "; the Country column stays empty.");
                        return;
                    }
                    using var file = File.OpenRead(path);
                    using var gzip = new GZipStream(file, CompressionMode.Decompress);
                    SetCountries(CountryDb.Load(gzip));
                }
                catch (Exception ex) { Log.Write("Could not load the country file: " + ex.Message); }
            });
        }

        public static void SetCountries(CountryDb db)
        {
            _db = db;
            Interlocked.Increment(ref _version);
        }

        private static bool TryParse(string ip, out IPAddress address)
        {
            address = null;
            if (string.IsNullOrEmpty(ip) || ip == "*" || !IPAddress.TryParse(IpText.Normalize(ip), out address)) return false;
            return !address.Equals(IPAddress.Any) && !address.Equals(IPAddress.IPv6Any);
        }

        /// <summary>Two-letter code, "LAN" for local addresses, or null when unknown or not loaded.</summary>
        public static string CountryCode(string ip)
        {
            if (!TryParse(ip, out var address)) return null;
            if (IPAddress.IsLoopback(address) || NetRanges.IsLan(address.ToString())) return "LAN";
            var code = _db?.Find(address);
            return code == null || code == "ZZ" ? null : code;
        }

        public static string CountryText(string ip)
        {
            var code = CountryCode(ip);
            if (code == null) return "";
            if (code == "LAN") return IPAddress.TryParse(IpText.Normalize(ip), out var a) && IPAddress.IsLoopback(a) ? "This PC" : "Local network";
            return CountryName(code);
        }

        public static string CountryName(string code) => CountryNames.GetOrAdd(code, c =>
        {
            if (c == "EU") return "European Union";
            try { return new RegionInfo(c).EnglishName; }
            catch (ArgumentException) { return c; }
        });

        /// <summary>The cached name, or "" while it's being looked up. Starts a lookup the first time an address is seen.</summary>
        public static string HostName(string ip, bool lookUp = true)
        {
            if (!TryParse(ip, out var address)) return "";
            var key = address.ToString();
            if (Names.TryGetValue(key, out var name)) return name ?? "";
            if (!lookUp) return "";
            if (Names.Count > MaxNames) Names.Clear();
            if (Names.TryAdd(key, null))
            {
                Queue.Enqueue(key);
                StartWorker();
            }
            return "";
        }

        private static void StartWorker()
        {
            if (Interlocked.Increment(ref _workers) > Workers)
            {
                Interlocked.Decrement(ref _workers);
                return;
            }
            Task.Run(() =>
            {
                while (Queue.TryDequeue(out var key))
                {
                    string name;
                    try { name = Resolver(IPAddress.Parse(key)) ?? ""; }
                    catch (Exception) { name = ""; }
                    Names[key] = name;
                    Interlocked.Increment(ref _version);
                }
                Interlocked.Decrement(ref _workers);
                // Something queued between the last dequeue and the decrement would otherwise wait for the next new address.
                if (!Queue.IsEmpty) StartWorker();
            });
        }

        /// <summary>Plain reverse lookup. GetHostEntry also looks the name up again forwards, which doubles the DNS traffic.</summary>
        private static string ReverseDns(IPAddress address)
        {
            try
            {
#pragma warning disable 618
                var name = Dns.GetHostByAddress(address).HostName;
#pragma warning restore 618
                return name == address.ToString() ? "" : name;
            }
            catch (SocketException) { return ""; }
        }

        /// <summary>For tests: forgets every name.</summary>
        public static void ClearNames()
        {
            Names.Clear();
            Interlocked.Increment(ref _version);
        }
    }
}
