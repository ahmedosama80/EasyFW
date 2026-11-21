using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Numerics;

namespace EasyFW.Core
{
    /// <summary>Values are persisted as numbers, so they must stay stable.</summary>
    public enum LanAccess { All = 0, Selected = 1, None = 2 }

    /// <summary>
    /// Which remote addresses count as LAN and which as internet, written the way Windows Firewall takes remote addresses.
    /// LAN is the subnets of this PC's Ethernet and Wi-Fi adapters, plus link-local addresses and broadcast and multicast,
    /// so devices on them can still find each other. It follows the network: joining another Wi-Fi changes it.
    /// Internet is every other address that can be routed, including private addresses reached another way, such as through a VPN.
    /// </summary>
    public static class NetRanges
    {
        private struct Range
        {
            public bool V6;
            public BigInteger First, Last;
        }

        private static readonly string[] PrivateBlocks = { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10" };
        /// <summary>Device discovery (SSDP, mDNS, NetBIOS) is sent to these rather than to a device's own address.</summary>
        private static readonly string[] DiscoveryBlocks = { "224.0.0.0/4", "255.255.255.255/32", "ff00::/8" };
        /// <summary>"This network", loopback and reserved addresses. Neither LAN nor internet.</summary>
        private static readonly string[] UnroutableBlocks = { "0.0.0.0/8", "127.0.0.0/8", "240.0.0.0/4" };

        /// <summary>Link-local addresses only ever reach the local link.</summary>
        private static readonly string[] LinkLocalBlocks = { "169.254.0.0/16", "fe80::/10" };
        /// <summary>IPv6 that is never internet: unspecified, loopback.</summary>
        private static readonly string[] UnroutableV6Blocks = { "::/128", "::1/128" };

        private static readonly List<Range> Discovery = Merge(DiscoveryBlocks.Select(Block));
        /// <summary>Public address space: all of IPv4 outside private, discovery and reserved blocks, and IPv6 global unicast. Fixed, whatever the network.</summary>
        private static readonly List<Range> Public = Merge(
            ComplementV4(Merge(PrivateBlocks.Concat(DiscoveryBlocks).Concat(UnroutableBlocks).Select(Block))).Concat(new[] { Block("2000::/3") }));

        private static readonly object Gate = new object();
        private static List<Range> _lan, _internet;
        private static int _version;

        /// <summary>The subnets of the Ethernet and Wi-Fi adapters. Swappable for tests; call <see cref="Refresh"/> after.</summary>
        public static Func<List<(string Cidr, string Adapter)>> AdapterSource { get; set; } = ReadAdapters;

        /// <summary>Changes whenever the LAN changes, so anything that kept answers can drop them.</summary>
        public static int Version => System.Threading.Volatile.Read(ref _version);

        public static event Action Changed;

        static NetRanges()
        {
            Refresh();
            try { NetworkChange.NetworkAddressChanged += (_, __) => Refresh(); }
            catch (NetworkInformationException) { }
        }

        /// <summary>Reads the adapters again. Runs by itself when the network changes.</summary>
        public static void Refresh()
        {
            List<(string Cidr, string Adapter)> adapters;
            try { adapters = AdapterSource?.Invoke() ?? new List<(string, string)>(); }
            catch (Exception ex) when (ex is NetworkInformationException || ex is InvalidOperationException) { adapters = new List<(string, string)>(); }
            var lan = Merge(adapters.Select(a => Block(a.Cidr)).Concat(LinkLocalBlocks.Select(Block)).Concat(DiscoveryBlocks.Select(Block)));
            var notInternet = Merge(lan.Concat(UnroutableBlocks.Select(Block)).Concat(UnroutableV6Blocks.Select(Block)));
            var internet = Merge(ComplementV4(notInternet).Concat(Complement(notInternet.Where(x => x.V6).ToList(), true)));
            lock (Gate)
            {
                var same = _lan != null && _lan.Count == lan.Count && _lan.Zip(lan, (a, b) => a.V6 == b.V6 && a.First == b.First && a.Last == b.Last).All(x => x);
                _lan = lan;
                _internet = internet;
                if (same && _version > 0) return;
                InternetCache.Clear();
                LanCache.Clear();
                AllowedCache.Clear();
                System.Threading.Interlocked.Increment(ref _version);
            }
            Changed?.Invoke();
        }

        /// <summary>The LAN, as Windows Firewall takes remote addresses.</summary>
        public static string LanText => string.Join(",", _lan.Select(Text));

        /// <summary>Accepts a.b.c.d/n, a bare address (one host), and the IPv6 forms. Host bits are cleared, so 192.168.1.7/24 becomes 192.168.1.0/24.</summary>
        public static bool TryNormalize(string text, out string cidr)
        {
            cidr = null;
            text = (text ?? "").Trim();
            var slash = text.IndexOf('/');
            var addressText = slash < 0 ? text : text.Substring(0, slash);
            // .NET reads "10.1" as 10.0.0.1, which is never what someone typing a subnet means.
            if (addressText.Contains('.') && !addressText.Contains(':') && addressText.Count(c => c == '.') != 3) return false;
            if (addressText.Contains('%') || !IPAddress.TryParse(addressText, out var address)) return false;
            var bits = address.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;
            var prefix = bits;
            if (slash >= 0 && (!int.TryParse(text.Substring(slash + 1), NumberStyles.None, CultureInfo.InvariantCulture, out prefix) || prefix > bits)) return false;
            var range = Block(address, prefix);
            cidr = ToAddress(range.First, range.V6) + "/" + prefix;
            return true;
        }

        /// <summary>The first and last address of a CIDR or single address, as numbers.</summary>
        public static bool TryRange(string text, out bool v6, out BigInteger first, out BigInteger last)
        {
            v6 = false;
            first = last = BigInteger.Zero;
            if (!TryNormalize(text, out var cidr)) return false;
            var r = Block(cidr);
            v6 = r.V6;
            first = r.First;
            last = r.Last;
            return true;
        }

        /// <exception cref="FormatException">A subnet isn't valid. The message names it.</exception>
        public static List<string> NormalizeSubnets(IEnumerable<string> subnets)
        {
            var result = new List<string>();
            foreach (var s in subnets ?? Enumerable.Empty<string>())
            {
                if (string.IsNullOrWhiteSpace(s)) continue;
                if (!TryNormalize(s, out var cidr)) throw new FormatException($"\"{s.Trim()}\" isn't a subnet. Use a form like 192.168.1.0/24.");
                if (!result.Contains(cidr)) result.Add(cidr);
            }
            return result;
        }

        /// <summary>The remote addresses a rule allows, as Windows Firewall takes them.</summary>
        /// <returns>Null when nothing is limited.</returns>
        public static string ForWindows(bool internet, LanAccess lan, IEnumerable<string> subnets)
        {
            var ranges = Allowed(internet, lan, subnets);
            return ranges == null ? null : string.Join(",", ranges.Select(Text));
        }

        /// <summary>An address that can't be read is allowed, since the firewall is what decides those.</summary>
        public static bool Allows(bool internet, LanAccess lan, IEnumerable<string> subnets, string ip)
        {
            if (internet && lan == LanAccess.All) return true;
            // Checked for every connection every second, so the ranges are worked out once per setting.
            var key = $"{internet}|{lan}|{(lan == LanAccess.Selected ? string.Join(",", subnets ?? Enumerable.Empty<string>()) : "")}";
            if (AllowedCache.Count > 256) AllowedCache.Clear();
            var ranges = AllowedCache.GetOrAdd(key, _ => Allowed(internet, lan, subnets));
            return ranges == null || Contains(ranges, ip, true);
        }

        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, List<Range>> AllowedCache =
            new System.Collections.Concurrent.ConcurrentDictionary<string, List<Range>>(StringComparer.Ordinal);

        /// <summary>On the network of an Ethernet or Wi-Fi adapter, link-local, or local discovery. Asked for every row, so answers are kept.</summary>
        public static bool IsLan(string ip)
        {
            if (string.IsNullOrEmpty(ip) || ip == "*") return false;
            if (LanCache.Count > 20000) LanCache.Clear();
            return LanCache.GetOrAdd(ip, a => Contains(_lan, a, false));
        }

        /// <summary>Anything routable that isn't LAN. Asked for every connection, so answers are kept per address.</summary>
        public static bool IsInternet(string ip)
        {
            if (string.IsNullOrEmpty(ip) || ip == "*") return false;
            if (InternetCache.Count > 20000) InternetCache.Clear();
            return InternetCache.GetOrAdd(ip, a => Contains(_internet, a, false));
        }

        /// <summary>A public internet address in the strict sense, whatever the network: never private, link-local, multicast or reserved.</summary>
        public static bool IsPublicAddress(string ip) => !string.IsNullOrEmpty(ip) && ip != "*" && Contains(Public, ip, false);

        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, bool> InternetCache =
            new System.Collections.Concurrent.ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, bool> LanCache =
            new System.Collections.Concurrent.ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

        private static bool Contains(List<Range> ranges, string ip, bool unreadable)
        {
            if (!IPAddress.TryParse(IpText.Normalize(ip), out var address)) return unreadable;
            if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
            var v6 = address.AddressFamily == AddressFamily.InterNetworkV6;
            var n = ToNumber(address);
            return ranges.Any(r => r.V6 == v6 && r.First <= n && n <= r.Last);
        }

        private static List<Range> Allowed(bool internet, LanAccess lan, IEnumerable<string> subnets)
        {
            if (internet && lan == LanAccess.All) return null;
            var parts = new List<Range>();
            if (internet) parts.AddRange(_internet);
            if (lan == LanAccess.All) parts.AddRange(_lan);
            else if (lan == LanAccess.Selected)
            {
                parts.AddRange(Discovery);
                // Saved subnets are checked when saved. One edited by hand that doesn't read is left out, which allows less, not more.
                foreach (var s in subnets ?? Enumerable.Empty<string>())
                    if (TryNormalize(s, out var cidr)) parts.Add(Block(cidr));
            }
            return Merge(parts);
        }

        /// <summary>The subnets of this PC's LAN: those of its connected Ethernet and Wi-Fi adapters.</summary>
        public static List<(string Cidr, string Adapter)> LocalSubnets()
        {
            try { return AdapterSource?.Invoke() ?? new List<(string, string)>(); }
            catch (NetworkInformationException) { return new List<(string, string)>(); }
        }

        /// <summary>Virtual adapters look like Ethernet to Windows but lead elsewhere: to a VPN, a virtual machine or a capture driver.</summary>
        private static readonly string[] VirtualWords = { "Hyper-V", "vEthernet", "VMware", "VirtualBox", "Virtual", "TAP-", "Wintun", "WireGuard", "OpenVPN", "Npcap", "Loopback", "Bluetooth", "VPN", "Tunnel" };

        public static bool IsLanAdapter(NetworkInterfaceType type, string name, string description)
        {
            var physical = type == NetworkInterfaceType.Ethernet || type == NetworkInterfaceType.Wireless80211 || type == NetworkInterfaceType.GigabitEthernet
                           || type == NetworkInterfaceType.FastEthernetT || type == NetworkInterfaceType.FastEthernetFx || type == NetworkInterfaceType.Ethernet3Megabit;
            var text = (name ?? "") + " " + (description ?? "");
            return physical && !VirtualWords.Any(w => text.IndexOf(w, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        /// <summary>Every address subnet, IPv4 and IPv6, on connected Ethernet and Wi-Fi adapters.</summary>
        private static List<(string Cidr, string Adapter)> ReadAdapters()
        {
            var result = new List<(string Cidr, string Adapter)>();
            NetworkInterface[] adapters;
            try { adapters = NetworkInterface.GetAllNetworkInterfaces(); }
            catch (NetworkInformationException) { return result; }
            foreach (var adapter in adapters)
            {
                if (adapter.OperationalStatus != OperationalStatus.Up || !IsLanAdapter(adapter.NetworkInterfaceType, adapter.Name, adapter.Description)) continue;
                foreach (var u in adapter.GetIPProperties().UnicastAddresses)
                {
                    var a = u.Address;
                    if (a.AddressFamily != AddressFamily.InterNetwork && a.AddressFamily != AddressFamily.InterNetworkV6) continue;
                    if (u.PrefixLength <= 0) continue;
                    var address = new IPAddress(a.GetAddressBytes()).ToString();
                    if (TryNormalize(address + "/" + u.PrefixLength, out var cidr) && !result.Any(x => x.Cidr == cidr))
                        result.Add((cidr, adapter.Name));
                }
            }
            return result;
        }

        private static Range Block(string cidr)
        {
            var slash = cidr.IndexOf('/');
            return Block(IPAddress.Parse(cidr.Substring(0, slash)), int.Parse(cidr.Substring(slash + 1), CultureInfo.InvariantCulture));
        }

        private static Range Block(IPAddress address, int prefix)
        {
            var v6 = address.AddressFamily == AddressFamily.InterNetworkV6;
            var size = BigInteger.One << ((v6 ? 128 : 32) - prefix);
            var first = ToNumber(address) / size * size;
            return new Range { V6 = v6, First = first, Last = first + size - 1 };
        }

        private static BigInteger ToNumber(IPAddress address)
        {
            // BigInteger reads little-endian and signed, so the bytes are reversed and given a zero top byte.
            var bytes = address.GetAddressBytes().Reverse().Concat(new byte[] { 0 }).ToArray();
            return new BigInteger(bytes);
        }

        public static string ToAddress(BigInteger n, bool v6)
        {
            var length = v6 ? 16 : 4;
            var little = n.ToByteArray();
            var bytes = new byte[length];
            for (var i = 0; i < length && i < little.Length; i++) bytes[length - 1 - i] = little[i];
            return new IPAddress(bytes).ToString();
        }

        private static string Text(Range r)
        {
            var first = ToAddress(r.First, r.V6);
            return r.First == r.Last ? first : first + "-" + ToAddress(r.Last, r.V6);
        }

        private static List<Range> Merge(IEnumerable<Range> ranges)
        {
            var result = new List<Range>();
            foreach (var r in ranges.OrderBy(x => x.V6).ThenBy(x => x.First))
            {
                if (result.Count > 0)
                {
                    var last = result[result.Count - 1];
                    if (last.V6 == r.V6 && r.First <= last.Last + 1)
                    {
                        if (r.Last > last.Last)
                        {
                            last.Last = r.Last;
                            result[result.Count - 1] = last;
                        }
                        continue;
                    }
                }
                result.Add(r);
            }
            return result;
        }

        /// <summary>Everything of one family that the ranges don't cover.</summary>
        private static IEnumerable<Range> Complement(List<Range> taken, bool v6)
        {
            var max = (BigInteger.One << (v6 ? 128 : 32)) - 1;
            var next = BigInteger.Zero;
            foreach (var r in taken.Where(x => x.V6 == v6).OrderBy(x => x.First))
            {
                if (r.First > next) yield return new Range { V6 = v6, First = next, Last = r.First - 1 };
                if (r.Last + 1 > next) next = r.Last + 1;
            }
            if (next <= max) yield return new Range { V6 = v6, First = next, Last = max };
        }

        private static IEnumerable<Range> ComplementV4(List<Range> taken)
        {
            var max = (BigInteger.One << 32) - 1;
            var next = BigInteger.Zero;
            foreach (var r in taken.Where(x => !x.V6))
            {
                if (r.First > next) yield return new Range { First = next, Last = r.First - 1 };
                next = r.Last + 1;
            }
            if (next <= max) yield return new Range { First = next, Last = max };
        }
    }
}
