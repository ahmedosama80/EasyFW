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
    /// LAN is the private and link-local ranges, plus broadcast and multicast so devices can still find each other.
    /// Internet is every other address that can be routed.
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

        private static readonly List<Range> Lan = Merge(PrivateBlocks.Concat(DiscoveryBlocks).Select(Block));
        private static readonly List<Range> Discovery = Merge(DiscoveryBlocks.Select(Block));
        /// <summary>All of IPv4 outside the blocks above, and IPv6 global unicast, which is where every internet IPv6 address lives.</summary>
        private static readonly List<Range> Internet = Merge(
            ComplementV4(Merge(PrivateBlocks.Concat(DiscoveryBlocks).Concat(UnroutableBlocks).Select(Block))).Concat(new[] { Block("2000::/3") }));

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
            var ranges = Allowed(internet, lan, subnets);
            return ranges == null || Contains(ranges, ip, true);
        }

        /// <summary>Uses the ranges worked out at startup, since country lookups ask this for every row.</summary>
        public static bool IsLan(string ip) => Contains(Lan, ip, false);

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
            if (internet) parts.AddRange(Internet);
            if (lan == LanAccess.All) parts.AddRange(Lan);
            else if (lan == LanAccess.Selected)
            {
                parts.AddRange(Discovery);
                // Saved subnets are checked when saved. One edited by hand that doesn't read is left out, which allows less, not more.
                foreach (var s in subnets ?? Enumerable.Empty<string>())
                    if (TryNormalize(s, out var cidr)) parts.Add(Block(cidr));
            }
            return Merge(parts);
        }

        /// <summary>The subnets of this PC's connected network adapters: every IPv4 one, and IPv6 unique-local ones, which are the IPv6 LAN.</summary>
        public static List<(string Cidr, string Adapter)> LocalSubnets()
        {
            var result = new List<(string Cidr, string Adapter)>();
            NetworkInterface[] adapters;
            try { adapters = NetworkInterface.GetAllNetworkInterfaces(); }
            catch (NetworkInformationException) { return result; }
            foreach (var adapter in adapters)
            {
                if (adapter.OperationalStatus != OperationalStatus.Up || adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var u in adapter.GetIPProperties().UnicastAddresses)
                {
                    var a = u.Address;
                    if (a.AddressFamily == AddressFamily.InterNetworkV6 && (a.GetAddressBytes()[0] & 0xFE) != 0xFC) continue;
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

        private static string ToAddress(BigInteger n, bool v6)
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
