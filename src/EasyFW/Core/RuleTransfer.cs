using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Xml;

namespace EasyFW.Core
{
    [DataContract]
    public sealed class RulesFile
    {
        [DataMember] public List<AppRule> Rules { get; set; }
    }

    /// <summary>Reads and writes rules files. Only rules move: never protection state or the Windows Firewall snapshot.</summary>
    public static class RuleTransfer
    {
        public static byte[] Export(IEnumerable<AppRule> rules)
        {
            using var ms = new MemoryStream();
            using (var w = JsonReaderWriterFactory.CreateJsonWriter(ms, new UTF8Encoding(false), false, true))
            {
                new DataContractJsonSerializer(typeof(RulesFile)).WriteObject(w, new RulesFile { Rules = rules.ToList() });
                w.Flush();
            }
            return ms.ToArray();
        }

        /// <summary>
        /// A file can come from anywhere, so every value is checked before it can reach the firewall.
        /// Rules get new ids because an id ends up in firewall rule names, where a crafted one could match other rules.
        /// </summary>
        /// <exception cref="InvalidDataException">The file isn't usable. The message says why.</exception>
        public static List<AppRule> Parse(byte[] bytes)
        {
            var result = new List<AppRule>();
            var rules = Read(bytes);
            for (var i = 0; i < rules.Count; i++)
            {
                var rule = Check(rules[i], i + 1);
                // One rule per app, as everywhere else. The last one in the file wins.
                result.RemoveAll(r => AppPaths.Same(r.AppPath, rule.AppPath));
                result.Add(rule);
            }
            return result;
        }

        private static List<AppRule> Read(byte[] bytes)
        {
            var offset = bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF ? 3 : 0;
            RulesFile file;
            try
            {
                using var ms = new MemoryStream(bytes, offset, bytes.Length - offset);
                file = (RulesFile)new DataContractJsonSerializer(typeof(RulesFile)).ReadObject(ms);
            }
            catch (Exception ex) when (ex is SerializationException || ex is XmlException)
            {
                throw new InvalidDataException("That file isn't a EasyFW rules file.", ex);
            }
            return file?.Rules ?? throw new InvalidDataException("That file isn't a EasyFW rules file.");
        }

        private static AppRule Check(AppRule rule, int number)
        {
            if (rule == null) throw Bad(number, "it's empty");
            var path = AppPaths.Normalize(rule.AppPath);
            if (!AppPaths.IsRuleTarget(path)) throw Bad(number, "it needs the full path of a program");
            if (!Enum.IsDefined(typeof(RuleAction), rule.Action)) throw Bad(number, "its decision isn't valid");
            if (!Enum.IsDefined(typeof(RuleDirection), rule.Direction)) throw Bad(number, "its direction isn't valid");

            string ports;
            try { ports = PortList.Normalize(rule.Ports); }
            catch (FormatException ex) { throw Bad(number, ex.Message); }
            if (ports != null && AppPaths.Same(path, AppPaths.PingApp)) throw Bad(number, "pings don't use ports");

            return new AppRule
            {
                AppPath = path, Action = rule.Action, Direction = rule.Direction, Enabled = rule.Enabled, Notes = rule.Notes, Ports = ports,
                CreatedUtc = rule.CreatedUtc == default ? DateTime.UtcNow : rule.CreatedUtc
            };
        }

        private static InvalidDataException Bad(int number, string reason) =>
            new InvalidDataException($"Rule {number} in that file can't be used: {reason}. Nothing was imported.");
    }
}
