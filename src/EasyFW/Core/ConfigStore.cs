using System;
using System.IO;
using System.Runtime.Serialization.Json;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Xml;

namespace EasyFW.Core
{
    /// <summary>
    /// Persists config as JSON. The default location is an admin-only folder under ProgramData:
    /// if ordinary programs could edit this file they could approve themselves at the next start.
    /// </summary>
    public sealed class ConfigStore
    {
        private readonly string _path;
        private readonly bool _readOnly;

        public AppConfig Config { get; private set; }

        public static string DefaultFolder =>
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "EasyFW");

        /// <param name="path">Null keeps config in memory only (demo mode).</param>
        public ConfigStore(string path, bool readOnly)
        {
            _path = path;
            _readOnly = readOnly || path == null;
            Config = Load();
        }

        /// <summary>
        /// Brings rules and the Windows Firewall snapshot over from when the app was called HomeFW.
        /// Without the snapshot, the original firewall settings could never be put back.
        /// </summary>
        /// <returns>True if anything moved.</returns>
        public static bool MoveLegacyFolder(string dataRoot)
        {
            var oldFolder = Path.Combine(dataRoot, "HomeFW");
            var newFolder = Path.Combine(dataRoot, "EasyFW");
            var oldConfig = Path.Combine(oldFolder, "config.json");
            var newConfig = Path.Combine(newFolder, "config.json");
            if (!File.Exists(oldConfig) || File.Exists(newConfig)) return false;
            if (Directory.Exists(newFolder)) File.Move(oldConfig, newConfig);
            else Directory.Move(oldFolder, newFolder);
            return true;
        }

        public static void SecureFolder(string folder)
        {
            var dir = Directory.CreateDirectory(folder);
            var acl = new DirectorySecurity();
            acl.SetAccessRuleProtection(true, false);
            const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
            dir.SetAccessControl(acl);
        }

        private AppConfig Load()
        {
            if (_path == null) return new AppConfig();
            try
            {
                if (!File.Exists(_path)) return new AppConfig();
                var cfg = Deserialize(File.ReadAllBytes(_path));
                cfg.Normalize();
                return cfg;
            }
            catch (UnauthorizedAccessException ex)
            {
                Log.Write("Config not readable: " + ex.Message);
                return new AppConfig();
            }
            catch (Exception ex)
            {
                // Keep the bad file: it may hold the snapshot needed to restore Windows Firewall.
                Log.Write("Config unreadable, starting fresh: " + ex.Message);
                if (!_readOnly)
                {
                    try { File.Copy(_path, _path + ".bad", true); } catch (Exception) { }
                }
                return new AppConfig();
            }
        }

        public static AppConfig Deserialize(byte[] bytes)
        {
            var offset = bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF ? 3 : 0;
            using var ms = new MemoryStream(bytes, offset, bytes.Length - offset);
            return (AppConfig)new DataContractJsonSerializer(typeof(AppConfig)).ReadObject(ms);
        }

        public static byte[] Serialize(AppConfig config)
        {
            using var ms = new MemoryStream();
            using (var w = JsonReaderWriterFactory.CreateJsonWriter(ms, new UTF8Encoding(false), false, true))
            {
                new DataContractJsonSerializer(typeof(AppConfig)).WriteObject(w, config);
                w.Flush();
            }
            return ms.ToArray();
        }

        /// <summary>Atomic, so a crash mid-save can't lose the Windows Firewall snapshot.</summary>
        public void Save()
        {
            if (_readOnly) return;
            var tmp = _path + ".tmp";
            File.WriteAllBytes(tmp, Serialize(Config));
            if (File.Exists(_path)) File.Replace(tmp, _path, null);
            else File.Move(tmp, _path);
        }
    }
}
