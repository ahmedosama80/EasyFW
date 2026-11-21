using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using EasyFW.Core;

namespace EasyFW.Platform
{
    /// <summary>The folders and printers this PC shares, and who is using them, read from Windows (WMI). Needs administrator rights for the users.</summary>
    public static class Shares
    {
        private const uint AdminFlag = 0x80000000;

        public static List<ShareInfo> Read()
        {
            var shares = new List<ShareInfo>();
            using (var search = new ManagementObjectSearcher("SELECT Name, Path, Description, Type FROM Win32_Share"))
            using (var results = search.Get())
            {
                foreach (ManagementObject s in results)
                {
                    using (s)
                    {
                        var type = Convert.ToUInt32(s["Type"] ?? 0u);
                        var kind = type & ~AdminFlag;
                        shares.Add(new ShareInfo
                        {
                            Name = (string)s["Name"],
                            Path = (string)s["Path"] ?? "",
                            Description = (string)s["Description"] ?? "",
                            IsAdmin = (type & AdminFlag) != 0,
                            Type = kind == 0 ? "Folder" : kind == 1 ? "Printer" : kind == 2 ? "Device" : kind == 3 ? "Remote control (IPC)" : "Other"
                        });
                    }
                }
            }
            try
            {
                using var search = new ManagementObjectSearcher("SELECT ShareName, ComputerName, UserName, NumberOfFiles, ActiveTime FROM Win32_ServerConnection");
                using var results = search.Get();
                foreach (ManagementObject c in results)
                {
                    using (c)
                    {
                        var share = shares.FirstOrDefault(x => string.Equals(x.Name, (string)c["ShareName"], StringComparison.OrdinalIgnoreCase));
                        share?.Users.Add(new ShareUser
                        {
                            Computer = (string)c["ComputerName"] ?? "",
                            User = (string)c["UserName"] ?? "",
                            Files = Convert.ToInt32(c["NumberOfFiles"] ?? 0),
                            Seconds = Convert.ToInt32(c["ActiveTime"] ?? 0)
                        });
                    }
                }
            }
            // Without administrator rights Windows won't say who's connected; the shares still list.
            catch (ManagementException ex) { Log.Write("Can't read share connections: " + ex.Message); }
            catch (UnauthorizedAccessException ex) { Log.Write("Can't read share connections: " + ex.Message); }
            return shares;
        }

        /// <summary>Stops sharing a folder. The folder and its files stay.</summary>
        /// <exception cref="InvalidOperationException">Windows refused.</exception>
        public static void StopSharing(string name)
        {
            using var share = new ManagementObject($"Win32_Share.Name='{name.Replace("\\", "\\\\").Replace("'", "\\'")}'");
            var result = Convert.ToUInt32(share.InvokeMethod("Delete", null));
            if (result != 0) throw new InvalidOperationException($"Windows didn't stop sharing \"{name}\" (error {result}).");
        }
    }
}
