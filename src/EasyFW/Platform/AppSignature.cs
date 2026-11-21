using System;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using EasyFW.Core;

namespace EasyFW.Platform
{
    /// <summary>
    /// Whether a program has a valid digital signature, and who signed it. Checked the way Windows checks it (WinVerifyTrust),
    /// including programs signed through a Windows catalog, as most Windows programs are. Revocation isn't checked online,
    /// so a check never waits on the network. Checks run in the background and are cached; <see cref="Version"/> changes when one finishes.
    /// </summary>
    public static class AppSignature
    {
        public const string Checking = "";
        private const int Workers = 2;
        private static readonly ConcurrentDictionary<string, string> Results = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentQueue<string> Queue = new ConcurrentQueue<string>();
        private static int _workers, _version;

        public static int Version => Volatile.Read(ref _version);

        /// <summary>"Yes (signer)", "No", "Not valid", "File missing", or "" while it's being checked.</summary>
        public static string Text(string appPath)
        {
            if (string.IsNullOrEmpty(appPath)) return "";
            if (AppPaths.IsPseudoApp(appPath)) return "Yes (Windows)";
            if (Results.TryGetValue(appPath, out var text)) return text ?? Checking;
            if (Results.Count > 5000) Results.Clear();
            if (Results.TryAdd(appPath, null))
            {
                Queue.Enqueue(appPath);
                StartWorker();
            }
            return Checking;
        }

        /// <summary>True for a valid signature, false for none or a broken one, null while unknown.</summary>
        public static bool? IsSigned(string appPath)
        {
            var t = Text(appPath);
            return t.Length == 0 ? (bool?)null : t.StartsWith("Yes", StringComparison.Ordinal);
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
                while (Queue.TryDequeue(out var path))
                {
                    string text;
                    try { text = Check(path); }
                    catch (Exception ex)
                    {
                        Log.Write($"Signature check failed for {path}: {ex.Message}");
                        text = "Unknown";
                    }
                    Results[path] = text;
                    Interlocked.Increment(ref _version);
                }
                Interlocked.Decrement(ref _workers);
                if (!Queue.IsEmpty) StartWorker();
            });
        }

        public static string Check(string appPath)
        {
            var path = Environment.ExpandEnvironmentVariables(appPath);
            if (!File.Exists(path)) return "File missing";
            var embedded = Verify.File(path);
            if (embedded == 0) return "Yes (" + Signer(path) + ")";
            if (!Verify.IsUnsigned(embedded)) return "Not valid";
            var catalog = Verify.Catalog(path, out var catalogFile);
            if (catalog == 0) return "Yes (" + Signer(catalogFile, "Windows catalog") + ")";
            return catalog == Verify.NotInCatalog || Verify.IsUnsigned(catalog) ? "No" : "Not valid";
        }

        private static string Signer(string signedFile, string fallback = "signed")
        {
            try
            {
                using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(signedFile));
                var name = cert.GetNameInfo(X509NameType.SimpleName, false);
                return string.IsNullOrEmpty(name) ? fallback : name;
            }
            catch (Exception) { return fallback; }
        }

        private static class Verify
        {
            private static readonly IntPtr NoWindow = new IntPtr(-1);
            private static readonly Guid GenericVerifyV2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
            private const uint UiNone = 2, RevokeNone = 0, ChoiceFile = 1, ChoiceCatalog = 2, CacheOnlyUrlRetrieval = 0x1000;
            public const int NotInCatalog = -1;

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            private struct FileInfo
            {
                public uint cbStruct;
                public string pcwszFilePath;
                public IntPtr hFile;
                public IntPtr pgKnownSubject;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            private struct CatalogInfo
            {
                public uint cbStruct;
                public uint dwCatalogVersion;
                public string pcwszCatalogFilePath;
                public string pcwszMemberTag;
                public string pcwszMemberFilePath;
                public IntPtr hMemberFile;
                public IntPtr pbCalculatedFileHash;
                public uint cbCalculatedFileHash;
                public IntPtr pcCatalogContext;
                public IntPtr hCatAdmin;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct TrustData
            {
                public uint cbStruct;
                public IntPtr pPolicyCallbackData;
                public IntPtr pSIPClientData;
                public uint dwUIChoice;
                public uint fdwRevocationChecks;
                public uint dwUnionChoice;
                public IntPtr pInfo;
                public uint dwStateAction;
                public IntPtr hWVTStateData;
                public IntPtr pwszURLReference;
                public uint dwProvFlags;
                public uint dwUIContext;
                public IntPtr pSignatureSettings;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            private struct CatalogFile
            {
                public uint cbStruct;
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile;
            }

            [DllImport("wintrust.dll", ExactSpelling = true)]
            private static extern int WinVerifyTrust(IntPtr hwnd, [In] ref Guid action, [In] ref TrustData data);

            [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
            private static extern bool CryptCATAdminAcquireContext2(out IntPtr admin, IntPtr subsystem, string hashAlgorithm, IntPtr strongHashPolicy, uint flags);

            [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
            private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr admin, IntPtr file, ref uint hashSize, [Out] byte[] hash, uint flags);

            [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
            private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr admin, byte[] hash, uint hashSize, uint flags, IntPtr previous);

            [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
            private static extern bool CryptCATCatalogInfoFromContext(IntPtr catInfo, ref CatalogFile info, uint flags);

            [DllImport("wintrust.dll", ExactSpelling = true)]
            private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr admin, IntPtr catInfo, uint flags);

            [DllImport("wintrust.dll", ExactSpelling = true)]
            private static extern bool CryptCATAdminReleaseContext(IntPtr admin, uint flags);

            /// <summary>No signature, or a file type that can't carry one.</summary>
            public static bool IsUnsigned(int result) =>
                result == unchecked((int)0x800B0100) || result == unchecked((int)0x800B0003) || result == unchecked((int)0x800B0001);

            private static int Run(uint choice, IntPtr info)
            {
                var data = new TrustData
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(TrustData)), dwUIChoice = UiNone, fdwRevocationChecks = RevokeNone,
                    dwUnionChoice = choice, pInfo = info, dwProvFlags = CacheOnlyUrlRetrieval
                };
                var action = GenericVerifyV2;
                return WinVerifyTrust(NoWindow, ref action, ref data);
            }

            public static int File(string path)
            {
                var info = new FileInfo { cbStruct = (uint)Marshal.SizeOf(typeof(FileInfo)), pcwszFilePath = path };
                var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(FileInfo)));
                try
                {
                    Marshal.StructureToPtr(info, ptr, false);
                    try { return Run(ChoiceFile, ptr); }
                    finally { Marshal.DestroyStructure(ptr, typeof(FileInfo)); }
                }
                finally { Marshal.FreeHGlobal(ptr); }
            }

            /// <summary>Looks the file's hash up in the Windows catalogs, SHA-256 first, then SHA-1 for older catalogs.</summary>
            public static int Catalog(string path, out string catalogFile)
            {
                catalogFile = null;
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                foreach (var algorithm in new[] { "SHA256", "SHA1" })
                {
                    if (!CryptCATAdminAcquireContext2(out var admin, IntPtr.Zero, algorithm, IntPtr.Zero, 0)) continue;
                    try
                    {
                        uint size = 0;
                        var handle = stream.SafeFileHandle.DangerousGetHandle();
                        CryptCATAdminCalcHashFromFileHandle2(admin, handle, ref size, null, 0);
                        if (size == 0 || size > 256) continue;
                        var hash = new byte[size];
                        if (!CryptCATAdminCalcHashFromFileHandle2(admin, handle, ref size, hash, 0)) continue;
                        var catInfo = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, IntPtr.Zero);
                        if (catInfo == IntPtr.Zero) continue;
                        try
                        {
                            var file = new CatalogFile { cbStruct = (uint)Marshal.SizeOf(typeof(CatalogFile)) };
                            if (!CryptCATCatalogInfoFromContext(catInfo, ref file, 0)) continue;
                            catalogFile = file.wszCatalogFile;
                            return VerifyInCatalog(path, file.wszCatalogFile, hash, admin);
                        }
                        finally { CryptCATAdminReleaseCatalogContext(admin, catInfo, 0); }
                    }
                    finally { CryptCATAdminReleaseContext(admin, 0); }
                }
                return NotInCatalog;
            }

            private static int VerifyInCatalog(string path, string catalog, byte[] hash, IntPtr admin)
            {
                var hashPtr = Marshal.AllocHGlobal(hash.Length);
                var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(CatalogInfo)));
                try
                {
                    Marshal.Copy(hash, 0, hashPtr, hash.Length);
                    var info = new CatalogInfo
                    {
                        cbStruct = (uint)Marshal.SizeOf(typeof(CatalogInfo)), pcwszCatalogFilePath = catalog,
                        pcwszMemberTag = BitConverter.ToString(hash).Replace("-", ""), pcwszMemberFilePath = path,
                        pbCalculatedFileHash = hashPtr, cbCalculatedFileHash = (uint)hash.Length, hCatAdmin = admin
                    };
                    Marshal.StructureToPtr(info, ptr, false);
                    try { return Run(ChoiceCatalog, ptr); }
                    finally { Marshal.DestroyStructure(ptr, typeof(CatalogInfo)); }
                }
                finally
                {
                    Marshal.FreeHGlobal(ptr);
                    Marshal.FreeHGlobal(hashPtr);
                }
            }
        }
    }
}
