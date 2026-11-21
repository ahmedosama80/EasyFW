using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EasyFW.Core
{
    public enum UpdateChoice { NotAsked, Auto, Off }

    /// <summary>A release on GitHub that EasyFW can install.</summary>
    public sealed class ReleaseInfo
    {
        public Version Version { get; set; }
        public string Tag { get; set; }
        public string PageUrl { get; set; }
        public string ZipName { get; set; }
        public string ZipUrl { get; set; }
        public long ZipSize { get; set; }
        /// <summary>Lowercase hex, when GitHub gives one.</summary>
        public string Sha256 { get; set; }
    }

    /// <summary>
    /// Updates EasyFW from its GitHub releases: finds the newest release, downloads its Windows zip, checks it,
    /// and swaps the files beside the running exe. Windows lets a running exe be renamed, so the old one moves aside
    /// as *.old and goes at the next start. Anything that fails puts the old files back.
    /// </summary>
    public static class Updater
    {
        public const string Repo = "ahmedosama80/EasyFW";
        public static string LatestUrl => $"https://api.github.com/repos/{Repo}/releases/latest";
        public static string ReleasesPage => $"https://github.com/{Repo}/releases";

        /// <summary>Swappable for tests: the text at a URL, or null for 404.</summary>
        public static Func<string, Task<string>> GetText { get; set; } = DefaultGetText;
        /// <summary>Swappable for tests: saves a URL to a file.</summary>
        public static Func<string, string, Task> Download { get; set; } = DefaultDownload;

        [DataContract]
        private sealed class GhRelease
        {
            [DataMember(Name = "tag_name")] public string Tag { get; set; }
            [DataMember(Name = "html_url")] public string Page { get; set; }
            [DataMember(Name = "draft")] public bool Draft { get; set; }
            [DataMember(Name = "prerelease")] public bool Prerelease { get; set; }
            [DataMember(Name = "assets")] public List<GhAsset> Assets { get; set; }
        }

        [DataContract]
        private sealed class GhAsset
        {
            [DataMember(Name = "name")] public string Name { get; set; }
            [DataMember(Name = "browser_download_url")] public string Url { get; set; }
            [DataMember(Name = "size")] public long Size { get; set; }
            [DataMember(Name = "digest")] public string Digest { get; set; }
        }

        /// <summary>"v2.1.0" or "2.1" as a version, or null.</summary>
        public static Version ParseTag(string tag)
        {
            var text = (tag ?? "").Trim().TrimStart('v', 'V');
            if (!Version.TryParse(text, out var v)) return null;
            return new Version(v.Major, v.Minor, Math.Max(0, v.Build));
        }

        public static bool IsNewer(ReleaseInfo release, string current) =>
            release?.Version != null && Version.TryParse(current, out var mine) && release.Version > new Version(mine.Major, mine.Minor, Math.Max(0, mine.Build));

        /// <summary>Reads GitHub's answer for the latest release.</summary>
        /// <returns>Null when no usable release is published.</returns>
        public static ReleaseInfo Parse(string json)
        {
            if (string.IsNullOrWhiteSpace(json)) return null;
            GhRelease r;
            using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(json)))
                r = (GhRelease)new DataContractJsonSerializer(typeof(GhRelease)).ReadObject(stream);
            var version = ParseTag(r?.Tag);
            if (r == null || r.Draft || r.Prerelease || version == null) return null;
            var zip = r.Assets?.FirstOrDefault(a => a.Name != null && a.Name.StartsWith("EasyFW-", StringComparison.OrdinalIgnoreCase)
                                                     && a.Name.EndsWith("-windows.zip", StringComparison.OrdinalIgnoreCase)
                                                     && a.Url != null && a.Url.StartsWith("https://github.com/" + Repo + "/", StringComparison.OrdinalIgnoreCase));
            if (zip == null) return null;
            var digest = zip.Digest != null && zip.Digest.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) ? zip.Digest.Substring(7).ToLowerInvariant() : null;
            return new ReleaseInfo { Version = version, Tag = r.Tag, PageUrl = r.Page, ZipName = zip.Name, ZipUrl = zip.Url, ZipSize = zip.Size, Sha256 = digest };
        }

        public static async Task<ReleaseInfo> LatestAsync() => Parse(await GetText(LatestUrl).ConfigureAwait(false));

        /// <summary>Downloads and unpacks a release into <paramref name="workDir"/>\staging, and checks it's the version it claims.</summary>
        /// <returns>The folder holding the new files.</returns>
        /// <exception cref="InvalidDataException">The download doesn't check out.</exception>
        public static async Task<string> StageAsync(ReleaseInfo release, string workDir)
        {
            Directory.CreateDirectory(workDir);
            var zipPath = Path.Combine(workDir, "update.zip");
            var staging = Path.Combine(workDir, "staging");
            if (File.Exists(zipPath)) File.Delete(zipPath);
            if (Directory.Exists(staging)) Directory.Delete(staging, true);

            await Download(release.ZipUrl, zipPath).ConfigureAwait(false);
            var size = new FileInfo(zipPath).Length;
            if (release.ZipSize > 0 && size != release.ZipSize) throw new InvalidDataException($"The download is {size} bytes, GitHub said {release.ZipSize}.");
            if (release.Sha256 != null && Sha256Of(zipPath) != release.Sha256) throw new InvalidDataException("The download doesn't match GitHub's checksum.");

            Directory.CreateDirectory(staging);
            using (var zip = ZipFile.OpenRead(zipPath))
            {
                foreach (var entry in zip.Entries)
                {
                    // Only plain files at the top of the zip. Anything with a folder in its name is left out, so nothing lands outside the install folder.
                    if (entry.FullName.IndexOfAny(new[] { '/', '\\', ':' }) >= 0 || entry.Name.Length == 0 || entry.Name.StartsWith(".")) continue;
                    entry.ExtractToFile(Path.Combine(staging, entry.Name), true);
                }
            }
            File.Delete(zipPath);

            var exe = Path.Combine(staging, "EasyFW.exe");
            if (!File.Exists(exe)) throw new InvalidDataException("The release has no EasyFW.exe.");
            var built = AssemblyName.GetAssemblyName(exe).Version;
            if (new Version(built.Major, built.Minor, Math.Max(0, built.Build)) != release.Version)
                throw new InvalidDataException($"The release says {release.Version} but its EasyFW.exe is {built.ToString(3)}.");
            return staging;
        }

        /// <summary>Puts the staged files in the install folder. Each file it replaces is kept as *.old until the next start.</summary>
        public static void Install(string staging, string installDir)
        {
            var moved = new List<(string Target, string Old)>();
            var added = new List<string>();
            try
            {
                foreach (var source in Directory.GetFiles(staging))
                {
                    var target = Path.Combine(installDir, Path.GetFileName(source));
                    if (File.Exists(target))
                    {
                        var old = target + ".old";
                        if (File.Exists(old))
                        {
                            try { File.Delete(old); }
                            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { old = target + "." + DateTime.UtcNow.Ticks + ".old"; }
                        }
                        File.Move(target, old);
                        moved.Add((target, old));
                    }
                    File.Copy(source, target);
                    added.Add(target);
                }
            }
            catch
            {
                foreach (var file in added)
                {
                    try { File.Delete(file); } catch (Exception ex) { Log.Write($"Update rollback: couldn't remove {file}: {ex.Message}"); }
                }
                foreach (var (target, old) in moved)
                {
                    try { File.Move(old, target); } catch (Exception ex) { Log.Write($"Update rollback: couldn't restore {target}: {ex.Message}"); }
                }
                throw;
            }
            try { Directory.Delete(staging, true); } catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
        }

        /// <summary>Deletes files an earlier update moved aside. Ones still in use stay for next time.</summary>
        public static void CleanUp(string installDir)
        {
            foreach (var old in Directory.GetFiles(installDir, "*.old"))
            {
                try { File.Delete(old); }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
            }
        }

        public static string Sha256Of(string path)
        {
            using var sha = SHA256.Create();
            using var stream = File.OpenRead(path);
            return string.Concat(sha.ComputeHash(stream).Select(b => b.ToString("x2")));
        }

        private static HttpWebRequest Request(string url)
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            var request = (HttpWebRequest)WebRequest.Create(url);
            request.UserAgent = "EasyFW/" + AppInfo.Version;
            request.Accept = url.Contains("api.github.com") ? "application/vnd.github+json" : "*/*";
            request.Timeout = request.ReadWriteTimeout = 30000;
            request.AllowAutoRedirect = true;
            return request;
        }

        private static async Task<string> DefaultGetText(string url)
        {
            try
            {
                using var response = (HttpWebResponse)await Request(url).GetResponseAsync().ConfigureAwait(false);
                using var reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8);
                return await reader.ReadToEndAsync().ConfigureAwait(false);
            }
            catch (WebException ex) when ((ex.Response as HttpWebResponse)?.StatusCode == HttpStatusCode.NotFound) { return null; }
        }

        private static async Task DefaultDownload(string url, string path)
        {
            var request = Request(url);
            request.Timeout = request.ReadWriteTimeout = 120000;
            using var response = await request.GetResponseAsync().ConfigureAwait(false);
            // Downloads redirect to GitHub's file host. Anything else is refused.
            var host = response.ResponseUri.Host;
            if (!host.EndsWith("github.com", StringComparison.OrdinalIgnoreCase) && !host.EndsWith("githubusercontent.com", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("The download came from " + host + ", not GitHub.");
            using var input = response.GetResponseStream();
            using var output = File.Create(path);
            await input.CopyToAsync(output).ConfigureAwait(false);
        }
    }
}
