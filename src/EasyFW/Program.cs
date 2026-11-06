using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Windows.Forms;
using EasyFW.Core;
using EasyFW.Demo;
using EasyFW.Platform;
using EasyFW.UI;

namespace EasyFW
{
    public sealed class AppEnvironment
    {
        public FirewallService Service { get; set; }
        public IEventSource Events { get; set; }
        public Func<List<ActiveEndpoint>> PollActive { get; set; }
        /// <summary>Null when open connections mustn't be closed: in monitor-only and demo modes.</summary>
        public Func<ActiveEndpoint, bool> CloseConnection { get; set; }
    }

    public static class Program
    {
        private const string ShowEventName = @"Local\EasyFW.Show";
        private const string MutexName = @"Local\EasyFW.Instance";
        private static Mutex _instance;

        public static string ExePath => Process.GetCurrentProcess().MainModule.FileName;

        [STAThread]
        private static int Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.ThreadException += (_, e) => ReportFatal(e.Exception);
            AppDomain.CurrentDomain.UnhandledException += (_, e) => ReportFatal(e.ExceptionObject as Exception);

            var demo = args.Contains("--demo");
            var monitorOnly = args.Contains("--monitor-only");
            var startInTray = args.Contains("--tray");

            if (!demo && !TakeOverFromHomeFW()) return 1;

            if (args.Contains("--restore")) return RunRestore();

            // Demo mode has no shared state, so it may run beside a real instance.
            EventWaitHandle showSignal = null;
            if (!demo && !AcquireSingleInstance()) return 0;

            var env = demo ? BuildDemo() : BuildReal(monitorOnly);
            if (!demo) showSignal = CreateShowSignal();

            using (var context = new TrayContext(env, startInTray, showSignal))
                Application.Run(context);

            ReleaseSingleInstance();
            return 0;
        }

        /// <summary>The app was called HomeFW. A running old copy would fight this one over the same firewall settings.</summary>
        private static bool TakeOverFromHomeFW()
        {
            if (Process.GetProcessesByName("HomeFW").Length > 0)
            {
                MessageBox.Show("HomeFW, the old version of this app, is still running. Exit it first (right-click its shield in the tray, then Exit), then start EasyFW again.",
                    "EasyFW", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }
            try
            {
                if (!ConfigStore.MoveLegacyFolder(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData))) return true;
            }
            catch (Exception ex)
            {
                Log.Write("Could not move HomeFW data: " + ex);
                MessageBox.Show("EasyFW couldn't bring over your rules from HomeFW, so it hasn't started: " + ex.Message, "EasyFW", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
            try { AutoStart.MoveLegacyTask(ExePath); }
            catch (Exception ex) { Log.Write("Could not move the HomeFW logon task: " + ex.Message); }
            return true;
        }

        /// <param name="monitorOnly">Reads only. The app always has administrator rights, so this flag alone keeps it from changing anything.</param>
        public static AppEnvironment BuildReal(bool monitorOnly)
        {
            var folder = ConfigStore.DefaultFolder;
            if (!monitorOnly)
            {
                try
                {
                    ConfigStore.SecureFolder(folder);
                    Log.FilePath = Path.Combine(folder, "easyfw.log");
                }
                catch (Exception ex) { Log.Write("Could not secure data folder: " + ex.Message); }
            }
            var store = new ConfigStore(Path.Combine(folder, "config.json"), monitorOnly);
            var reader = new ActiveConnectionReader();
            return new AppEnvironment
            {
                Service = new FirewallService(store, new WindowsFirewallBackend(), monitorOnly ? RunMode.MonitorOnly : RunMode.Live),
                Events = monitorOnly ? null : new SecurityLogEventSource(),
                PollActive = reader.Read,
                CloseConnection = monitorOnly ? (Func<ActiveEndpoint, bool>)null : ActiveConnectionReader.CloseTcp
            };
        }

        public static AppEnvironment BuildDemo()
        {
            var service = new FirewallService(new ConfigStore(null, true), new DemoBackend(), RunMode.Demo);
            return new AppEnvironment
            {
                Service = service,
                Events = new DemoTraffic(service.Evaluate),
                PollActive = DemoTraffic.ActiveSample
            };
        }

        private static void ReleaseSingleInstance()
        {
            _instance?.Dispose();
            _instance = null;
        }

        /// <summary>Leaves monitor-only for a normal start. The mutex goes first, or the new copy would exit as a duplicate.</summary>
        public static void RestartWithProtection()
        {
            ReleaseSingleInstance();
            Process.Start(ExePath);
            Application.ExitThread();
        }

        private static bool AcquireSingleInstance()
        {
            try
            {
                _instance = new Mutex(true, MutexName, out var created);
                if (created) return true;
                ReleaseSingleInstance();
            }
            // An elevated instance's mutex denies unelevated callers, which still means "already running".
            catch (UnauthorizedAccessException) { }

            try
            {
                using var signal = EventWaitHandle.OpenExisting(ShowEventName, EventWaitHandleRights.Modify);
                signal.Set();
            }
            catch (Exception ex) when (ex is WaitHandleCannotBeOpenedException || ex is UnauthorizedAccessException)
            {
                MessageBox.Show("EasyFW is already running. Look for its shield icon in the system tray.", "EasyFW");
            }
            return false;
        }

        private static EventWaitHandle CreateShowSignal()
        {
            // Open to everyone so an unelevated second launch can bring the elevated window forward.
            var security = new EventWaitHandleSecurity();
            security.AddAccessRule(new EventWaitHandleAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                EventWaitHandleRights.Modify | EventWaitHandleRights.Synchronize, AccessControlType.Allow));
            security.AddAccessRule(new EventWaitHandleAccessRule(WindowsIdentity.GetCurrent().User,
                EventWaitHandleRights.FullControl, AccessControlType.Allow));
            return new EventWaitHandle(false, EventResetMode.AutoReset, ShowEventName, out _, security);
        }

        /// <summary>Recovery path that works even if the UI can't start: puts Windows Firewall back and exits.</summary>
        private static int RunRestore()
        {
            // A running copy still believes protection is on, and its next check would block everything again.
            if (!AcquireSingleInstance())
            {
                MessageBox.Show("EasyFW is running. Exit it first, then run --restore again.", "EasyFW", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return 1;
            }

            var exitCode = 1;
            FirewallService service = null;
            using var label = new Label { Dock = DockStyle.Fill, TextAlign = System.Drawing.ContentAlignment.MiddleCenter, Text = "Restoring Windows Firewall..." };
            using var form = new Form
            {
                Text = "EasyFW - restoring", ClientSize = new System.Drawing.Size(460, 90), FormBorderStyle = FormBorderStyle.FixedDialog,
                StartPosition = FormStartPosition.CenterScreen, ControlBox = false
            };
            using var timer = new System.Windows.Forms.Timer { Interval = 500 };
            form.Controls.Add(label);
            timer.Tick += (_, __) =>
            {
                var activity = service?.Activity;
                if (activity != null) label.Text = activity + ". This can take a couple of minutes.";
            };
            form.Shown += async (_, __) =>
            {
                timer.Start();
                try
                {
                    var store = new ConfigStore(Path.Combine(ConfigStore.DefaultFolder, "config.json"), false);
                    service = new FirewallService(store, new WindowsFirewallBackend(), RunMode.Live);
                    await service.DisableAsync();
                    timer.Stop();
                    MessageBox.Show(form, "Windows Firewall is back to how it was before EasyFW.", "EasyFW");
                    exitCode = 0;
                }
                catch (Exception ex)
                {
                    timer.Stop();
                    Log.Write("Restore failed: " + ex);
                    MessageBox.Show(form, "Restore failed: " + ex.Message, "EasyFW", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                form.Close();
            };
            Application.Run(form);
            ReleaseSingleInstance();
            return exitCode;
        }

        private static void ReportFatal(Exception ex)
        {
            Log.Write("Unhandled: " + ex);
            MessageBox.Show("Unexpected error: " + ex?.Message, "EasyFW", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
