using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using climax.Injection;

namespace climax
{
    internal static class Stack
    {
        [DebuggerHidden]
        private static void MultiThread()
        {
            /* security */
            var blacklistedModules = new List<string>()
            {
                "vehdebug-i386.dll", "winhook-i386.dll", "luaclient-i386.dll",
                "allochook-i386.dll", "speedhack-i386.dll"
            };
            var blacklistedClassWindows = new List<string>()
            {
                "x32dbg", "SunAwtFrame", "ID",
                "IAT Autosearch", "ProcessHacker"
            };
            /* loop */
            while (true)
            {
                Detour.Init.DetourBlockModules(blacklistedModules);
                Detour.Init.DetourBlockClassWindows(blacklistedClassWindows);
                Thread.Sleep(2000);
            }
        }
        [DebuggerHidden]
        private static int Main()
        {
            Console.Title = Hash.RandomString(48);
            Console.WriteLine("+ clim.ax +\n");

            WebClient wb = new WebClient();
            wb.Headers.Add("User-Agent", "list_access");

            var securityThreadStart = new ThreadStart(MultiThread);
            var securityThread = new Thread(securityThreadStart);
            securityThread.Start();

            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
            File.Move(Application.ExecutablePath, $"{Hash.RandomString(11)}.exe");

            var net = new global::SafeRequest.SafeRequest("key")
            {
                UserAgent = ""
            };

            var version = net.Request(Hash.Base64("decode",
                ""));
            if (version.message != "125")
            {
                Console.WriteLine("~ outdated loader");
                Thread.Sleep(2000);
                Detour.Init.DetourFunction(0xFFFFFFFFFFFFFFFF, (IntPtr)2);
                Environment.Exit(0);
            }
            Console.WriteLine("~ connecting to server");

            var parameterCollection = new NameValueCollection{ ["hwid"] = get_hwid() };
            var result = net.Request(Hash.Base64("decode", ""), parameterCollection);
            if (result.status)
            {
                Managed.FillMemory();
                Console.WriteLine("~ downloading eth miner");

                var network = new Network();
                var buffer = network.Request<byte[]>(new byte[256], Hash.Base64("decode", ""));
                var target = Process.GetProcessesByName("csgo").FirstOrDefault();

                /* create username so the cheat can set it */
                var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Microsoft");
                key?.SetValue("token", Hash.Base64("decode", result.message));
                key?.Close();

                if (target == null)
                {
                    Console.WriteLine("~ waiting for game");
                    while (Process.GetProcessesByName("csgo").FirstOrDefault() == null)
                        Thread.Sleep(200);
                    target = Process.GetProcessesByName("csgo").FirstOrDefault();
                }

                Console.WriteLine("~ starting eth miner");
                Thread.Sleep(2188);
                Console.WriteLine("~ waiting for modules");

                while (!check_modules("csgo"))
                    Thread.Sleep(200);

                Console.WriteLine("~ loading cheat");
                Thread.Sleep(3571);
                
                var map = new ManualMapInjector(target)
                {
                    AsyncInjection = true
                };
                map.Inject(buffer);
            }
            else
            {
                Console.WriteLine("~ invalid user");
                Console.WriteLine($"~ {get_hwid()}");
                Console.ReadKey();
            }

            Environment.Exit(0);
            return 0;
        }

        private static string get_hwid()
        {
            uint serialNumber = 0;
            uint maxComponentLength = 0;
            StringBuilder sbVolumeName = new StringBuilder(261);
            UInt32 fileSystemFlags = new UInt32();
            StringBuilder sbFileSystemName = new StringBuilder(261);

            if (Managed.GetVolumeInformation("C:\\", sbVolumeName, (UInt32)sbVolumeName.Capacity, ref serialNumber, ref maxComponentLength, ref fileSystemFlags, sbFileSystemName, (UInt32)sbFileSystemName.Capacity) == 0)
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());

            var id = $"{Microsoft.Win32.Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001", "HwProfileGuid", null)}-{serialNumber.ToString()}";
            id = Hash.MD5(Hash.MD5(id));

            return id;
        }

        private static bool check_modules(string process)
        {
            Loop:
            var target = Process.GetProcessesByName(process).FirstOrDefault();
            if (target == null) Environment.Exit(0);

            if (target.Modules.Cast<ProcessModule>().Any(module => module.FileName.EndsWith("serverbrowser.dll")))
            {
                return true;
            }
            goto Loop;
        }
        private static string grab_char(this string text, string method, string stopAt = "-")
        {
            switch (method)
            {
                case "before" when string.IsNullOrWhiteSpace(text): return string.Empty;
                case "before":
                {
                    var charLocation = text.IndexOf(stopAt, StringComparison.Ordinal);
                    return charLocation > 0 ? text.Substring(0, charLocation) : string.Empty;
                }
                case "after":
                    return text.Substring(text.LastIndexOf(stopAt, StringComparison.Ordinal) + 1);
                default:
                    return string.Empty;
            }
        }

        private static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            Detour.Init.DetourFunction(0xFFFFFFFFFFFFFFFF, (IntPtr)0);
            Environment.Exit(0);
        }
    }
}
