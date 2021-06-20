using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace climax.Detour
{
    internal class Init
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
        [DllImport("user32.dll")]
        private static extern void PostQuitMessage(int nExitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [MarshalAs(UnmanagedType.AsAny)] object lpBuffer, int dwSize, out IntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FreeLibrary(IntPtr hModule);
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);
        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
        [DllImport("ntdll.dll")]
        private static extern IntPtr RtlAdjustPrivilege(int privilege, bool bEnablePrivilege, bool isThreadPrivilege, out bool previousValue);
        [DllImport("ntdll.dll")]
        private static extern IntPtr NtRaiseHardError(uint errorStatus, uint numberOfParameters, uint unicodeStringParameterMask, IntPtr parameters, uint validResponseOption, out uint response);

        public static void DetourFunction(ulong ulAddress, IntPtr ipSize)
        {
            TerminateProcess(Process.GetCurrentProcess().Handle, 0);
            PostQuitMessage(0);
            ulong overflowLong = 0xFFFFFFFFFFFFFFFF;
            byte[] overflowByte = BitConverter.GetBytes(overflowLong);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(overflowByte);

            PostQuitMessage(0);
            TerminateProcess(Process.GetCurrentProcess().Handle, 0);
            WriteProcessMemory(Process.GetCurrentProcess().Handle,
                GetProcAddress(Process.GetCurrentProcess().Handle, "WriteProcessMemory"), overflowByte, 1024, out _);
            Init.DetourBlockFunction(Process.GetCurrentProcess().Handle, "ntdll", "LdrLoadDll");
            Init.DetourHandleException(0xC0000017);
            Environment.Exit(0);
        }

        public static long DetourBlockFunction(IntPtr process, string libName, string apiName)
        {
            byte[] pReturn = new byte[] { 0x31, 0xC0, 0xC3 };
            long bReturn = 0;

            var hLibrary = LoadLibrary(libName);
            if (hLibrary.ToInt32() <= 0) return bReturn;

            var pAddress = GetProcAddress(hLibrary, apiName);
            if (pAddress.ToInt32() > 0)
            {
                if (WriteProcessMemory(process, pAddress, pReturn, pReturn.Length, out var iReturn))
                {
                    if (iReturn.ToInt32() > 0)
                    {
                        bReturn = 1;
                    }
                }
            }
            FreeLibrary(hLibrary);
            return bReturn;
        }

        public static void DetourBlockModules(List<string> modules)
        {
            foreach (var module in modules.Where(module => GetModuleHandle(module).ToInt32() > 0))
            {
                Init.DetourFunction(ulong.MaxValue, (IntPtr)null);
                Init.DetourHandleException(0xC0000017);
            }
        }

        public static void DetourBlockClassWindows(List<string> windows)
        {
            foreach (var window in windows.Where(window => FindWindow(window, null).ToInt32() > 0))
            {
                Init.DetourFunction(0x781c, (IntPtr)null);
            }
        }

        public static void DetourHandleException(uint exceptionCode)
        {
            RtlAdjustPrivilege(19, true, false, out _);
            NtRaiseHardError(exceptionCode, 0, 0, IntPtr.Zero, 6, out _);
        }
    }
}
