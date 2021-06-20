using System;
using System.Runtime.InteropServices;
using System.Text;

namespace climax
{
    class Managed
    {
        [DllImport("kernel32.dll")]
        private static extern IntPtr ZeroMemory(IntPtr addr, IntPtr size);

        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualProtect(IntPtr lpAddress, IntPtr dwSize, IntPtr flNewProtect, ref IntPtr lpflOldProtect);
        [DllImport("kernel32.dll")]
        public static extern long GetVolumeInformation(string pathName, StringBuilder volumeNameBuffer, UInt32 volumeNameSize, ref UInt32 volumeSerialNumber, ref UInt32 maximumComponentLength, ref UInt32 fileSystemFlags, StringBuilder fileSystemNameBuffer, UInt32 fileSystemNameSize);
        private static void EraseSection(IntPtr address, int size)
        {
            IntPtr sz = (IntPtr)size;
            IntPtr dwOld = default;
            VirtualProtect(address, sz, (IntPtr)0x40, ref dwOld);
            ZeroMemory(address, sz);
            IntPtr temp = default;
            VirtualProtect(address, sz, dwOld, ref temp);
        }

        public static void FillMemory()
        {
            var process = System.Diagnostics.Process.GetCurrentProcess();
            if (process.MainModule == null) return;

            var baseAddress = process.MainModule.BaseAddress;
            var dwpeheader = Marshal.ReadInt32((IntPtr)(baseAddress.ToInt32() + 0x3C));
            var wnumberofsections = Marshal.ReadInt16((IntPtr)(baseAddress.ToInt32() + dwpeheader + 0x6));

            EraseSection(baseAddress, 30);

            foreach (var t in Peheaderdwords)
            {
                EraseSection((IntPtr)(baseAddress.ToInt32() + dwpeheader + t), 4);
            }

            foreach (var t in Peheaderwords)
            {
                EraseSection((IntPtr)(baseAddress.ToInt32() + dwpeheader + t), 2);
            }

            foreach (var t in Peheaderbytes)
            {
                EraseSection((IntPtr)(baseAddress.ToInt32() + dwpeheader + t), 1);
            }

            var x = 0;
            var y = 0;
            while (x <= wnumberofsections)
            {
                if (y == 0)
                {
                    EraseSection((IntPtr)((baseAddress.ToInt32() + dwpeheader + 0xFA + (0x28 * x)) + 0x20), 2);
                }

                EraseSection((IntPtr)((baseAddress.ToInt32() + dwpeheader + 0xFA + (0x28 * x)) + Sectiontabledwords[y]), 4);

                y++;

                if (y != Sectiontabledwords.Length) continue;
                x++;
                y = 0;
            }
        }

        private static readonly int[] Sectiontabledwords = new int[] { 0x8, 0xC, 0x10, 0x14, 0x18, 0x1C, 0x24 };
        private static readonly int[] Peheaderbytes = new int[] { 0x1A, 0x1B };
        private static readonly int[] Peheaderwords = new int[] { 0x4, 0x16, 0x18, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x5C, 0x5E };
        private static readonly int[] Peheaderdwords = new int[] { 0x0, 0x8, 0xC, 0x10, 0x16, 0x1C, 0x20, 0x28, 0x2C, 0x34, 0x3C, 0x4C, 0x50, 0x54, 0x58, 0x60, 0x64, 0x68, 0x6C, 0x70, 0x74, 0x104, 0x108, 0x10C, 0x110, 0x114, 0x11C };
    }
}

