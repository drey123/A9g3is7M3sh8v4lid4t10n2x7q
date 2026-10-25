// ============================================================================
// LR2021Selftest.cs - CI timing-anchor gate for the LR2021 C# model.
// Re-derives the MAC-timing anchors the research loop relies on and asserts
// them, so a drifted constant or a wedged abort path fails CI. Exit code 0
// = all anchors hold. License: MIT (AegisMesh validation fixture).
// ============================================================================

using System;

namespace AegisMesh.Validation
{
    public static class LR2021Selftest
    {
        private const double Tolerance = 1e-9;

        private static void Assert(bool cond, string what)
        {
            if (!cond)
            {
                Console.WriteLine("FAIL: " + what);
                Environment.Exit(1);
            }
            Console.WriteLine("ok: " + what);
        }

        private static void AssertNear(double a, double b, string what)
        {
            Assert(Math.Abs(a - b) <= Math.Max(1e-6, Math.Abs(b) * Tolerance),
                   what + " (" + a + " vs " + b + ")");
        }

        public static int Main()
        {
            var r = new LR2021();

            // 1) mode-transition timing anchors (datasheet-class, ML-002 path)
            r.Write(0x40030000, (byte)ChipMode.StandbyRC);
            AssertNear(r.VirtualUs, LR2021.TStandbyRcUs, "sleep->standby_rc");
            r.Write(0x40030000, (byte)ChipMode.StandbyXosc);
            AssertNear(r.VirtualUs, LR2021.TStandbyRcUs + LR2021.TStandbyXoscUs,
                       "standby_rc->standby_xosc");
            r.Write(0x40030000, (byte)ChipMode.Tx);
            AssertNear(r.VirtualUs,
                       LR2021.TStandbyRcUs + LR2021.TStandbyXoscUs
                       + LR2021.TTxToRxUs, "xosc->tx turnaround");

            // 2) US915 dwell guard (15.247): SF9/125 32 B = 263.17 ms passes,
            //    SF10/125 32 B = 485.38 ms is flagged (ITER-2 airtime table)
            r.Write(0x40030058, (byte)(263 / 2));      // 263.17 -> 131 LSB
            Assert(r.Read(0x40030058) >> 1 == 0, "263 ms frame passes dwell");
            r.Write(0x40030058, (byte)(485 / 2));      // 485.38 -> 242 LSB
            Assert((r.Read(0x40030058) & 0x02) != 0,
                   "485 ms frame flagged (dwell violation IRQ)");

            // 3) abort path: <= 100 us, clean FIFO over 1e5 legal cycles
            //    (ML-002); asserts are silent in the loop, one verdict after
            r.Reset();
            bool loopOk = true;
            double before = 0.0;
            for (int i = 0; i < 100000 && loopOk; i++)
            {
                r.Write(0x40030000, (byte)ChipMode.StandbyRC);
                r.Write(0x40030000, (byte)ChipMode.StandbyXosc);
                r.Write(0x40030000, (byte)ChipMode.Tx);
                before = r.VirtualUs;
                r.Write(0x40030050, 0x01);
                loopOk &= r.Mode == ChipMode.StandbyRC
                       && (r.VirtualUs - before)
                              <= LR2021.TAbortSettlingUs + 1e-9;
            }
            Assert(loopOk, "1e5 legal aborts: standby return, <= 100 us each");
            Assert(r.AbortCount == 100000, "abort counter = 1e5");
            Assert(!r.AbortWedgeFlag, "no wedge marker over 1e5 legal aborts");
            // the illegal-context hook: abort from Sleep is caught
            r.Reset();
            r.Write(0x40030050, 0x01);
            Assert(r.AbortWedgeFlag, "abort from Sleep sets the wedge hook");

            // 4) CAD duration scales with programmed symbols (LBT hook)
            r.Reset();
            r.Write(0x40030040, 8);
            AssertNear(r.CadDurationUs(), 8 * 1024.0, "CAD 8 symbols SF7/125");
            r.Write(0x40030040, 2);
            AssertNear(r.CadDurationUs(), 2 * 1024.0, "CAD 2 symbols SF7/125");

            Console.WriteLine("LR2021 selftest: all anchors hold");
            return 0;
        }
    }
}
