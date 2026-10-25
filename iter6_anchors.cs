// ============================================================================
// Iter6Anchors.cs - CI arithmetic anchors for the ITER-6 research constants
// (DP formal audit + spill contention capacity boundary).  Same contract as
// LR2021Selftest: re-derive the closed-form numbers the research prose
// quotes and assert them, so a drifted constant fails CI.  All values are
// pure arithmetic - no Monte Carlo, no numpy.  Exit 0 = all anchors hold.
// License: MIT (AegisMesh validation fixture).
// ============================================================================

using System;

namespace AegisMesh.Validation
{
    public static class Iter6Anchors
    {
        private static void Assert(bool cond, string what)
        {
            if (!cond)
            {
                Console.WriteLine("FAIL: " + what);
                Environment.Exit(1);
            }
            Console.WriteLine("ok: " + what);
        }

        private static void AssertNear(double a, double b, string what,
                                       double tol = 1e-9)
        {
            Assert(Math.Abs(a - b) <= tol, what + " (" + a + " vs " + b + ")");
        }

        public static int Main()
        {
            // ---- 1) HW-008 window-capacity arithmetic (spill contention) --
            double capStep = 16 * 128 * 20.0 / 2.048;   // B per 20 s step
            AssertNear(capStep, 20000.0, "16-frame cap = 20000 B/step");
            AssertNear(16 * 128 / 2.048, 1000.0, "R_sync = 1000 B/s");

            // ---- 2) RT-007 epsilon arithmetic (DP audit) -------------------
            double epsPub = 1.0 / 4.0;                  // b = 4, Delta = 1
            AssertNear(epsPub, 0.25, "epsilon per publication = 0.25");
            AssertNear(36 * epsPub, 9.0, "basic composition k=2 (m=36) = 9.0");
            AssertNear(72 * epsPub, 18.0, "basic composition k=1 (m=72)");
            AssertNear(18 * epsPub, 4.5, "basic composition k=4 (m=18)");

            // Advanced composition (Dwork-Roth Thm 3.20), delta = 1e-6:
            // eps_adv = sqrt(2 m ln(1/delta)) eps + m eps (e^eps - 1)
            double delta = 1e-6;
            Func<double, double> adv = m =>
                Math.Sqrt(2 * m * Math.Log(1.0 / delta)) * epsPub
                + m * epsPub * (Math.Exp(epsPub) - 1.0);
            AssertNear(adv(72), 16.26322406692886,
                       "advanced composition m=72 (tighter than basic)");
            AssertNear(adv(36), 10.44101140482507,
                       "advanced composition m=36");
            Assert(adv(36) > 36 * epsPub,
                   "k=2: basic 9.0 remains the tighter bound (pure DP)");
            Assert(adv(72) < 72 * epsPub,
                   "k=1: advanced 16.26 < basic 18.0");

            // ---- 3) Rounding-aware false-flag table (RT-007 refinement) ----
            // P(round(c + Lap(0,b)) >= theta) = 0.5 e^{-(theta-0.5-c)/b}
            // (the noised count is ROUNDED - ITER-5's closed-form table used
            //  the unrounded tail; the MC was rounding-aware)
            Func<double, double, double> pRound = (th, c) =>
                0.5 * Math.Exp(-(th - 0.5 - c) / 4.0);
            AssertNear(pRound(16, 10), 0.12641979790237323,
                       "p(round >= 16 | c = 10)");
            AssertNear(pRound(12, 10), 0.3436446393954861,
                       "p(round >= 12 | c = 10)");
            // 2-of-3 published window: 3p^2(1-p) + p^3
            Func<double, double> win = p => 3 * p * p * (1 - p) + p * p * p;
            AssertNear(win(pRound(16, 10)), 0.04390502225798921,
                       "theta=16, c=10 window prob (0.0439/h at k=1)");
            AssertNear(win(pRound(12, 10)), 0.2731117977161736,
                       "theta=12, c=10 window prob (0.2731/h at k=1)");
            Assert(win(pRound(12, 10)) / win(pRound(16, 10)) > 5.0,
                   "theta 12 -> 16 cuts the c=10 false-flag rate > 5x");

            // ---- 4) Suppression (c_min = 8) closed forms -------------------
            // empty venue (c = 0): emission = P(round(0 + Lap) >= 8)
            AssertNear(0.5 * Math.Exp(-7.5 / 4.0), 0.07667748342246423,
                       "empty-venue emission frac = 0.0767 (measured 0.0767)");
            Assert(8 < 16,
                   "c_min=8 < theta=16: above-theta slots never suppressed");

            // ---- 5) A1 memoization theory anchors --------------------------
            AssertNear(Math.Sqrt(2 * 16), 5.656854249492381,
                       "persistent-noise per-bucket RMSE = sqrt(2) b");
            AssertNear(Math.Sqrt(2.0 * 16 / 146), 0.4681645887845222,
                       "fresh-noise averaged RMSE at 146 beacons");

            // ---- 6) Spill capacity boundary arithmetic ---------------------
            // degraded scenario: ~42 % of 300 pendants disconnected
            double aggWorst = 300 * 0.42 * 44.8;        // B/s demand
            double aggOwn = 300 * 0.42 * 6.4;
            AssertNear(aggWorst / 6000.0, 0.9407999999999999,
                       "worst-case aggregate demand = 94.1 % of 6 kB/s");
            AssertNear(aggOwn / 6000.0, 0.13440000000000002,
                       "own-traffic aggregate demand = 13.4 % of 6 kB/s");

            Console.WriteLine("iter6 anchors: ALL PASS");
            return 0;
        }
    }
}
