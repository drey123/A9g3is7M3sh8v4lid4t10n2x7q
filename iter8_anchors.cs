// ============================================================================
// Iter8Anchors.cs - CI arithmetic anchors for the ITER-8 research constants
// (conditional-binary spray policy: hybrid discipline rates + own-send
// admission shaping + egress-split load-balance bounds).  Same contract as
// Iter6/Iter7Anchors: re-derive the closed-form numbers the research prose
// quotes and assert them, so a drifted constant fails CI.  All values are
// pure arithmetic - no Monte Carlo, no trace statistics (those live in
// results_iter8.json and are deliberately kept out of this gate, per the
// no-silent-correction rule established in ITER-7).  Exit 0 = pass.
// License: MIT (AegisMesh validation fixture).
// ============================================================================

using System;

namespace AegisMesh.Validation
{
    public static class Iter8Anchors
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

        // Per-node journal accrual (B/s) under a spray policy, zero
        // in-island contacts (the closed-form kernel the DES composes with
        // measured contact terms):
        //   ceiling(m) = lam x 128 x min(L, m)                 [binary]
        //   plain(m)   = lam x 128                             [contacts = 0]
        //   hybrid     = ceiling if m <= m* else plain
        //   hshape     = hybrid, with the plain branch at min(lam, lam_cap)
        public static double HybridRate(int m, double lam, int mStar,
                                        double lamCap = 0.05,
                                        bool shape = false)
        {
            const int L = 6; const double msgB = 128.0;
            if (m <= mStar) return lam * msgB * Math.Min(L, m);
            double lamPlain = shape ? Math.Min(lam, lamCap) : lam;
            return lamPlain * msgB;   // zero-contact kernel
        }

        public static int Main()
        {
            const double lam = 0.05;        // msg/s own send rate (ITER-3)
            const double lamHi = 0.1;       // the chatty-user corner (HW-011)
            const double msgB = 128.0;
            const int L = 6;                // Spray-and-Wait copy budget
            const int mStar = 5;            // hybrid island-size threshold
            const double lamCap = 0.05;     // admission shaping cap
            const double aggCap = 6000.0;   // B/s aggregate sync capacity

            // ---- 1) Hybrid policy rate kernel (m* = 5) ----------------
            // Small islands run BINARY (ceiling rates); large islands run
            // PLAIN (contact-limited kernel; measured contacts add on top
            // in the DES, not here).
            AssertNear(HybridRate(1, lam, mStar), 6.4,
                       "hybrid m=1: ceiling 6.4 B/s (binary in small island)");
            AssertNear(HybridRate(3, lam, mStar), 19.2,
                       "hybrid m=3: ceiling 19.2 B/s");
            AssertNear(HybridRate(5, lam, mStar), 32.0,
                       "hybrid m=5: ceiling 32.0 B/s (m* boundary)");
            AssertNear(HybridRate(6, lam, mStar), 6.4,
                       "hybrid m=6 > m*: plain kernel 6.4 B/s (zero-contact)");
            AssertNear(HybridRate(12, lam, mStar), 6.4,
                       "hybrid m=12: plain kernel (contact-limited regime)");

            // ---- 2) Shaping identity (HW-011's named rule, now exact) --
            // In large islands the own-send rate is capped at lam_cap;
            // small islands keep the user's true rate.
            AssertNear(HybridRate(6, lamHi, mStar, lamCap, shape: true), 6.4,
                       "hshape m=6 @ lam 0.1: plain branch capped to 0.05");
            AssertNear(HybridRate(5, lamHi, mStar, lamCap, shape: true),
                       lamHi * msgB * 5.0,
                       "hshape m=5 @ lam 0.1: small island keeps true rate");
            Assert(HybridRate(6, lamHi, mStar, lamCap, shape: true)
                   < HybridRate(6, lamHi, mStar),
                   "shaping strictly reduces large-island kernel at lam 0.1");

            // ---- 3) Pointwise domination: hybrid <= all-binary ceiling -
            // The conditional policy can never exceed the unconditioned
            // binary accrual it replaces (the saturation corner is bounded
            // by construction, not by measurement).
            foreach (int m in new int[] { 1, 2, 3, 4, 5, 6, 7, 8, 12, 40 })
            {
                double ceilHi = lamHi * msgB * Math.Min(L, m);
                Assert(HybridRate(m, lamHi, mStar) <= ceilHi + 1e-12,
                       "hybrid(m=" + m + ") @ 0.1 <= ceiling " + ceilHi);
                Assert(HybridRate(m, lamHi, mStar, lamCap, shape: true)
                       <= ceilHi + 1e-12,
                       "hshape(m=" + m + ") @ 0.1 <= ceiling " + ceilHi);
            }

            // ---- 4) The saturating corner is capped below capacity at
            //         the kernel level: worst per-node hybrid kernel
            //         @ lam 0.1 is the m=5 ceiling 64.0 B/s; the all-binary
            //         kernel is 76.8 B/s (m >= 6).  Ratio 5/6 per node.
            AssertNear(HybridRate(5, lamHi, mStar), 64.0,
                       "hybrid worst kernel @ 0.1 = 64.0 B/s (m = m*)");
            AssertNear(lamHi * msgB * (double)L, 76.8,
                       "all-binary kernel @ 0.1 = 76.8 B/s (m >= L)");
            Assert(HybridRate(5, lamHi, mStar) < lamHi * msgB * L,
                   "hybrid removes the m >= L 38.4 B/s (0.05-scale) tier");

            // ---- 5) Egress-split load-balance bounds (ITER-7 #6) ------
            // K backlogged peers, t touched repeaters, least-loaded
            // assignment: max load per repeater is bounded by
            // ceil(K/t) and every touched repeater gets >= floor(K/t).
            Func<int, int, int> ceilDiv = (a, b) => (a + b - 1) / b;
            AssertNear(ceilDiv(9, 1), 9, "t=1 degenerates to single egress");
            AssertNear(ceilDiv(9, 2), 5, "K=9, t=2: max load 5");
            AssertNear(ceilDiv(9, 3), 3, "K=9, t=3: max load 3");
            Assert(ceilDiv(9, 3) <= ceilDiv(9, 2) && ceilDiv(9, 2) <= 9,
                   "more touched repeaters never increases max load");
            // Demand-side identity: aggregate demand is INVARIANT under
            // re-assignment (only per-repeater K divides) - the saturated
            // regime (94.1 % of aggregate, ITER-6) cannot be fixed by
            // splitting, only the sparse-regime tails can.
            AssertNear(6000.0 / aggCap, 1.0,
                       "aggregate sync capacity = 6 x 1000 B/s (carried)");

            Console.WriteLine("Iter8Anchors: all anchors PASS");
            return 0;
        }
    }
}
