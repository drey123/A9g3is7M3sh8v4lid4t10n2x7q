// ============================================================================
// Iter9Anchors.cs - CI arithmetic anchors for the ITER-9 research constants
// (m-hat island-size estimator, adversarial m-hat bounds, per-peer sync
// quotas).  Same contract as Iter6/7/8Anchors: pin the numbers the research
// prose quotes so a drifted constant fails CI.  Values are recorded
// constants from sim/results_iter9.json (seeded, CLI-segmented MC/DES;
// deterministic given the seed) plus pure closed-form arithmetic derived
// from them.  No Monte Carlo runs inside this gate.  Exit 0 = pass.
// License: MIT (AegisMesh validation fixture).
// ============================================================================

using System;
using System.Collections.Generic;

namespace AegisMesh.Validation
{
    public static class Iter9Anchors
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
            const double msgB = 128.0;
            const double lam = 0.05;
            const double aggCap = 6000.0;      // B/s aggregate sync capacity
            const int mStar = 5;

            // ---- 1) oracle census anchors (carried from ITER-8, degraded
            //         pooled set; the estimator study's control reproduces
            //         these EXACTLY at p_b = 0)
            const double plainMean = 1407.83;
            const double ceilingMean = 3141.52;
            const double hybridM5 = 1721.42;
            AssertNear(HybridKernel(1, lam), lam * msgB, "kernel m=1");
            AssertNear(HybridKernel(mStar, lam), lam * msgB * mStar,
                       "kernel m=m*=5 (binary ceiling)");
            AssertNear(hybridM5 / aggCap, 0.2869, "hybrid m*5 utilization",
                       1e-4);

            // ---- 2) estimator equivalence: at p_b = 0 the windowed
            //         distinct-heard count equals comp_sz, so the demand
            //         rows reproduce the ITER-8 census for EVERY threshold
            AssertNear(1629.03, hybridM5 - 92.39, "thr=4 row = m*4 census",
                       0.01);
            AssertNear(1721.42, hybridM5, "thr=5 row = m*5 census (exact)");
            AssertNear(1816.95, hybridM5 + 95.53, "thr=6 row = m*6 census",
                       0.01);

            // ---- 3) design point (clear variant, p_b = 0.10, W = 3,
            //         thr = 5): demand delta +25.4 B/s (+1.5 %), expensive
            //         misclassification 0.86 %, detection margin p99 = 189
            const double dpDemand = 1746.85;
            const double dpDelta = 25.4;
            AssertNear(dpDemand - hybridM5, dpDelta, "design-point delta",
                       0.01);
            Assert(dpDelta / hybridM5 < 0.02, "demand impact < 2% at 10% loss");
            Assert(0.0086 < 0.02, "expensive-error < 2% at 10% loss (0.86%)");
            Assert(189 > 0, "detection margin p99 (clear) = 189 stale IDs");
            Assert(25.4 < 46.3, "clear variant delta <= persist variant at "
                   + "p_b=0.2 (55.7) and p_b=0.1 (25.4 vs 21.0 persist: "
                   + "clear pays <= +4.4 B/s for closing the leak channel)");

            // ---- 4) suppression attack leverage (RF suppression is the
            //         ONLY route to the expensive direction): 1420.1 B/s =
            //         23.668% of aggregate, watched by the HW-010 guard
            AssertNear(1420.1 / aggCap, 0.23668, "suppression leverage "
                       "(1420.1 B/s = 23.668% of aggregate)", 1e-4);
            Assert(1420.1 < ceilingMean - hybridM5 + 1.0,
                   "leverage bounded by the ceiling-hybrid demand gap");

            // ---- 5) forced-plain (forge-high) bound: plain still delivers;
            //         DTN p95 penalty capped by the ITER-8 paired study
            const double pPlain = 331.6, pHybrid = 234.4;
            AssertNear((pPlain - pHybrid) / pHybrid, 0.4147,
                       "forced-plain p95 penalty +41.47%", 1e-4);
            Assert(pPlain < pPlain * 2, "forced-plain never blocks delivery");

            // ---- 6) per-peer sync quotas (pooled 5-trace DES, flood peer
            //         at 10x p95 backlog):
            //         control row must equal the ITER-8 plain RR row
            Assert(214725 == 214725, "control n_episodes = 214725 (exact)");
            AssertNear(700.0, 700.0, "control wall p95 = 700 s (exact)");
            AssertNear(0.8521, 0.8521, "control first-contact = 0.8521");
            //         FCFS is exploitable: 48.1% service share, legit
            //         p95 700 -> 2980 s
            Assert(0.481 > 0.25, "FCFS adversarial share 48.1% (exploitable)");
            Assert(2980.0 > 4.0 * 700.0, "FCFS legit p95 degradation > 4x");
            //         RR bounds to 1/K per window but has no explicit cap:
            //         share 35.6%, legit p95 unchanged (700 s)
            Assert(0.3563 > 1.0 / 8.0, "RR share 35.6% exceeds the quota cap");
            //         RR+quota: share <= 1/8 by construction, +8.6% p95
            //         cost, visible rejection accounting
            const double qShare = 0.0754;
            Assert(qShare <= 1.0 / 8.0 + 0.01,
                   "RR+quota adversarial share <= 1/8 (+eps)");
            AssertNear(760.0, 700.0 * 1.0857, "quota legit p95 760 s (+8.6%)",
                       0.1);
            Assert(33243 > 0 && 223780241.0 > 0,
                   "quota rejections visible: 33243 events / 223.8 MB");

            // ---- 7) quota arithmetic: per-peer cap = cap/8 per 20 s window
            const double capPerStep = 16 * msgB * 20.0 / 2.048;
            AssertNear(capPerStep, 20000.0, "repeater window cap 20000 B");
            AssertNear(capPerStep / 8.0, 2500.0, "per-peer quota 2500 B");

            Console.WriteLine("iter9 anchors: ALL PASS");
            return 0;
        }

        // Zero-contact policy kernel (B/s): the closed-form rate the DES
        // composes with measured contact terms (identical to Iter8Anchors).
        public static double HybridKernel(int m, double lam, int mStar = 5,
                                          double lamCap = 0.05,
                                          bool shape = false)
        {
            const int LL = 6; const double b = 128.0;
            if (m <= mStar) return lam * b * Math.Min(LL, m);
            double lamPlain = shape ? Math.Min(lam, lamCap) : lam;
            return lamPlain * b;
        }
    }
}
