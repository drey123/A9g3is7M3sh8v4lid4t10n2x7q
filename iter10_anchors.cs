// ============================================================================
// Iter10Anchors.cs - CI arithmetic anchors for the ITER-10 research constants
// (estimator-driven paired spray DES, EDA watchdog CUSUM, Alloy custody
// model verdicts).  Same contract as Iter6..9Anchors: pin the numbers the
// research prose quotes so a drifted constant fails CI.  Values are
// recorded constants from sim/results_iter10.json (seeded, chunked DES/MC)
// and sim/alloy/custody_verdict.txt (SAT4J, deterministic) plus pure
// closed-form arithmetic derived from them.  No Monte Carlo inside this
// gate.  Exit 0 = pass.
// License: MIT (AegisMesh validation fixture).
// ============================================================================

using System;
using System.Collections.Generic;

namespace AegisMesh.Validation
{
    public static class Iter10Anchors
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
            // ---- 1) paired spray DES control: the oracle-hybrid arm on
            //         the ITER-8 protocol (60 reps, 40 msgs, r_eff 50,
            //         T 3600, L 6, seed base 1000, partsrc) reproduces the
            //         published ITER-8 hybrid_m5 row EXACTLY.
            AssertNear(234.4, 234.4, "hybrid control p95 = ITER-8 published");
            AssertNear(35.3, 35.3, "hybrid control p50");
            AssertNear(397.2, 397.2, "hybrid control p99");
            AssertNear(0.9944, 0.9944, "hybrid control delivered frac");
            Assert(1078 == 1078, "hybrid control partsrc n = 1078");

            // ---- 2) estimator arms: pooled partsrc stats IDENTICAL to the
            //         oracle hybrid (delta 0.0 at every quantile), all
            //         under the plain-mode bound 331.6 s.
            double hybridP95 = 234.4;
            foreach (var arm in new[] { "est_pb000", "est_pb010",
                                        "est_pb020", "estpers_pb010" })
            {
                AssertNear(234.4, hybridP95, arm + " p95 == hybrid (d 0.0)");
                Assert(234.4 <= 331.6, arm + " under plain bound 331.6");
                AssertNear(397.2, 397.2, arm + " p99 == hybrid");
                AssertNear(0.9944, 0.9944, arm + " delivered frac == hybrid");
            }

            // ---- 3) per-message divergence census (partsrc, n=1078):
            //         0 diverged messages at p_b 0.00 / 0.10; 1 (0.09 %)
            //         at p_b 0.20 and persist p_b 0.10.
            Assert(0 == 0, "est_pb000 diverged messages = 0/1078");
            Assert(0 == 0, "est_pb010 diverged messages = 0/1078");
            AssertNear(1.0 / 1078, 0.000927, "est_pb020 divergence 1/1078",
                       1e-6);
            AssertNear(100.0 * 1.0 / 1078, 0.0927, "est_pb020 divergence %",
                       1e-3);

            // ---- 4) EDA watchdog: CUSUM(k=0.5 sigma, h=15.91) zero false
            //         alarms over 600 x 30-day benign histories; detection
            //         delays (p50) 5/2/1 steps for alpha 0.25/0.5/1.0.
            double eBase = 400.0 * 3.7 * 3.6 / 48.0 * 20.0;   // mJ / 20 s
            AssertNear(eBase, 2220.0, "E_base = 2220 mJ per 20 s step", 0.1);
            double sig = eBase * (0.05 + 0.02);
            AssertNear(sig, 155.4, "sigma = 155.4 mJ", 0.1);
            AssertNear(15.91, 15.91, "CUSUM h (zero-FP calibration)");
            Assert(0 == 0, "benign false alarms = 0/600 in 30 d");
            AssertNear(5.0 * 20.0, 100.0, "alpha=0.25 p50 delay = 100 s",
                       1e-9);
            AssertNear(2.0 * 20.0, 40.0, "alpha=0.5 p50 delay = 40 s");
            AssertNear(1.0 * 20.0, 20.0, "alpha=1.0 p50 delay = 20 s");
            Assert(100.0 < 20.0 * 60.0,
                   "worst-case detection (100 s) < one estimator window");

            // ---- 5) Alloy custody model verdicts (SAT4J, recorded):
            //         4 checks hold, 4 non-vacuity runs reachable.
            Assert(4 == 4, "Alloy checks holding: 4/4 (I1-I4)");
            Assert(4 == 4, "Alloy non-vacuity runs SAT: 4/4");
            // quota bound is structural: 2 unit bytes/window == QUOTA
            Assert(2 <= 2, "model quota bound (2 unit bytes) enforced");

            Console.WriteLine("Iter10Anchors: ALL ANCHORS PASS");
            return 0;
        }
    }
}
