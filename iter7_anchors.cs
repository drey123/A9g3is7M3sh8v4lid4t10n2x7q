// ============================================================================
// Iter7Anchors.cs - CI arithmetic anchors for the ITER-7 research constants
// (island journal-accrual custody model: the 7x spill-plane unknown
// decomposed into contact-limited and custody-ceiling regimes).  Same
// contract as Iter6Anchors: re-derive the closed-form numbers the research
// prose quotes and assert them, so a drifted constant fails CI.  All
// values are pure arithmetic - no Monte Carlo, no numpy.  Exit 0 = pass.
// License: MIT (AegisMesh validation fixture).
// ============================================================================

using System;

namespace AegisMesh.Validation
{
    public static class Iter7Anchors
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
            const double lam = 0.05;        // msg/s own send rate (ITER-3)
            const double msgB = 128.0;      // B per journaled message
            const int L = 6;                // Spray-and-Wait copy budget

            // ---- 1) Custody ceiling a(m) = lam x 128 x min(L, m) --------
            Func<int, double> ceiling = m => lam * msgB * Math.Min(L, m);
            AssertNear(ceiling(1), 6.4, "a(1) = own traffic only = 6.4 B/s");
            AssertNear(ceiling(2), 12.8, "a(2) = 12.8 B/s");
            AssertNear(ceiling(3), 19.2, "a(3) = 19.2 B/s");
            AssertNear(ceiling(4), 25.6, "a(4) = 25.6 B/s");
            AssertNear(ceiling(5), 32.0, "a(5) = 32.0 B/s");
            AssertNear(ceiling(6), 38.4, "a(6) = custody ceiling 38.4 B/s");
            AssertNear(ceiling(8), 38.4,
                       "a(8) = ceiling (min(L,m) saturates at L)");
            AssertNear(ceiling(8) / ceiling(1), 6.0,
                       "ceiling = 6x own traffic (the spray budget, not 7)");

            // ---- 2) The island ceiling is BELOW the connected-relay
            //         bound (44.8 B/s = 6.4 x 7): unreachable in islands -
            double worst = 6.4 * 7.0;
            AssertNear(worst, 44.8, "connected-relay bound = 44.8 B/s");
            Assert(ceiling(8) < worst,
                   "island custody ceiling 38.4 < 44.8 connected-relay bound");
            AssertNear(ceiling(8) / worst, 6.0 / 7.0,
                       "ceiling / worst bound = 6/7 = 0.857142857...");

            // ---- 3) Plain-spray contact-limited accrual -----------------
            // per-node any-contact rate at the measured degraded median
            // ICT-any 196 s: received-copy rate <= 1 msg per contact ->
            // a_plain = lam x 128 + 128/196  (size-independent)
            double aPlain = lam * msgB + msgB / 196.0;
            AssertNear(aPlain, 7.053061224489796,
                       "a_plain = 6.4 + 128/196 = 7.053 B/s");
            Assert(aPlain < ceiling(2),
                   "plain-spray accrual < custody ceiling already at m=2");
            AssertNear(aPlain / 6.4, 1.1020408163265306,
                       "plain accrual = 1.102x own traffic (not 7x)");

            // ---- 4) HW-010 utilization-guard boundary (uniform accrual) -
            // guard fires when D x a > 0.5 x 6000 = 3000 B/s
            double guardB = 0.5 * 6 * (16 * msgB / 2.048);
            AssertNear(guardB, 3000.0, "guard threshold = 3000 B/s");
            double dPlain = 3000.0 / aPlain;
            AssertNear(dPlain, 425.34722222222223,
                       "plain-spray guard needs > 425 disconnected nodes");
            double dCeil = 3000.0 / ceiling(8);
            AssertNear(dCeil, 78.125,
                       "ceiling accrual guard needs > 78 disconnected");
            // NOTE (ITER-7 trace-resolved correction): the uniform-arithmetic
            // boundary above is a FLOOR, not a firing prediction.  Islands
            // form in dense venues where the measured in-island contact rate
            // (~0.945 new edges/node/20 s in the degraded trace set) is
            // ~9x the population-median ICT-any, so the trace-resolved
            // plain-mode demand reaches the 3000 B/s threshold in 7.5 % of
            // degraded-set steps at lam=0.05 (census, results_iter7.json).
            // Firing fractions are trace-derived statistics and stay in the
            // Python results, not in this closed-form gate.
            // ---- 5) Received-copy conservation cap ----------------------
            // per-node received rate <= lam x (min(L,m)-1) msgs/s (credit
            // supply), also <= contact rate; at the measured island contact
            // rate 0.945/20 s and m >= 6 the contact side binds:
            double cIsland = 0.945 / 20.0;          // measured contacts/s
            double recvTrace = Math.Min(cIsland, lam * (L - 1.0));
            AssertNear(recvTrace, 0.04725,
                       "trace-island received rate = min(0.04725, 0.25) = 0.04725 msg/s");
            double aPlainTrace = lam * msgB + recvTrace * msgB;
            AssertNear(aPlainTrace, 12.448,
                       "trace-resolved plain accrual = 6.4 + 6.048 = 12.448 B/s");

            Console.WriteLine("iter7 anchors: ALL PASS");
            return 0;
        }
    }
}
