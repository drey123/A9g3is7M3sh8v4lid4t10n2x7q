// ============================================================================
// LR2021 peripheral model (C#) - AegisMesh firmware validation fixture
// ============================================================================
// Status: SKELETON WITH TIMING HOOKS. Graduates sim/renode/lr2021_peripheral.py
// (whose register map is the spec) toward the register-accurate Renode model
// called for by ITER-3 #13 / ITER-4 #6. Compiles against RenodeStubs.cs and
// is exercised by LR2021Selftest.cs in CI (compile + timing-anchor gate);
// semantic validation inside a full Renode checkout is the remaining step
// (owner environment; see research.md VAL-001/VAL-002).
//
// Modeled subset (MAC-timing claims only - MAC-002/004, ML-002, HW-007):
//   0x0000 OCDW      chip mode (sleep/standbyrc/standbyxosc/rx/tx)
//   0x0004 CFG       packet type (LoRa / FLRC)
//   0x0030 IRQMASK   interrupt mask
//   0x0034 IRQ       interrupt status (rxdone, txdone, cadDone, abortDone,
//                    timeout) - write-1-to-clear
//   0x0040 CADCFG    num CAD symbols
//   0x0044 RXTIMEOUT rx_max_time for CAD-RX / CAD-LBT (automated CAD with the
//                    host asleep - the feature that keeps the U5 out of the
//                    4 ms critical path)
//   0x0050 ABORT     write 1 = abort in-flight TX to standby (L1 pre-emption,
//                    ML-002: target <= 100 us, 1e5 clean cycles)
//   0x0054 ABORTSTAT abort counter (wedge instrumentation)
//   0x0058 TXAIRTIME accumulated on-air time of the last TX program (dwell
//                    guard: US915 15.247 400 ms)
//
// Timing constants are datasheet-class (LR2021 DS Rev 2.1 class) pending the
// rev-A abort bench (carried hardware item); the model's job is to make them
// machine-checkable, not to claim silicon accuracy.
//
// License: MIT (AegisMesh validation fixture - disposable, belongs in the
// public Actions repo per task.md "Firmware Validation Infrastructure").
// ============================================================================

namespace AegisMesh.Validation
{
    /// <summary>Chip modes modeled after the LR2021 operation modes.</summary>
    public enum ChipMode : byte
    {
        Sleep = 0,
        StandbyRC = 1,
        StandbyXosc = 2,
        Rx = 3,
        Tx = 4,
    }

    public enum PacketType : byte
    {
        LoRa = 0,
        Flrc = 1,
    }

    /// <summary>
    /// LR2021 register-level skeleton with virtual-time accounting for the
    /// mode-transition, CAD and abort timing hooks the MAC claims depend on.
    /// </summary>
    public class LR2021 : IBytePeripheral
    {
        // --- datasheet-class timing constants (us) -------------------------
        public const double TStandbyRcUs = 55.0;      // sleep -> STANDBY_RC
        public const double TStandbyXoscUs = 180.0;   // STANDBY_RC -> XOSC
        public const double TTxToRxUs = 250.0;        // turnaround
        public const double TAbortSettlingUs = 100.0; // ML-002 bench target
        public const double Us915DwellMaxMs = 400.0;  // FCC 15.247(d)

        private const long BaseAddress = 0x40030000;
        private const long Size = 0x1000;

        private readonly byte[] regs = new byte[Size];
        private double virtualUs;
        private ChipMode mode = ChipMode.Sleep;
        private bool txPending;
        private long abortCount;
        private bool abortWedge;
        private double cadSymbols = 8;                 // CADCFG default
        private double symbolTimeUs = 1024.0;          // SF7 / 125 kHz
        private double lastTxMs;
        private ushort irqMask = 0xFFFF;

        public ChipMode Mode { get { return mode; } }
        public long AbortCount { get { return abortCount; } }
        public bool AbortWedgeFlag { get { return abortWedge; } }
        public double VirtualUs { get { return virtualUs; } }
        public double LastTxAirtimeMs { get { return lastTxMs; } }

        // --- bus interface (stub-shaped; mirror of real Renode signatures) -
        public byte Read(long offset)
        {
            offset -= BaseAddress;
            switch (offset)
            {
                case 0x0000: return (byte)mode;
                case 0x0004: return regs[0x04];
                case 0x0030: return (byte)(irqMask & 0xFF);
                case 0x0031: return (byte)(irqMask >> 8);
                case 0x0034: return regs[0x34];          // IRQ (W1C)
                case 0x0040: return regs[0x40];          // CAD symbols
                case 0x0044: return regs[0x44];          // RXTIMEOUT lsb
                case 0x0054: return (byte)(abortCount & 0xFF);
                case 0x0055: return (byte)((abortCount >> 8) & 0xFF);
                case 0x0058: return (byte)(((lastTxMs > Us915DwellMaxMs
                                             ? 2 : 0))
                                            | (regs[0x58] & 0x01));
                default: return regs[offset];
            }
        }

        public void Write(long offset, byte value)
        {
            offset -= BaseAddress;
            regs[offset] = value;
            switch (offset)
            {
                case 0x0000:
                    TransitionMode((ChipMode)(value & 0x07));
                    break;
                case 0x0030:
                    irqMask = value;
                    break;
                case 0x0034:
                    regs[0x34] &= (byte)~value;          // write-1-to-clear
                    break;
                case 0x0040:
                    cadSymbols = value > 0 ? value : 1;
                    break;
                case 0x0050:
                    if ((value & 0x01) != 0)
                    {
                        Abort();
                    }
                    break;
                case 0x0058:
                    lastTxMs = value * 2.0;              // 2 ms/LSB encoding
                    if (lastTxMs > Us915DwellMaxMs)
                    {
                        SetIrqBit(5);                    // DWELL-VIOLATION
                    }
                    break;
            }
        }

        // --- timing model ---------------------------------------------------
        private void TransitionMode(ChipMode target)
        {
            double cost = 0.0;
            if (target == ChipMode.StandbyRC && mode == ChipMode.Sleep)
            {
                cost = TStandbyRcUs;
            }
            else if (target == ChipMode.StandbyXosc
                     && mode == ChipMode.StandbyRC)
            {
                cost = TStandbyXoscUs;
            }
            else if (target == ChipMode.Rx && mode == ChipMode.StandbyXosc)
            {
                cost = TTxToRxUs;
            }
            else if (target == ChipMode.Tx && mode == ChipMode.StandbyXosc)
            {
                cost = TTxToRxUs;
                txPending = true;
            }
            else if (target == ChipMode.Sleep)
            {
                txPending = false;
            }
            virtualUs += cost;
            mode = target;
        }

        /// <summary>CAD duration for the programmed symbol count (us).</summary>
        public double CadDurationUs()
        {
            return cadSymbols * symbolTimeUs;
        }

        private void Abort()
        {
            // illegal-context guard: an abort in Sleep loses FIFO state in a
            // real chip - the instrumentation hook the 1e5-cycle bench keeps
            if (mode == ChipMode.Sleep)
            {
                abortWedge = true;
            }
            virtualUs += TAbortSettlingUs;
            abortCount++;
            txPending = false;
            mode = ChipMode.StandbyRC;
            SetIrqBit(3);                                // ABORT-DONE
        }

        private void SetIrqBit(int bit)
        {
            regs[0x34] |= (byte)(1 << bit);
        }

        public void Reset()
        {
            for (int i = 0; i < regs.Length; i++)
            {
                regs[i] = 0;
            }
            virtualUs = 0.0;
            mode = ChipMode.Sleep;
            txPending = false;
            abortCount = 0;
            abortWedge = false;
            lastTxMs = 0.0;
            cadSymbols = 8;
            symbolTimeUs = 1024.0;
            irqMask = 0xFFFF;
        }

        public void NoisyLog(string format, params object[] args)
        {
            // stub logger: real Renode routes this to its logging sink
        }
    }
}
