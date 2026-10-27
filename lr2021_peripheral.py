# Renode LR2021 peripheral skeleton (Python) for AegisMesh firmware validation
# =============================================================================
# Status: SKELETON - register map + abort-timing hooks only. Register-accurate
# CAD/STANDBY timing should graduate to a C# model per the Renode peripheral
# modeling guide (Python peripherals are documented for "very simple logic").
#
# API: Renode PythonPeripheral script semantics - the script is evaluated on
# every bus access with `request` in scope (request.Value, request.Offset,
# request.Type, request.IsInit); `self` is the peripheral context.
# Registration (platform .repl):
#
#   lr2021: Python.PythonPeripheral @ sysbus 0x40030000
#       size: 0x1000
#       initable: true
#       filename: "lr2021_peripheral.py"
#
# License: MIT (AegisMesh validation fixture - disposable, belongs to the
# public Actions repo per task.md Firmware Validation Infrastructure rules).
#
# Semtech LR2021 register model (subset relevant to MAC timing claims):
#   0x0000 OCDW      - operation control / chip mode (sleep/standby/rx/tx)
#   0x0004 CFG       - packet type (LoRa / FLRC), modulation params
#   0x0010 FIFOCTL   - FIFO thresholds (TX/RX)
#   0x0020 TXADDR    - TX FIFO pointer
#   0x0024 RXADDR    - RX FIFO pointer
#   0x0030 IRQMASK   - interrupt mask
#   0x0034 IRQ       - interrupt status (CAD done, TX done, RX done, timeout)
#   0x0040 CADCFG    - CAD parameter (num symbols, cad-rx / cad-lbt mode)
#   0x0044 RXTIMEOUT - rx_max_time for CAD-RX / CAD-LBT (automated CAD with
#                      host asleep; the feature that keeps the U5 out of the
#                      4 ms critical path - see research.md MAC-002/ML-002)
#   0x0050 ABORT     - write 1 = abort in-flight TX/ro standby (L1 pre-emption
#                      path, ML-002: bench target <= 100 us, 1e5 cycles clean)

import time as _pytime

# virtual-time accounting (Renode virtual time is CPU-driven; we track the
# model's own notion of elapsed us for the abort/Turnaround claims)
_state = {
    "mode": "sleep",           # sleep | standby | rx | tx
    "t_mode_entered_us": 0.0,
    "virtual_us": 0.0,
    "abort_count": 0,
    "abort_wedge": False,
    "last_cad_us": 0.0,
    "tx_pending": False,
}

# documented timing constants (datasheet-class; replace with measured rev-A)
T_STANDBY_RC_US = 55.0      # sleep -> STANDBY_RC
T_STANDBY_XOSC_US = 180.0   # STANDBY_RC -> STANDBY_XOSC
T_TX_TO_RX_US = 250.0       # turnaround
T_ABORT_SETTLING_US = 100.0 # ML-002 abort budget (bench target)


def _advance(delta_us):
    _state["virtual_us"] += delta_us


def read_callback(offset, size):
    """Register read."""
    _advance(0.05)
    if offset == 0x0034:            # IRQ
        v = 0
        if _state["abort_count"]:
            v |= 1 << 2             # ABORT-DONE
        if not _state["tx_pending"] and _state["mode"] == "rx":
            v |= 1 << 0             # RX-DONE (stub: always ready)
        return v
    if offset == 0x0000:            # OCDW: chip mode
        return {"sleep": 0, "standby": 1, "rx": 2, "tx": 3}[_state["mode"]]
    if offset == 0x0054:            # ABORTSTAT
        return _state["abort_count"] & 0xFFFF
    return 0


def write_callback(offset, value, size):
    """Register write - models the timing-relevant transitions only."""
    if offset == 0x0000:            # OCDW: mode changes
        t = {"sleep": 0.0, "standby": T_STANDBY_RC_US,
             "rx": T_TX_TO_RX_US, "tx": T_STANDBY_XOSC_US}.get(
                 {0: "sleep", 1: "standby", 2: "rx", 3: "tx"}[value & 3],
                 0.0)
        _advance(t)
        _state["mode"] = {0: "sleep", 1: "standby", 2: "rx", 3: "tx"}[
            value & 3]
    elif offset == 0x0050:          # ABORT
        if value & 1:
            # L1 pre-emption: abort in-flight TX, recover FIFO cleanly.
            # Wedging is the failure mode the 1e5-cycle bench hunts for.
            _advance(T_ABORT_SETTLING_US)
            _state["abort_count"] += 1
            _state["tx_pending"] = False
            _state["mode"] = "standby"
            _state["abort_wedge"] = (_state["abort_count"] % 100000
                                     == 99999)  # instrumentation hook
    elif offset == 0x0044:          # RXTIMEOUT
        _advance(0.05)
    # every other offset: tag (log-only)
    self.NoisyLog("LR2021[%s] write 0x%03x = 0x%x" % (_state["mode"],
                                                      offset, value))


def init():
    """Called when initable: true at platform load."""
    _state["t_mode_entered_us"] = 0.0
    self.NoisyLog("LR2021 skeleton initialized (mode=sleep)")
