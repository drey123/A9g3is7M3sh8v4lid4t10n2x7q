// ============================================================================
// RenodeStubs.cs - minimal compile-time stand-ins for the Renode API surface
// used by the LR2021 C# model. This is NOT Renode: CI compiles the model
// against these stubs to catch syntax/type drift cheaply. Semantic validation
// (bus timing against an emulated STM32U5) requires building the model inside
// a Renode checkout - an owner-environment step, recorded in research.md.
// License: MIT (AegisMesh validation fixture).
// ============================================================================

namespace AegisMesh.Validation
{
    /// <summary>Byte-bus peripheral surface (Renode IBytePeripheral shape).</summary>
    public interface IBytePeripheral
    {
        byte Read(long offset);
        void Write(long offset, byte value);
        void Reset();
    }
}
