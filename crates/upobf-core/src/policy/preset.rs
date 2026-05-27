//! Build presets controlling strength vs AV friendliness.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Preset {
    /// AV-friendly preset (default, MVP target):
    /// - LZMA + ChaCha20 layered compression
    /// - Standard-API anti-debug (no syscalls, no PEB walk hashing)
    /// - cpuid-only anti-VM (does not exit on detection)
    /// - String encryption, polymorphic stub
    /// - No self-debug, no anti-attach, no API stealing
    AvFriendly,

    /// Aggressive preset (V2):
    /// - Adds API hashing, IAT erasure, VEH control flow
    /// - Adds advanced anti-debug (SEH chain, INT2D, etc.)
    /// - Higher AV detection risk
    Aggressive,
}

impl Default for Preset {
    fn default() -> Self {
        Preset::AvFriendly
    }
}
