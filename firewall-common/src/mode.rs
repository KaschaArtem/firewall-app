/// Pass all traffic; whitelist and blacklist are ignored.
pub const MODE_ALL_PASS: u32 = 0;
/// Drop all traffic; whitelist and blacklist are ignored.
pub const MODE_ALL_DROP: u32 = 1;
/// Pass by default; blacklist drops, whitelist passes (overrides default).
pub const MODE_DEFAULT_PASS: u32 = 2;
/// Drop by default; blacklist drops, whitelist passes (overrides default).
pub const MODE_DEFAULT_DROP: u32 = 3;
