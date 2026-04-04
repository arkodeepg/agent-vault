// Per-OS primitives. Everything here is either a file read or a <20-line FFI
// to a syscall that userspace cannot forge — boot identity and boot-clock time.

use anyhow::{anyhow, bail, Result};
use std::os::raw::c_int;
#[cfg(target_os = "macos")]
use std::os::raw::{c_char, c_void};

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

extern "C" {
    fn clock_gettime(clk_id: c_int, tp: *mut Timespec) -> c_int;
    fn getuid() -> u32;
}

// CLOCK_BOOTTIME on Linux and CLOCK_MONOTONIC on Darwin both:
//   - count through sleep/hibernate
//   - reset at reboot
//   - are monotonic and not settable from userspace
#[cfg(target_os = "linux")]
const BOOT_CLOCK: c_int = 7; // CLOCK_BOOTTIME

#[cfg(target_os = "macos")]
const BOOT_CLOCK: c_int = 6; // CLOCK_MONOTONIC (Darwin ticks through sleep)

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("s only supports linux and macos");

/// Nanoseconds since boot, including time spent in sleep/hibernate.
/// Cannot be set backwards or paused by userspace.
pub fn boot_clock_ns() -> Result<u64> {
    let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    let rc = unsafe { clock_gettime(BOOT_CLOCK, &mut ts) };
    if rc != 0 {
        bail!("clock_gettime failed");
    }
    let secs = ts.tv_sec.max(0) as u64;
    let nsec = ts.tv_nsec.max(0) as u64;
    Ok(secs.saturating_mul(1_000_000_000).saturating_add(nsec))
}

pub fn uid() -> u32 {
    unsafe { getuid() }
}

/// A per-boot identifier. Changes across reboots, constant within a boot.
/// Used as IKM for the ticket key derivation: after reboot, TK is not
/// recoverable and AES-GCM authentication on the ticket will fail.
#[cfg(target_os = "linux")]
pub fn boot_id() -> Result<Vec<u8>> {
    std::fs::read("/proc/sys/kernel/random/boot_id")
        .map_err(|e| anyhow!("reading /proc/sys/kernel/random/boot_id: {e}"))
}

#[cfg(target_os = "macos")]
pub fn boot_id() -> Result<Vec<u8>> {
    extern "C" {
        fn sysctlbyname(
            name: *const c_char,
            oldp: *mut c_void,
            oldlenp: *mut usize,
            newp: *mut c_void,
            newlen: usize,
        ) -> c_int;
    }
    // struct timeval on Darwin = { time_t tv_sec; suseconds_t tv_usec }
    //                          = { i64,          i32              }
    // 16 bytes including tail padding; sysctl writes exactly that.
    let mut buf = [0u8; 16];
    let mut len: usize = buf.len();
    let name = b"kern.boottime\0";
    let rc = unsafe {
        sysctlbyname(
            name.as_ptr() as *const c_char,
            buf.as_mut_ptr() as *mut c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        bail!("sysctl kern.boottime failed");
    }
    Ok(buf[..len].to_vec())
}
