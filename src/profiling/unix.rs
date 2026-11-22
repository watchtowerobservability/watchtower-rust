//! `SIGPROF` sampling on Linux and Apple (x86-64, aarch64). The handler walks frame pointers from
//! the interrupted registers into a static ring; the sampler thread drains it and symbolizes.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use super::{DEPTH, Stacks};

const SLOTS: usize = 1024;
const EMPTY: u8 = 0;
const WRITING: u8 = 1;
const FULL: u8 = 2;

struct Slot {
    state: AtomicU8,
    len: AtomicUsize,
    span: AtomicU64,
    hi: AtomicU64,
    lo: AtomicU64,
    ips: [AtomicUsize; DEPTH],
}

impl Slot {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            len: AtomicUsize::new(0),
            span: AtomicU64::new(0),
            hi: AtomicU64::new(0),
            lo: AtomicU64::new(0),
            ips: [const { AtomicUsize::new(0) }; DEPTH],
        }
    }
}

static RING: [Slot; SLOTS] = [const { Slot::new() }; SLOTS];
static NEXT: AtomicUsize = AtomicUsize::new(0);
static LOST: AtomicU64 = AtomicU64::new(0);
static ACTIVE: AtomicBool = AtomicBool::new(false);

#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn errno() -> *mut libc::c_int {
    unsafe { libc::__errno_location() }
}
#[cfg(target_vendor = "apple")]
unsafe fn errno() -> *mut libc::c_int {
    unsafe { libc::__error() }
}

/// Interrupted registers: (pc, frame pointer, stack pointer).
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "x86_64"
))]
unsafe fn regs(uc: *const libc::ucontext_t) -> (usize, usize, usize) {
    let g = unsafe { &(*uc).uc_mcontext.gregs };
    (
        g[libc::REG_RIP as usize] as usize,
        g[libc::REG_RBP as usize] as usize,
        g[libc::REG_RSP as usize] as usize,
    )
}
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
unsafe fn regs(uc: *const libc::ucontext_t) -> (usize, usize, usize) {
    let m = unsafe { &(*uc).uc_mcontext };
    (m.pc as usize, m.regs[29] as usize, m.sp as usize)
}
#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
unsafe fn regs(uc: *const libc::ucontext_t) -> (usize, usize, usize) {
    let s = unsafe { &(*(*uc).uc_mcontext).__ss };
    (s.__pc as usize, s.__fp as usize, s.__sp as usize)
}
#[cfg(all(target_vendor = "apple", target_arch = "x86_64"))]
unsafe fn regs(uc: *const libc::ucontext_t) -> (usize, usize, usize) {
    let s = unsafe { &(*(*uc).uc_mcontext).__ss };
    (s.__rip as usize, s.__rbp as usize, s.__rsp as usize)
}

/// Upper bound of a frame pointer above sp: a chain cannot be longer than this on any thread we
/// would walk, and it stops garbage in the frame register from wandering the address space.
#[cfg(any(target_os = "linux", target_os = "android"))]
const MAX_STACK: usize = 1 << 30;

/// Reads a frame record `[saved fp, return address]` at `fp`, or `None`. Must not fault: bad
/// frame-pointer values are normal in code built without frame pointers.
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn read_record(fp: usize, sp: usize) -> Option<[usize; 2]> {
    if fp.checked_sub(sp)? >= MAX_STACK {
        return None;
    }
    let mut out = [0usize; 2];
    let local = libc::iovec {
        iov_base: out.as_mut_ptr().cast(),
        iov_len: size_of::<[usize; 2]>(),
    };
    let remote = libc::iovec {
        iov_base: fp as *mut libc::c_void,
        iov_len: size_of::<[usize; 2]>(),
    };
    // The kernel checks the address and answers EFAULT, so garbage cannot crash the application.
    let n = unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) };
    (n == size_of::<[usize; 2]>() as isize).then_some(out)
}

/// As above, on Apple: only the running thread's own stack is read, which is always mapped.
#[cfg(target_vendor = "apple")]
unsafe fn read_record(fp: usize, sp: usize) -> Option<[usize; 2]> {
    let me = unsafe { libc::pthread_self() };
    let top = unsafe { libc::pthread_get_stackaddr_np(me) } as usize;
    if fp < sp || fp.checked_add(size_of::<[usize; 2]>())? > top {
        return None;
    }
    Some(unsafe { *(fp as *const [usize; 2]) })
}

/// Strips pointer-authentication bits from a return address.
fn code_addr(ra: usize) -> usize {
    if cfg!(target_arch = "aarch64") {
        ra & 0x0000_ffff_ffff_ffff
    } else {
        ra
    }
}

/// Async-signal-safe: atomics and one raw syscall only, no allocation, no lock, no unwinder and
/// no `dl_iterate_phdr`, so it cannot deadlock against what the interrupted code holds.
extern "C" fn on_prof(_: libc::c_int, _: *mut libc::siginfo_t, uc: *mut libc::c_void) {
    let saved = unsafe { *errno() };
    let slot = &RING[NEXT.fetch_add(1, Ordering::Relaxed) % SLOTS];
    if slot
        .state
        .compare_exchange(EMPTY, WRITING, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
    {
        let (pc, mut fp, sp) = unsafe { regs(uc as *const libc::ucontext_t) };
        slot.ips[0].store(pc, Ordering::Relaxed);
        let mut n = 1;
        let mut low = sp;
        // Frames grow up the stack, aligned: anything else ends the walk.
        while n < DEPTH && fp % align_of::<usize>() == 0 && fp >= low {
            let Some([next, ra]) = (unsafe { read_record(fp, low) }) else {
                break;
            };
            if ra == 0 {
                break;
            }
            slot.ips[n].store(code_addr(ra), Ordering::Relaxed);
            n += 1;
            low = fp + 1;
            fp = next;
        }
        let ids = super::spans::current(super::thread_id());
        slot.span.store(ids.0, Ordering::Relaxed);
        slot.hi.store((ids.1 >> 64) as u64, Ordering::Relaxed);
        slot.lo.store(ids.1 as u64, Ordering::Relaxed);
        slot.len.store(n, Ordering::Relaxed);
        slot.state.store(FULL, Ordering::Release);
    } else {
        LOST.fetch_add(1, Ordering::Relaxed);
    }
    unsafe { *errno() = saved };
}

fn timer(hz: u32) -> io::Result<()> {
    let us = if hz == 0 {
        0
    } else {
        1_000_000 / i64::from(hz)
    };
    let tv = libc::timeval {
        tv_sec: (us / 1_000_000) as libc::time_t,
        tv_usec: (us % 1_000_000) as libc::suseconds_t,
    };
    let it = libc::itimerval {
        it_interval: tv,
        it_value: tv,
    };
    if unsafe { libc::setitimer(libc::ITIMER_PROF, &it, std::ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) struct Sampler;

impl Sampler {
    pub(crate) fn new(hz: u32) -> io::Result<Self> {
        if ACTIVE.swap(true, Ordering::AcqRel) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "a profiler already runs",
            ));
        }
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_prof as *const () as libc::sighandler_t;
            sa.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
            libc::sigemptyset(&mut sa.sa_mask);
            if libc::sigaction(libc::SIGPROF, &sa, std::ptr::null_mut()) != 0 {
                ACTIVE.store(false, Ordering::Release);
                return Err(io::Error::last_os_error());
            }
        }
        timer(hz).inspect_err(|_| ACTIVE.store(false, Ordering::Release))?;
        Ok(Self)
    }

    pub(crate) fn tick(&self) -> Duration {
        Duration::from_millis(100)
    }

    /// Waits one collection round; SIGPROF does the sampling meanwhile.
    pub(crate) fn wait(&self) {
        std::thread::sleep(self.tick());
    }

    /// Keeps SIGPROF off the thread that symbolizes and uploads.
    pub(crate) fn on_sampler_thread(&self) {
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGPROF);
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        }
    }

    pub(crate) fn collect(&mut self, into: &mut Stacks) {
        for slot in &RING {
            if slot.state.load(Ordering::Acquire) != FULL {
                continue;
            }
            let n = slot.len.load(Ordering::Relaxed).min(DEPTH);
            let ips: Vec<usize> = slot.ips[..n]
                .iter()
                .map(|a| a.load(Ordering::Relaxed))
                .collect();
            let ids = (
                slot.span.load(Ordering::Relaxed),
                (u128::from(slot.hi.load(Ordering::Relaxed)) << 64)
                    | u128::from(slot.lo.load(Ordering::Relaxed)),
            );
            slot.state.store(EMPTY, Ordering::Release);
            if !ips.is_empty() {
                *into.entry((ips, ids)).or_insert(0) += 1;
            }
        }
    }
}

/// This thread's OS id, async-signal-safe.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn thread_id() -> u64 {
    (unsafe { libc::syscall(libc::SYS_gettid) }) as u64
}
#[cfg(target_vendor = "apple")]
pub(crate) fn thread_id() -> u64 {
    u64::from(unsafe { libc::pthread_mach_thread_np(libc::pthread_self()) })
}

impl Drop for Sampler {
    fn drop(&mut self) {
        let _ = timer(0); // the handler stays installed: a late SIGPROF must not kill the process
        ACTIVE.store(false, Ordering::Release);
    }
}
