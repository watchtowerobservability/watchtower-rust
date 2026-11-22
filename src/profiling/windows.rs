//! Windows x86-64 and arm64 sampling: suspend, copy the context and stack into preallocated
//! memory, resume, then unwind the copy with the OS unwinder. While a thread is suspended nothing
//! here allocates or takes a user-mode lock, because that thread may hold the heap or loader lock.

use std::collections::HashMap;
use std::ffi::c_void;
use std::io;
use std::time::{Duration, Instant};

use super::{DEPTH, Stacks};

type Handle = isize;

#[repr(C)]
struct ThreadEntry32 {
    size: u32,
    usage: u32,
    tid: u32,
    pid: u32,
    base_pri: i32,
    delta_pri: i32,
    flags: u32,
}

/// The thread `CONTEXT` as raw words (16-aligned).
#[repr(C, align(16))]
struct Context([u64; arch::WORDS]);

/// x64 `CONTEXT`: 1232 bytes, ContextFlags at byte 48, Rsp word 19, Rip word 31.
#[cfg(target_arch = "x86_64")]
mod arch {
    pub(super) const WORDS: usize = 154;
    pub(super) const FLAGS_WORD: usize = 6;
    pub(super) const FLAGS: u32 = 0x0010_000B; // AMD64 | CONTROL | INTEGER | FLOATING_POINT
    pub(super) const SP: usize = 19;
    pub(super) const PC: usize = 31;
    pub(super) const LR: Option<usize> = None;
    pub(super) const GPRS: (usize, usize) = (15, 30); // Rax..R15, Rsp included
}

/// arm64 `CONTEXT` (`ARM64_NT_CONTEXT`, winnt.h): 912 bytes, ContextFlags at byte 0, X0 word 1,
/// Fp word 30, Lr word 31, Sp word 32, Pc word 33.
#[cfg(target_arch = "aarch64")]
mod arch {
    pub(super) const WORDS: usize = 114;
    pub(super) const FLAGS_WORD: usize = 0; // the high half is Cpsr, an output
    pub(super) const FLAGS: u32 = 0x0040_0007; // ARM64 | CONTROL | INTEGER | FLOATING_POINT
    pub(super) const SP: usize = 32;
    pub(super) const PC: usize = 33;
    pub(super) const LR: Option<usize> = Some(31);
    pub(super) const GPRS: (usize, usize) = (1, 32); // X0..Lr and Sp
}

// The copy buffer starts at 8 MiB and grows (after the thread is resumed) to fit a larger stack,
// so a stack is never unwound truncated. Zeroed large allocations commit lazily. The slack past
// the copy reads as zeros if a frame's unwind data reaches past the stack's top.
const STACK_COPY: usize = 8 << 20;
const STACK_MAX: usize = 256 << 20; // a thread with a larger stack is skipped
const STACK_SLACK: usize = 1 << 20;
const MEM_COMMIT: u32 = 0x1000;
const PAGE_READWRITE: u32 = 0x04;

#[repr(C)]
#[derive(Default)]
struct MemoryInfo {
    base: usize,
    alloc_base: usize,
    alloc_protect: u32,
    partition: u16,
    region_size: usize,
    state: u32,
    protect: u32,
    kind: u32,
}
const TH32CS_SNAPTHREAD: u32 = 0x4;
const CREATE_WAITABLE_TIMER_HIGH_RESOLUTION: u32 = 0x2; // Windows 10 1803+
const TIMER_ALL_ACCESS: u32 = 0x001F_0003;
const INFINITE: u32 = u32::MAX;
const ACCESS: u32 = 0x2 | 0x8 | 0x40; // SUSPEND_RESUME | GET_CONTEXT | QUERY_INFORMATION

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> Handle;
    fn Thread32First(snap: Handle, te: *mut ThreadEntry32) -> i32;
    fn Thread32Next(snap: Handle, te: *mut ThreadEntry32) -> i32;
    fn OpenThread(access: u32, inherit: i32, tid: u32) -> Handle;
    fn SuspendThread(h: Handle) -> u32;
    fn ResumeThread(h: Handle) -> u32;
    fn GetThreadContext(h: Handle, ctx: *mut Context) -> i32;
    fn QueryThreadCycleTime(h: Handle, cycles: *mut u64) -> i32;
    fn CloseHandle(h: Handle) -> i32;
    fn VirtualQuery(addr: *const c_void, info: *mut MemoryInfo, len: usize) -> usize;
    fn GetCurrentProcessId() -> u32;
    fn GetCurrentThreadId() -> u32;
    fn CreateWaitableTimerExW(
        attrs: *mut c_void,
        name: *const u16,
        flags: u32,
        access: u32,
    ) -> Handle;
    fn SetWaitableTimer(
        h: Handle,
        due: *const i64,
        period: i32,
        apc: *mut c_void,
        arg: *mut c_void,
        resume: i32,
    ) -> i32;
    fn WaitForSingleObject(h: Handle, ms: u32) -> u32;
    fn RtlLookupFunctionEntry(pc: u64, base: *mut u64, history: *mut c_void) -> *mut c_void;
    fn RtlVirtualUnwind(
        kind: u32,
        base: u64,
        pc: u64,
        entry: *mut c_void,
        ctx: *mut Context,
        handler_data: *mut *mut c_void,
        establisher: *mut u64,
        ptrs: *mut c_void,
    ) -> *mut c_void;
}

struct Thread {
    h: Handle,
    cycles: u64,
}

pub(crate) struct Sampler {
    tick: Duration,
    timer: Handle, // high-resolution waitable timer; 0 falls back to Sleep (~15.6 ms steps)
    threads: HashMap<u32, Thread>,
    listed: Option<Instant>,
    ctx: Box<Context>,
    ips: [usize; DEPTH],
    stack: Vec<u8>,
    stack_base: u64,
    stack_len: usize,
    /// Stack size seen that did not fit the buffer; it grows before the next round.
    stack_need: usize,
}

// SAFETY: the handles are process-wide and only used from the owning sampler thread at a time.
unsafe impl Send for Sampler {}

impl Sampler {
    pub(crate) fn new(hz: u32) -> io::Result<Self> {
        let timer = unsafe {
            CreateWaitableTimerExW(
                std::ptr::null_mut(),
                std::ptr::null(),
                CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                TIMER_ALL_ACCESS,
            )
        };
        Ok(Self {
            tick: Duration::from_micros(1_000_000 / u64::from(hz.max(1))),
            timer,
            threads: HashMap::new(),
            listed: None,
            ctx: Box::new(Context([0; arch::WORDS])),
            ips: [0; DEPTH],
            stack: vec![0; STACK_COPY + STACK_SLACK],
            stack_base: 0,
            stack_len: 0,
            stack_need: 0,
        })
    }

    /// Waits one tick: on the high-resolution timer when there is one, else `Sleep`, whose
    /// default resolution caps the rate near 64 Hz.
    pub(crate) fn wait(&self) {
        // relative due time, in 100 ns units
        let due = -i64::try_from(self.tick.as_nanos() / 100).unwrap_or(i64::MAX);
        let set = self.timer != 0
            && unsafe {
                SetWaitableTimer(
                    self.timer,
                    &due,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    0,
                )
            } != 0;
        if !set || unsafe { WaitForSingleObject(self.timer, INFINITE) } != 0 {
            std::thread::sleep(self.tick);
        }
    }

    /// The sampler never samples the thread it runs on (see `relist`).
    pub(crate) fn on_sampler_thread(&self) {}

    /// Re-lists this process's threads (at most once a second).
    fn relist(&mut self) {
        if self
            .listed
            .is_some_and(|t| t.elapsed() < Duration::from_secs(1))
        {
            return;
        }
        self.listed = Some(Instant::now());
        let (pid, me) = unsafe { (GetCurrentProcessId(), GetCurrentThreadId()) };
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snap == -1 {
            return;
        }
        let mut seen = Vec::new();
        let mut te = ThreadEntry32 {
            size: size_of::<ThreadEntry32>() as u32,
            usage: 0,
            tid: 0,
            pid: 0,
            base_pri: 0,
            delta_pri: 0,
            flags: 0,
        };
        let mut ok = unsafe { Thread32First(snap, &mut te) } != 0;
        while ok {
            if te.pid == pid && te.tid != me {
                seen.push(te.tid);
            }
            ok = unsafe { Thread32Next(snap, &mut te) } != 0;
        }
        unsafe { CloseHandle(snap) };
        self.threads.retain(|tid, t| {
            let keep = seen.contains(tid);
            if !keep {
                unsafe { CloseHandle(t.h) };
            }
            keep
        });
        for tid in seen {
            if !self.threads.contains_key(&tid) {
                let h = unsafe { OpenThread(ACCESS, 0, tid) };
                if h != 0 {
                    self.threads.insert(tid, Thread { h, cycles: 0 });
                }
            }
        }
    }

    /// Copies the suspended thread's context and stack top into preallocated memory. Only
    /// syscalls and a memcpy run here: no allocation and no user-mode lock, because this thread
    /// may hold the heap or loader lock and would never be resumed if we waited on it.
    fn snapshot(&mut self, h: Handle) -> bool {
        self.ctx.0 = [0; arch::WORDS];
        // ContextFlags lives in the low half of its word
        self.ctx.0[arch::FLAGS_WORD] = u64::from(arch::FLAGS);
        if unsafe { GetThreadContext(h, &mut *self.ctx) } == 0 {
            return false;
        }
        let rsp = self.ctx.0[arch::SP];
        let mut m = MemoryInfo::default();
        let got = unsafe { VirtualQuery(rsp as *const c_void, &mut m, size_of::<MemoryInfo>()) };
        if got == 0 || m.state != MEM_COMMIT || m.protect & PAGE_READWRITE == 0 {
            return false;
        }
        let end = m.base as u64 + m.region_size as u64;
        let len = end.saturating_sub(rsp) as usize;
        if len + STACK_SLACK > self.stack.len() {
            self.stack_need = len; // too deep for the buffer: grown after resume, read next round
            return false;
        }
        self.stack_len = len;
        self.stack_base = rsp;
        unsafe {
            std::ptr::copy_nonoverlapping(
                rsp as *const u8,
                self.stack.as_mut_ptr(),
                self.stack_len,
            );
        }
        true
    }

    /// Moves every register that points into the original stack range onto the copy, so the
    /// unwinder reads saved values from the snapshot and never the live stack.
    fn rebase(&mut self) {
        let (lo, hi) = (self.stack_base, self.stack_base + self.stack_len as u64);
        let delta = (self.stack.as_ptr() as u64).wrapping_sub(lo);
        for r in &mut self.ctx.0[arch::GPRS.0..=arch::GPRS.1] {
            if *r >= lo && *r < hi {
                *r = r.wrapping_add(delta);
            }
        }
    }

    /// Unwinds the snapshot into `self.ips`; runs after the thread is resumed, so the locks
    /// `RtlLookupFunctionEntry` may take cannot be held by a thread we stopped.
    fn unwind(&mut self) -> usize {
        let copy = self.stack.as_ptr() as u64;
        let copy_end = copy + self.stack_len as u64;
        let mut n = 0;
        while n < DEPTH {
            self.rebase();
            let rip = self.ctx.0[arch::PC];
            let rsp = self.ctx.0[arch::SP];
            if rip == 0 || rsp < copy || rsp + 8 > copy_end {
                break;
            }
            self.ips[n] = rip as usize;
            n += 1;
            let mut base = 0u64;
            let f = unsafe { RtlLookupFunctionEntry(rip, &mut base, std::ptr::null_mut()) };
            if f.is_null() {
                // A leaf function without unwind data. x64: its return address is at rsp. arm64:
                // it is in Lr, which is only still valid for the frame that was running.
                match arch::LR {
                    None => {
                        self.ctx.0[arch::PC] = unsafe { *(rsp as *const u64) };
                        self.ctx.0[arch::SP] = rsp + 8;
                    }
                    Some(lr) if n == 1 => self.ctx.0[arch::PC] = self.ctx.0[lr],
                    Some(_) => break,
                }
            } else {
                let (mut data, mut frame) = (std::ptr::null_mut(), 0u64);
                // The buffer has slack past the copy, so a frame near the end reads zeros, not unmapped memory.
                unsafe {
                    RtlVirtualUnwind(
                        0,
                        base,
                        rip,
                        f,
                        &mut *self.ctx,
                        &mut data,
                        &mut frame,
                        std::ptr::null_mut(),
                    );
                }
            }
        }
        n
    }

    pub(crate) fn collect(&mut self, into: &mut Stacks) {
        self.relist();
        let tids: Vec<u32> = self.threads.keys().copied().collect();
        for tid in tids {
            let Some(t) = self.threads.get_mut(&tid) else {
                continue;
            };
            let (h, mut cycles) = (t.h, 0u64);
            if unsafe { QueryThreadCycleTime(h, &mut cycles) } == 0 || cycles == t.cycles {
                continue; // not on a CPU since the last round: a CPU profile skips it
            }
            t.cycles = cycles;
            if unsafe { SuspendThread(h) } == u32::MAX {
                continue;
            }
            // Nothing between suspend and resume may allocate or lock: see `snapshot`.
            let copied = self.snapshot(h);
            unsafe { ResumeThread(h) };
            if !copied {
                continue;
            }
            let n = self.unwind();
            if n > 0 {
                let ids = super::spans::current(u64::from(tid));
                *into.entry((self.ips[..n].to_vec(), ids)).or_insert(0) += 1;
            }
        }
        // Grown here, with every thread running: allocation is safe now.
        if self.stack_need > 0 && self.stack_need <= STACK_MAX {
            self.stack = vec![0; self.stack_need.next_power_of_two() + STACK_SLACK];
        }
        self.stack_need = 0;
    }
}

/// This thread's OS id.
pub(crate) fn thread_id() -> u64 {
    u64::from(unsafe { GetCurrentThreadId() })
}

impl Drop for Sampler {
    fn drop(&mut self) {
        for t in self.threads.values() {
            unsafe { CloseHandle(t.h) };
        }
        if self.timer != 0 {
            unsafe { CloseHandle(self.timer) };
        }
    }
}
