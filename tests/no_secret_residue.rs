//! Guards the crate's core memory-hygiene promise: once a secret-producing
//! operation returns, no freed heap block still holds key material.
//!
//! A global allocator wrapper copies each block's contents at the instant it is
//! freed, and the tests then scan that scrap for known key material. Recording
//! is armed per-thread, so a test observes only its own allocations.
//!
//! Two things keep this from decaying into a rubber stamp:
//!
//! - [`detector_finds_a_deliberate_leak`] is a canary. A leak test that has
//!   silently stopped detecting leaks passes forever, so one case here *must*
//!   fail to be clean.
//! - Scrap overflow is an assertion failure, not a skipped recording.
//!
//! Blind spot worth naming: this sees the heap only. Every secret this crate
//! holds is boxed so that it falls under the scan, which is what
//! [`private_key_keeps_its_bytes_off_the_stack`] pins down. What remains out of
//! reach is other people's stack: the `[u8; 32]` a caller hands to
//! `PrivateKey::from_bytes`, and whatever libsecp256k1 leaves behind while
//! deriving a public key.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::{Cell, UnsafeCell};
use std::hint::black_box;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use btc_keygen::PrivateKey;

// ---------------------------------------------------------------
// Recording allocator
// ---------------------------------------------------------------

/// Room for the freed blocks of a whole keypair pipeline.
const SCRAP_CAP: usize = 4 << 20;

/// Blocks bigger than this are skipped, so one unexpectedly large allocation
/// cannot consume the whole scrap. Nothing on the paths under test comes close:
/// the largest recorded block is a few hundred bytes. Every secret this crate
/// holds is well under the limit, so none can slip past it.
const MAX_BLOCK: usize = 64 << 10;

struct Scrap(UnsafeCell<[u8; SCRAP_CAP]>);

// Safety: only the armed thread writes, and it writes at offsets it claimed
// from CURSOR, so writes never overlap. Reads happen after disarming.
unsafe impl Sync for Scrap {}

static SCRAP: Scrap = Scrap(UnsafeCell::new([0; SCRAP_CAP]));
static CURSOR: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);
static OVERFLOWED: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// Const-initialized and destructor-free, so touching it from inside the
    /// allocator cannot allocate or re-enter.
    static ARMED: Cell<bool> = const { Cell::new(false) };
}

fn armed() -> bool {
    ARMED.try_with(Cell::get).unwrap_or(false)
}

struct Recorder;

unsafe impl GlobalAlloc for Recorder {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if armed() {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let size = layout.size();
        if armed() && size > 0 && size <= MAX_BLOCK {
            let start = CURSOR.fetch_add(size, Ordering::Relaxed);
            if start + size <= SCRAP_CAP {
                // Safety: the block is still live until System.dealloc below,
                // and `start..start + size` is ours alone.
                unsafe {
                    std::ptr::copy_nonoverlapping(ptr, SCRAP.0.get().cast::<u8>().add(start), size);
                }
            } else {
                OVERFLOWED.store(true, Ordering::Relaxed);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Recorder = Recorder;

// ---------------------------------------------------------------
// Harness
// ---------------------------------------------------------------

/// The scrap is global, so recordings run one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

struct Recording {
    /// Allocations made while armed.
    allocs: usize,
    /// Bytes requested by those allocations. Tracked separately because one
    /// allocation can be a megabyte, so a count alone hides the cost.
    bytes: usize,
    /// Contents of every block freed while armed.
    freed: Vec<u8>,
}

impl Recording {
    fn holds(&self, needle: &[u8]) -> bool {
        self.freed.windows(needle.len()).any(|w| w == needle)
    }

    /// Asserts that nothing derived from `key` survived in freed memory: not
    /// the raw scalar, not its WIF, not its hex.
    fn assert_no_trace_of(&self, key: &PrivateKey) {
        let wif = btc_keygen::encode_wif(key);
        let hex = key.to_hex();

        assert!(
            !self.holds(key.as_bytes()),
            "raw private key bytes found in {} bytes of freed heap",
            self.freed.len()
        );
        assert!(
            !self.holds(wif.expose_bytes()),
            "WIF found in {} bytes of freed heap",
            self.freed.len()
        );
        assert!(
            !self.holds(hex.expose_bytes()),
            "private key hex found in {} bytes of freed heap",
            self.freed.len()
        );
    }
}

/// Runs `body` with allocation recording armed on this thread.
fn record(body: impl FnOnce()) -> Recording {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    CURSOR.store(0, Ordering::SeqCst);
    ALLOCS.store(0, Ordering::SeqCst);
    ALLOC_BYTES.store(0, Ordering::SeqCst);
    OVERFLOWED.store(false, Ordering::SeqCst);

    ARMED.set(true);
    body();
    ARMED.set(false);

    let used = CURSOR.load(Ordering::SeqCst).min(SCRAP_CAP);
    let allocs = ALLOCS.load(Ordering::SeqCst);
    let bytes = ALLOC_BYTES.load(Ordering::SeqCst);
    assert!(
        !OVERFLOWED.load(Ordering::SeqCst),
        "freed-block scrap overflowed: raise SCRAP_CAP. A skipped recording \
         would make this test pass without checking anything."
    );

    // Safety: disarmed and holding SERIAL, so nothing is writing to the scrap.
    // Copying it allocates, which is why this happens after disarming.
    let freed = unsafe { std::slice::from_raw_parts(SCRAP.0.get().cast::<u8>(), used) }.to_vec();
    Recording {
        allocs,
        bytes,
        freed,
    }
}

const KEY_HEX: &str = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";

fn test_key() -> PrivateKey {
    PrivateKey::from_hex(KEY_HEX).expect("known-good test vector")
}

// ---------------------------------------------------------------
// The canary: proves the detector still detects
// ---------------------------------------------------------------

#[test]
fn detector_finds_a_deliberate_leak() {
    const CANARY: &str = "canary-9f3a1c0e-must-be-found-in-the-freed-heap";

    let recording = record(|| {
        let leaked = String::from(CANARY);
        black_box(leaked.as_bytes());
    });

    assert!(
        recording.holds(CANARY.as_bytes()),
        "the detector cannot see a String it just watched being freed, so every \
         other test in this file is meaningless"
    );
    assert!(
        recording.allocs >= 1,
        "the String allocation went uncounted"
    );
}

// ---------------------------------------------------------------
// No residue from secret-producing operations
// ---------------------------------------------------------------

#[test]
fn encode_wif_leaves_no_residue() {
    let key = test_key();
    let recording = record(|| {
        let wif = btc_keygen::encode_wif(&key);
        black_box(wif.expose_bytes());
    });
    recording.assert_no_trace_of(&key);
}

#[test]
fn to_hex_leaves_no_residue() {
    let key = test_key();
    let recording = record(|| {
        let hex = key.to_hex();
        black_box(hex.expose_bytes());
    });
    recording.assert_no_trace_of(&key);
}

#[test]
fn from_hex_leaves_no_residue() {
    let recording = record(|| {
        let key = PrivateKey::from_hex(KEY_HEX).unwrap();
        black_box(key.as_bytes());
    });
    recording.assert_no_trace_of(&test_key());
}

#[test]
fn whole_pipeline_leaves_no_residue() {
    let recording = record(|| {
        let key = PrivateKey::from_hex(KEY_HEX).unwrap();
        let wif = btc_keygen::encode_wif(&key);
        let hex = key.to_hex();
        let pubkey = btc_keygen::derive_pubkey(&key);
        let address = btc_keygen::derive_address(&pubkey);

        black_box(wif.expose_bytes());
        black_box(hex.expose_bytes());
        black_box(&address);
    });
    recording.assert_no_trace_of(&test_key());
}

/// The guard that keeps `PrivateKey`'s bytes reachable by every test above.
///
/// An inline `[u8; 32]` is memcpy'd into a fresh stack slot on every move, and
/// no allocator hook can see that, so reverting to one would make the residue
/// tests pass while checking nothing. Pointer-sized is the property to hold.
#[test]
fn private_key_keeps_its_bytes_off_the_stack() {
    assert_eq!(
        std::mem::size_of::<PrivateKey>(),
        std::mem::size_of::<usize>(),
        "PrivateKey must stay pointer-sized: inlining its bytes silently blinds \
         every other test in this file"
    );
}

#[test]
fn dropped_key_leaves_no_residue() {
    // Fingerprint of a real generated key, kept on the stack where a heap scan
    // cannot see it, so the scan below cannot match on our own copy.
    let mut fingerprint = [0u8; 32];

    let recording = record(|| {
        let key = btc_keygen::generate().expect("OS entropy must work");
        fingerprint = *key.as_bytes();
        black_box(key.as_bytes());
        drop(key);
    });

    assert!(
        !recording.holds(&fingerprint),
        "raw key bytes survived in freed heap after the PrivateKey was dropped"
    );
}

#[test]
fn generated_keys_leave_no_residue() {
    // The real entry point: OS entropy rather than a fixture.
    let mut generated = None;
    let recording = record(|| {
        let key = btc_keygen::generate().expect("OS entropy must work");
        let wif = btc_keygen::encode_wif(&key);
        black_box(wif.expose_bytes());
        generated = Some(key);
    });
    recording.assert_no_trace_of(&generated.expect("key was generated"));
}

// ---------------------------------------------------------------
// Allocation budgets: the north star for shrinking allocations
// ---------------------------------------------------------------

/// Ratchet, not decoration. When a change lowers one of these numbers, lower
/// the constant too, so the gain cannot be silently given back.
#[test]
fn secret_producers_stay_within_allocation_budget() {
    let key = test_key();

    // One allocation each, exactly the size of the secret buffer itself.
    let wif = record(|| {
        black_box(btc_keygen::encode_wif(&key));
    });
    assert_eq!(wif.allocs, 1, "encode_wif should allocate only SecretWif");
    assert_eq!(wif.bytes, 52, "SecretWif is the only allocation");

    let hex = record(|| {
        black_box(key.to_hex());
    });
    assert_eq!(hex.allocs, 1, "to_hex should allocate only SecretKeyHex");
    assert_eq!(hex.bytes, 64, "SecretKeyHex is the only allocation");

    // Parsing and generation each allocate the key's own 32-byte buffer, and
    // nothing else. That allocation is required, not incidental: a PrivateKey
    // holding an inline array would be memcpy'd on every move, leaving stack
    // copies nothing erases. One heap buffer, written in place, moves as a
    // pointer instead. These counts belong at 1 and must never reach 0.
    let parse = record(|| {
        black_box(PrivateKey::from_hex(KEY_HEX).unwrap());
    });
    assert_eq!(
        parse.allocs, 1,
        "from_hex should allocate only the key buffer"
    );
    assert_eq!(parse.bytes, 32, "the key buffer is the only allocation");

    let generate = record(|| {
        black_box(btc_keygen::generate().unwrap());
    });
    assert_eq!(
        generate.allocs, 1,
        "generate should allocate only the key buffer"
    );
    assert_eq!(generate.bytes, 32, "the key buffer is the only allocation");
}

/// Public derivation allocates twice, once inside each dependency:
/// `derive_pubkey` builds a `Secp256k1` context and `derive_address` builds the
/// Bech32 `String`. Neither holds secret material.
///
/// Both are small. libsecp256k1's precomputed tables are static in this build,
/// so the context costs a couple of hundred bytes rather than the megabyte an
/// on-the-fly table would, and there is nothing here worth optimizing.
///
/// Measured at 2 allocations and 250 bytes. The byte budget is tracked
/// alongside the count because one allocation can be arbitrarily large, so a
/// count on its own would hide a regression that swaps a static table for a
/// computed one.
#[test]
fn public_derivation_stays_within_allocation_budget() {
    const ALLOC_BUDGET: usize = 2;
    const BYTE_BUDGET: usize = 512;

    let key = test_key();
    let recording = record(|| {
        let pubkey = btc_keygen::derive_pubkey(&key);
        black_box(btc_keygen::derive_address(&pubkey));
    });

    assert!(
        recording.allocs <= ALLOC_BUDGET,
        "derive_pubkey + derive_address made {} allocations, budget is {ALLOC_BUDGET}",
        recording.allocs
    );
    assert!(
        recording.bytes <= BYTE_BUDGET,
        "derive_pubkey + derive_address requested {} bytes, budget is {BYTE_BUDGET}",
        recording.bytes
    );
}
