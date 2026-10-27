//! Unit tests for `src/vmx/page.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items. The resident-allocation registry is global state set by
//! bring-up, so these test only the pure range logic `is_resident` relies on.

use super::*;

#[test]
fn an_allocation_contains_its_own_pages_and_no_others() {
    let a = Allocation {
        address: 0x1000,
        pages: 2,
        code: false,
    };
    // The page below, the first byte, the last byte, and the page above.
    assert!(!a.contains(0x0FFF));
    assert!(a.contains(0x1000));
    assert!(a.contains(0x1000 + 2 * PAGE_SIZE as u64 - 1));
    assert!(!a.contains(0x1000 + 2 * PAGE_SIZE as u64));
}
