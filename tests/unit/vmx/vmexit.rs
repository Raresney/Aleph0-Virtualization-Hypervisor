//! Unit tests for `src/vmx/vmexit/mod.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;

#[test]
fn an_untouched_stack_is_unused() {
    assert_eq!(used_bytes(&[0; 4]), 0);
}

#[test]
fn use_counts_from_the_lowest_nonzero_word_to_the_top() {
    // The stack grows down: the last word is its top, written first.
    assert_eq!(used_bytes(&[0, 0, 0, 7]), 8);
    // A zero word above the lowest written one still counts as used.
    assert_eq!(used_bytes(&[0, 5, 0, 7]), 24);
}

#[test]
fn a_written_lowest_word_is_the_whole_stack() {
    assert_eq!(used_bytes(&[1, 0, 0, 0]), 32);
}
