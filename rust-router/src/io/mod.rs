//! I/O utilities for rust-router
//!
//! This module provides efficient buffer management and bidirectional
//! copy operations for TCP proxying.

mod buffer;
mod copy;

pub use buffer::{BufferStats, IoBuffer, DEFAULT_BUFFER_SIZE, MAX_BUFFER_SIZE, MIN_BUFFER_SIZE};
pub use copy::{bidirectional_copy, bidirectional_copy_with_buffer, CopyResult};
