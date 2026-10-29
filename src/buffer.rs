//! Bounded in-memory buffer for batches that failed to export.

use std::collections::VecDeque;

/// Drops the oldest batch when full. Disk spooling is not implemented (shortcut: a process
/// restart loses buffered batches; upgrade by serializing to OTLP protobuf files).
#[derive(Debug)]
pub struct OfflineBuffer<T> {
    q: VecDeque<T>,
    max: usize,
}

impl<T> OfflineBuffer<T> {
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            q: VecDeque::new(),
            max: max.max(1),
        }
    }

    pub fn push(&mut self, item: T) {
        if self.q.len() >= self.max {
            self.q.pop_front();
        }
        self.q.push_back(item);
    }

    pub fn drain(&mut self) -> Vec<T> {
        self.q.drain(..).collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.q.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.q.is_empty()
    }
}
