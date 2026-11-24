//! A small bounded parallel map, for network-bound and parse-bound work.
//!
//! Results come back in input order, so callers stay deterministic.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Apply `f` to every item on up to `workers` threads. The output is in input order.
pub fn map<T: Sync, R: Send>(items: &[T], workers: usize, f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let workers = workers.clamp(1, items.len().max(1));
    if workers == 1 {
        return items.iter().map(f).collect();
    }
    let next = AtomicUsize::new(0);
    let slots: Vec<Mutex<Option<R>>> = items.iter().map(|_| Mutex::new(None)).collect();
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(i) else { break };
                    let r = f(item);
                    *slots[i]
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(r);
                }
            });
        }
    });
    slots
        .into_iter()
        .map(|m| {
            m.into_inner()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .expect("every item was mapped")
        })
        .collect()
}

/// Up to `cap` threads, but no more than the machine has.
pub fn threads(cap: usize) -> usize {
    std::thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
        .min(cap)
        .max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_order_and_maps_everything() {
        let items: Vec<u32> = (0..1000).collect();
        let out = map(&items, 8, |x| x * 2);
        assert_eq!(out, items.iter().map(|x| x * 2).collect::<Vec<_>>());
        assert!(map(&Vec::<u32>::new(), 8, |x| *x).is_empty());
        assert_eq!(map(&[1], 0, |x| x + 1), vec![2]);
    }
}
