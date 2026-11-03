// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Bounded lifecycle tracing without presentation I/O on networking tasks.
//!
//! Only fixed event names are retained; arbitrary tracing fields and spans are
//! discarded. The executable flushes after networking stops. This is not the
//! future desktop log stream, and does not install a process-global subscriber.

use std::{
    io::{self, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
use tracing::{Event, Metadata, Subscriber, span};

const CAPACITY: usize = 64;
const NAMES: &[&str] = &[
    "command_started",
    "command_stopped",
    "command_failed",
    "network_starting",
    "network_connected",
    "network_stopping",
    "network_retired",
    "network_recovery_required",
    "network_failed",
];

struct Records {
    names: [Option<&'static str>; CAPACITY],
    next: usize,
    count: usize,
}
impl Default for Records {
    fn default() -> Self {
        Self {
            names: [None; CAPACITY],
            next: 0,
            count: 0,
        }
    }
}
#[derive(Default)]
struct Inner {
    records: Mutex<Records>,
    dropped: AtomicU64,
}

#[derive(Clone, Default)]
pub struct LifecycleLog(Arc<Inner>);
impl LifecycleLog {
    /// Write the retained tail in order. Call after active networking stops;
    /// the writer may block or fail, unlike event recording.
    pub fn write(&self, writer: &mut impl Write) -> io::Result<()> {
        let records = self.0.records.lock().map_err(|_| io::ErrorKind::Other)?;
        let names = records.names;
        let next = records.next;
        let count = records.count;
        drop(records);
        for index in 0..count {
            let slot = (next + CAPACITY - count + index) % CAPACITY;
            if let Some(name) = names[slot] {
                writeln!(writer, "lifecycle {name}")?;
            }
        }
        writeln!(
            writer,
            "lifecycle dropped={}",
            self.0.dropped.load(Ordering::Relaxed)
        )
    }

    fn dropped(&self) {
        let _previous = self
            .0
            .dropped
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                Some(count.saturating_add(1))
            });
    }
}
impl Subscriber for LifecycleLog {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.is_event()
            && metadata.target() == "warper.lifecycle"
            && NAMES.contains(&metadata.name())
    }
    fn event(&self, event: &Event<'_>) {
        if !self.enabled(event.metadata()) {
            return;
        }
        // Contention and overflow lose diagnostics, never block forwarding.
        let Ok(mut records) = self.0.records.try_lock() else {
            self.dropped();
            return;
        };
        let next = records.next;
        records.names[next] = Some(event.metadata().name());
        records.next = (next + 1) % CAPACITY;
        if records.count == CAPACITY {
            self.dropped();
        } else {
            records.count += 1;
        }
    }
    // Spans are disabled; no span state or caller-provided fields are retained.
    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }
    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn enter(&self, _: &span::Id) {}
    fn exit(&self, _: &span::Id) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_ordered_bounded_tail_and_counts_overflow() {
        let log = LifecycleLog::default();
        tracing::subscriber::with_default(log.clone(), || {
            for _ in 0..CAPACITY {
                tracing::event!(name: "network_connected", target: "warper.lifecycle", tracing::Level::INFO, {});
            }
            tracing::event!(name: "network_retired", target: "warper.lifecycle", tracing::Level::INFO, {});
        });
        let mut output = Vec::new();
        log.write(&mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert_eq!(output.lines().count(), CAPACITY + 1);
        assert!(output.ends_with("lifecycle network_retired\nlifecycle dropped=1\n"));
    }

    #[test]
    fn ignores_fields_untrusted_names_and_other_targets() {
        let log = LifecycleLog::default();
        tracing::subscriber::with_default(log.clone(), || {
            tracing::event!(name: "network_connected", target: "warper.lifecycle", tracing::Level::INFO, password = "synthetic-secret");
            tracing::event!(name: "synthetic-secret", target: "warper.lifecycle", tracing::Level::INFO, {});
            tracing::event!(name: "network_connected", target: "other", tracing::Level::INFO, {});
        });
        let mut output = Vec::new();
        log.write(&mut output).unwrap();
        assert_eq!(
            output,
            b"lifecycle network_connected\nlifecycle dropped=0\n"
        );
    }

    #[test]
    fn contention_drops_events_without_waiting() {
        let log = LifecycleLog::default();
        let records = log.0.records.lock().unwrap();
        let worker_log = log.clone();
        let (completed, observed) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            tracing::subscriber::with_default(worker_log, || {
                tracing::event!(name: "network_connected", target: "warper.lifecycle", tracing::Level::INFO, {});
            });
            completed.send(()).unwrap();
        });
        let result = observed.recv_timeout(std::time::Duration::from_secs(1));
        // Release before joining even if recording mistakenly waited for us.
        drop(records);
        worker.join().unwrap();
        assert!(
            result.is_ok(),
            "recording must not wait for the retained log"
        );
        assert_eq!(log.0.dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn slow_output_does_not_hold_the_recording_lock() {
        use std::{sync::mpsc, time::Duration};
        struct SlowWriter {
            started: Option<mpsc::Sender<()>>,
            release: mpsc::Receiver<()>,
        }
        impl Write for SlowWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if let Some(started) = self.started.take() {
                    started.send(()).map_err(|_| io::ErrorKind::BrokenPipe)?;
                    self.release
                        .recv_timeout(Duration::from_secs(1))
                        .map_err(|_| io::ErrorKind::TimedOut)?;
                }
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let log = LifecycleLog::default();
        let writer_log = log.clone();
        let (started, observed) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let writer = std::thread::spawn(move || {
            writer_log.write(&mut SlowWriter {
                started: Some(started),
                release: released,
            })
        });
        let ready = observed.recv_timeout(Duration::from_secs(1));
        tracing::subscriber::with_default(log.clone(), || {
            tracing::event!(name: "network_connected", target: "warper.lifecycle", tracing::Level::INFO, {});
        });
        let resumed = release.send(());
        let result = writer.join().unwrap();
        assert!(ready.is_ok());
        assert!(resumed.is_ok());
        assert!(result.is_ok());
        let mut output = Vec::new();
        log.write(&mut output).unwrap();
        assert_eq!(
            output,
            b"lifecycle network_connected\nlifecycle dropped=0\n"
        );
    }

    #[test]
    fn unavailable_output_is_reported() {
        assert!(LifecycleLog::default().write(&mut io::sink()).is_ok());
        let log = LifecycleLog::default();
        tracing::subscriber::with_default(log.clone(), || {
            tracing::event!(name: "network_connected", target: "warper.lifecycle", tracing::Level::INFO, {});
        });
        let mut full = &mut [][..];
        assert_eq!(
            log.write(&mut full).unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
    }
}
