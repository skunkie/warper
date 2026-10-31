// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! One backend attempt and bounded copying, without detached child tasks.

use super::*;
use std::{
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, copy_bidirectional_with_sizes};
use warper_core::transport::TcpStream;

pub(super) async fn run(
    mut flow: CapturedTcp,
    backend: Arc<dyn Backend>,
    request: Request,
    end: Instant,
    idle: Duration,
) -> Completion {
    let mut upstream = match request
        .clone()
        .run(backend.open_tcp(flow.metadata.destination, request.clone()))
        .await
    {
        Ok(stream) => stream,
        Err(error) => {
            return Completion {
                id: flow.metadata.id,
                backend: flow.metadata.backend,
                transferred: Transferred::default(),
                outcome: Err(FlowError::Setup(error)),
            };
        }
    };
    let activity = Activity {
        origin: Instant::now(),
        progress: AtomicU64::new(0),
        sent: AtomicU64::new(0),
        received: AtomicU64::new(0),
    };
    let mut capture = Tracked {
        inner: &mut flow.stream,
        activity: &activity,
        written: &activity.received,
    };
    let mut remote = Tracked {
        inner: &mut upstream,
        activity: &activity,
        written: &activity.sent,
    };
    let mut cancel = request.cancellation;
    let copying = copy_bidirectional_with_sizes(
        &mut capture,
        &mut remote,
        COPY_BUFFER_BYTES,
        COPY_BUFFER_BYTES,
    );
    tokio::pin!(copying);
    let outcome = loop {
        let last = activity.progress.load(Ordering::Relaxed);
        let Some(deadline) = activity
            .origin
            .checked_add(Duration::from_millis(last))
            .and_then(|instant| instant.checked_add(idle))
            .and_then(|instant| instant.checked_add(Duration::from_millis(1)))
        else {
            break Err(FlowError::InvalidClock);
        };
        tokio::select! {biased;
            _=cancel.wait_for(|value|*value)=>break Err(FlowError::Cancelled),
            ()=tokio::time::sleep_until(end)=>break Err(FlowError::MaxAge),
            result=&mut copying=>break result.map(|_|()).map_err(|e|FlowError::Io(e.kind())),
            ()=tokio::time::sleep_until(deadline)=>{
                if activity.progress.load(Ordering::Relaxed)==last {break Err(FlowError::IdleTimeout);}
            },
        }
    };
    Completion {
        id: flow.metadata.id,
        backend: flow.metadata.backend,
        transferred: Transferred {
            sent: activity.sent.load(Ordering::Relaxed),
            received: activity.received.load(Ordering::Relaxed),
        },
        outcome,
    }
}
struct Activity {
    origin: Instant,
    progress: AtomicU64,
    sent: AtomicU64,
    received: AtomicU64,
}
impl Activity {
    fn progress(&self) {
        self.progress.store(
            self.origin.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            Ordering::Relaxed,
        );
    }
}
struct Tracked<'a> {
    inner: &'a mut TcpStream,
    activity: &'a Activity,
    written: &'a AtomicU64,
}
impl AsyncRead for Tracked<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buffer);
        if buffer.filled().len() > before {
            self.activity.progress();
        }
        result
    }
}
impl AsyncWrite for Tracked<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, bytes);
        if let Poll::Ready(Ok(count)) = result
            && count > 0
        {
            self.activity.progress();
            let _ = self
                .written
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |before| {
                    Some(before.saturating_add(count as u64))
                });
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
