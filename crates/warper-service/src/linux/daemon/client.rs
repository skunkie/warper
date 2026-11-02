// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use warper_control::admission::ClientPermit;

// Close the retained peer before releasing the session's final client lease.
struct Owner {
    peer: Arc<NativeStream>,
    session: Session,
}
pub(super) async fn run(
    stream: NativeStream,
    permit: ClientPermit,
    instance: [u8; 16],
    policy: watch::Receiver<Arc<OwnerPolicy>>,
    commands: mpsc::Sender<Command>,
    mut stop: watch::Receiver<bool>,
) -> Result<(), ClientError> {
    let peer = Arc::new(
        stream
            .try_clone()
            .map_err(|error| ClientError::Io(error.kind()))?,
    );
    let stream =
        tokio::net::UnixStream::from_std(stream).map_err(|error| ClientError::Io(error.kind()))?;
    let session = Session::admitted(stream, instance, permit).map_err(ClientError::Session)?;
    let mut owner = Owner { peer, session };
    loop {
        let deadline = Instant::now() + CONTROL_TIMEOUT;
        let current = policy.borrow().clone();
        owner
            .session
            .receive(&current, deadline, &mut stop)
            .await
            .map_err(ClientError::Session)?;
        let current = policy.borrow().clone();
        let request = owner
            .session
            .authorize(&current)
            .map_err(ClientError::Session)?;
        let (response, observe) = oneshot::channel();
        let command = Command::Dispatch {
            peer: owner.peer.clone(),
            request,
            response,
        };
        tokio::select! { biased;
            () = cancelled(&mut stop) => return Ok(()),
            () = sleep_until(deadline) => return Err(ClientError::Deadline),
            result = commands.send(command) => result.map_err(|_| ClientError::ActorLost)?,
        }
        let response = tokio::select! { biased;
            () = cancelled(&mut stop) => return Ok(()),
            () = sleep_until(deadline) => return Err(ClientError::Deadline),
            result = observe => result.map_err(|_| ClientError::ActorLost)?,
        };
        owner
            .session
            .respond(response.frame, Instant::now() + CONTROL_TIMEOUT, &mut stop)
            .await
            .map_err(ClientError::Session)?;
        drop(response.request);
    }
}
