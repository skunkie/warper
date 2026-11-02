// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::*;
use warper_control::runtime::{RuntimeLease, endpoint};

pub(super) fn run(
    mut commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
    policy: watch::Sender<Arc<OwnerPolicy>>,
    stop: watch::Receiver<bool>,
) -> Result<(), Error> {
    let mut lease = RuntimeLease::acquire().map_err(Error::Runtime)?;
    endpoint::recover(&mut lease).map_err(Error::Endpoint)?;
    let lease = Arc::new(lease);
    let (mut controller, effect) = Controller::open(
        lease.clone(),
        Request {
            deadline: Instant::now() + NATIVE_OBSERVATION,
            cancellation: stop.clone(),
        },
    )
    .map_err(Error::Controller)?;
    let endpoint = Arc::new(ControlEndpoint::bind(lease.clone()).map_err(Error::Publication)?);
    policy.send_replace(Arc::new(controller.policy().map_err(Error::Controller)?));
    let plan = controller.admission_plan().map_err(Error::Controller)?;
    events
        .blocking_send(Event::Boot {
            lease,
            listener: endpoint.clone_listener().map_err(Error::Endpoint)?,
            endpoint: endpoint.clone(),
            instance: controller.instance_id(),
            plan,
            effect,
        })
        .map_err(|_| Error::ChannelClosed)?;
    while let Some(command) = commands.blocking_recv() {
        if *stop.borrow() || stop.has_changed().is_err() {
            break;
        }
        let event = match command {
            Command::Shutdown => break,
            Command::Admit { stream, permit } => {
                let current = controller.policy().map_err(Error::Controller)?;
                match endpoint.authenticate_accepted(stream, &current) {
                    Ok(accepted) => Event::Admitted {
                        stream: accepted.stream,
                        permit,
                    },
                    Err(endpoint::Error::Peer(_)) => Event::RejectedPeer,
                    Err(error) => return Err(Error::Endpoint(error)),
                }
            }
            Command::Dispatch {
                peer,
                request,
                response,
            } => {
                let mut dispatch = controller
                    .dispatch(&peer, request.frame())
                    .map_err(Error::Controller)?;
                drop(peer);
                let current = controller
                    .policy()
                    .map_err(|secondary| Error::PolicyUpdate {
                        primary: dispatch.rejection.take().map(Box::new),
                        secondary: Box::new(secondary),
                    })?;
                policy.send_replace(Arc::new(current));
                Event::Reply {
                    dispatch,
                    request,
                    response,
                }
            }
            Command::Connected(epoch) => {
                controller.connected(epoch).map_err(Error::Controller)?;
                Event::Notified
            }
            Command::Finished { epoch, outcome } => {
                controller
                    .finished(epoch, &outcome)
                    .map_err(Error::Controller)?;
                Event::Finished(epoch)
            }
            Command::StartFailed { epoch, error } => {
                controller
                    .start_failed(epoch, error)
                    .map_err(Error::Controller)?;
                Event::StartFailed(epoch)
            }
        };
        events
            .blocking_send(event)
            .map_err(|_| Error::ChannelClosed)?;
    }
    // Main owns and signals the network; preserve durable desired intent.
    controller.shutdown();
    Ok(())
}
