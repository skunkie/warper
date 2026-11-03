// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Real protected dispatch and supervisor; this is not daemon/CLI acceptance.

use super::{
    application,
    configuration_installation::{encoded, with_ordinary_peer},
    fixture::{Failure, join_native, preserve},
    peers,
};
use std::{os::unix::net::UnixStream, sync::Arc, time::Duration};
use tokio::{
    sync::watch,
    time::{Instant, timeout},
};
use warper_control::{
    message::{Operation, OperationState, SessionState, Status},
    runtime::RuntimeLease,
    wire::{self, Code, Frame, Kind},
};
use warper_core::transport::Request;
use warper_service::{
    linux::{
        controller::{Controller, Dispatch, Effect},
        network::{self, Network, State},
    },
    native::Workers,
};

const SAMPLE: &str = "tunnel: {ip: 198.18.0.1, name: warper-ctrl}\nprotocols: [{socks5: {host: '127.0.0.1:1080', ips: [198.18.0.2/32]}}]\ntimeouts: {connect_ms: 3000, shutdown_ms: 4000}";

async fn native<F, T>(work: F) -> Result<T, Failure>
where
    F: FnOnce() -> Result<T, Failure> + Send + 'static,
    T: Send + 'static,
{
    let workers = Workers::new(1)?;
    let (owner, _) = watch::channel(false);
    let mut job = workers.try_reserve()?.start(work);
    join_native(&mut job, &owner).await?
}
fn dispatch(controller: &mut Controller, kind: Kind, body: Vec<u8>) -> Result<Dispatch, Failure> {
    let (peer, _client) = UnixStream::pair()?;
    Ok(controller.dispatch(&peer, &Frame::new(kind, 1, body)?)?)
}
fn accepted(dispatch: Dispatch, kind: Kind) -> Result<Dispatch, Failure> {
    if let Some(error) = dispatch.rejection {
        return Err(error.into());
    }
    if dispatch.reply.kind() != kind {
        return Err("controller reply kind differs".into());
    }
    Ok(dispatch)
}
fn rejection(dispatch: Dispatch, code: Code) -> Result<(), Failure> {
    if dispatch.rejection.as_ref().map(|error| error.code()) != Some(code)
        || dispatch.reply.kind() != Kind::ErrorReply
        || !matches!(dispatch.effect, Effect::None)
    {
        return Err(format!("controller rejection differs: {dispatch:?}").into());
    }
    Ok(())
}
fn status(controller: &mut Controller) -> Result<Status, Failure> {
    let reply = accepted(
        dispatch(controller, Kind::Status, vec![])?,
        Kind::StatusReply,
    )?;
    Ok(Status::decode(&reply.reply)?)
}
fn command(controller: &mut Controller, kind: Kind, nonce: u8) -> Result<Frame, Failure> {
    let status = status(controller)?;
    let id = wire::operation_id(status.desired_revision, [nonce; 8])?;
    let mut body = id.to_vec();
    body.extend_from_slice(&status.configuration_generation.to_be_bytes());
    body.extend_from_slice(&status.desired_revision.to_be_bytes());
    body.extend_from_slice(&controller.instance_id());
    Ok(Frame::new(kind, 1, body)?)
}
fn submit(controller: &mut Controller, frame: &Frame) -> Result<Dispatch, Failure> {
    let (peer, _client) = UnixStream::pair()?;
    Ok(controller.dispatch(&peer, frame)?)
}
fn install(controller: &mut Controller, capacity: usize) -> Result<(), Failure> {
    let status = status(controller)?;
    let mut body = status.configuration_generation.to_be_bytes().to_vec();
    body.extend_from_slice(
        encoded(&format!(
            "{SAMPLE}\nlimits: {{max_control_operations: {capacity}}}"
        ))?
        .expose(),
    );
    let reply = accepted(
        dispatch(controller, Kind::InstallConfig, body)?,
        Kind::ConfigReply,
    )?;
    if !matches!(reply.effect, Effect::AdmissionChanged(_)) {
        return Err("installation lost admission update".into());
    }
    Ok(())
}
fn operation(
    controller: &mut Controller,
    id: &[u8],
    expected: OperationState,
) -> Result<(), Failure> {
    let reply = accepted(
        dispatch(controller, Kind::OperationStatus, id.to_vec())?,
        Kind::OperationReply,
    )?;
    let operation = Operation::decode(&reply.reply)?;
    if operation.id != id || operation.state != expected {
        return Err("operation result differs".into());
    }
    Ok(())
}
fn enroll(controller: &mut Controller, owner: Option<u32>) -> Result<(), Failure> {
    let revision = status(controller)?.owner_revision;
    let mut body = revision.to_be_bytes().to_vec();
    body.extend_from_slice(&u32::from(owner.is_some()).to_be_bytes());
    body.extend_from_slice(&owner.unwrap_or(0).to_be_bytes());
    accepted(
        dispatch(controller, Kind::Enroll, body)?,
        Kind::EnrollmentReply,
    )?;
    Ok(())
}
fn authorization(controller: &mut Controller) -> Result<(), Failure> {
    enroll(controller, Some(1000))?;
    with_ordinary_peer(|peer| {
        let current = status(controller)?;
        accepted(
            controller.dispatch(peer, &Frame::new(Kind::Status, 1, vec![])?)?,
            Kind::StatusReply,
        )?;
        let down = command(controller, Kind::Disconnect, 11)?;
        let response = accepted(controller.dispatch(peer, &down)?, Kind::Accepted)?;
        if !matches!(response.effect, Effect::None) {
            return Err("idle owner Disconnect produced native action".into());
        }
        let mut body = current.configuration_generation.to_be_bytes().to_vec();
        body.extend_from_slice(b"malformed");
        rejection(
            controller.dispatch(peer, &Frame::new(Kind::InstallConfig, 2, body)?)?,
            Code::PermissionDenied,
        )?;
        for kind in [Kind::InspectRecovery, Kind::Recover] {
            rejection(
                controller.dispatch(peer, &Frame::new(kind, 2, vec![])?)?,
                Code::PermissionDenied,
            )?;
        }
        enroll(controller, None)?;
        rejection(
            controller.dispatch(peer, &Frame::new(Kind::Status, 3, vec![])?)?,
            Code::PermissionDenied,
        )?;
        rejection(controller.dispatch(peer, &down)?, Code::PermissionDenied)?;
        Ok(())
    })
}

async fn canceled_startup(runtime: Arc<RuntimeLease>) -> Result<Controller, Failure> {
    let (controller, epoch, configuration, down) = native(move || {
        let (_keep, cancellation) = watch::channel(false);
        let (mut controller, action) = Controller::open(
            runtime,
            Request {
                deadline: Instant::now() + Duration::from_secs(3),
                cancellation,
            },
        )?;
        if !matches!(action, Effect::None) {
            return Err("unexpected fixture boot intent".into());
        }
        accepted(
            dispatch(&mut controller, Kind::Hello, vec![])?,
            Kind::HelloReply,
        )?;
        authorization(&mut controller)?;
        install(&mut controller, 1)?;
        let up = command(&mut controller, Kind::Connect, 12)?;
        let accepted_up = accepted(submit(&mut controller, &up)?, Kind::Accepted)?;
        let Effect::Start {
            epoch,
            configuration,
        } = accepted_up.effect
        else {
            return Err("Connect did not produce Start".into());
        };
        let repeated = accepted(submit(&mut controller, &up)?, Kind::Accepted)?;
        if !matches!(repeated.effect, Effect::None) {
            return Err("repeated Connect produced another owner".into());
        }
        let concurrent = command(&mut controller, Kind::Connect, 13)?;
        rejection(submit(&mut controller, &concurrent)?, Code::Busy)?;
        let conflict = Frame::new(Kind::Disconnect, 1, up.body().to_vec())?;
        rejection(submit(&mut controller, &conflict)?, Code::Conflict)?;
        let down = command(&mut controller, Kind::Disconnect, 14)?;
        let accepted_down = accepted(submit(&mut controller, &down)?, Kind::Accepted)?;
        if !matches!(accepted_down.effect, Effect::Stop { epoch: stopped } if stopped == epoch) {
            return Err("Disconnect did not stop original epoch".into());
        }
        let repeated = accepted(submit(&mut controller, &down)?, Kind::Accepted)?;
        if !matches!(repeated.effect, Effect::None) {
            return Err("repeated Disconnect produced another action".into());
        }
        controller.connected(epoch)?;
        if status(&mut controller)?.state != SessionState::Disconnecting {
            return Err("superseded startup published Connected".into());
        }
        operation(&mut controller, &down.body()[..16], OperationState::Running)?;
        rejection(
            dispatch(
                &mut controller,
                Kind::OperationStatus,
                up.body()[..16].to_vec(),
            )?,
            Code::Conflict,
        )?;
        Ok((controller, epoch, configuration, down))
    })
    .await?;
    let mut network = Network::new(configuration)?;
    let (_stop, cancellation) = watch::channel(true);
    let (state, _) = watch::channel(State::Starting);
    let result = network.run(cancellation, &state).await;
    let controller = native(move || {
        let mut controller = controller;
        if !matches!(&result, Err(failure) if failure.primary == Some(network::Error::Cancelled) && failure.report.retired) {
            return match result { Err(error) => Err(error.into()), Ok(_) => Err("precanceled controller startup unexpectedly succeeded".into()) };
        }
        controller.finished(epoch, &result)?;
        if status(&mut controller)?.state != SessionState::Disconnected {
            return Err("canceled startup did not settle Disconnect".into());
        }
        operation(
            &mut controller,
            &down.body()[..16],
            OperationState::Succeeded,
        )?;
        // Even verified retirement cannot release a lease retained by its owner.
        let generation = status(&mut controller)?.configuration_generation;
        let mut body = generation.to_be_bytes().to_vec();
        body.extend_from_slice(encoded(SAMPLE)?.expose());
        rejection(
            dispatch(&mut controller, Kind::InstallConfig, body)?,
            Code::Busy,
        )?;
        Ok(controller)
    })
    .await?;
    drop(network);
    Ok(controller)
}

async fn interrupted_startup(controller: Controller) -> Result<Controller, Failure> {
    let (controller, epoch, configuration, up) = native(move || {
        let mut controller = controller;
        let up = command(&mut controller, Kind::Connect, 17)?;
        let action = accepted(submit(&mut controller, &up)?, Kind::Accepted)?;
        let Effect::Start {
            epoch,
            configuration,
        } = action.effect
        else {
            return Err("Connect did not produce Start".into());
        };
        if !matches!(controller.shutdown(), Effect::Stop { epoch: stopped } if stopped == epoch) {
            return Err("shutdown lost starting owner".into());
        }
        controller.connected(epoch)?;
        Ok((controller, epoch, configuration, up))
    })
    .await?;
    let mut network = Network::new(configuration)?;
    let (_stop, cancellation) = watch::channel(true);
    let (state, _) = watch::channel(State::Starting);
    let result = network.run(cancellation, &state).await;
    let controller = native(move || {
        let mut controller = controller;
        controller.finished(epoch, &result)?;
        operation(&mut controller, &up.body()[..16], OperationState::Failed)?;
        if status(&mut controller)?.state != SessionState::Disconnected {
            return Err("service shutdown did not retire startup".into());
        }
        Ok(controller)
    })
    .await?;
    drop(network);
    Ok(controller)
}

pub(super) async fn exercise(runtime: Arc<RuntimeLease>) -> Result<(), Failure> {
    let controller = canceled_startup(runtime).await?;
    let controller = interrupted_startup(controller).await?;
    let (controller, epoch, configuration, up) = native(move || {
        let mut controller = controller;
        install(&mut controller, 4)?;
        let up = command(&mut controller, Kind::Connect, 15)?;
        let action = accepted(submit(&mut controller, &up)?, Kind::Accepted)?;
        let Effect::Start {
            epoch,
            configuration,
        } = action.effect
        else {
            return Err("Connect did not produce Start".into());
        };
        Ok((controller, epoch, configuration, up))
    })
    .await?;
    let mut network = Network::new(configuration)?;
    let mut peers = peers().await?;
    let (stop, cancellation) = watch::channel(false);
    let (state, mut observed) = watch::channel(State::Starting);
    let mut task = tokio::spawn(async move {
        let result = network.run(cancellation, &state).await;
        (network, result)
    });
    let mut controller = Some(controller);
    let mut early = None;
    let mut down = None;
    let outcome = async {
        tokio::select! { biased;
            result = &mut task => { early = Some(result); return Err("controller network stopped before readiness".into()); },
            ready = timeout(Duration::from_secs(5), observed.wait_for(|state| *state == State::Connected)) => { drop(ready??); },
        }
        let owned = controller.take().ok_or("controller missing")?;
        let (owned, disconnect) = native(move || {
            let mut controller = owned;
            controller.connected(epoch)?;
            operation(&mut controller, &up.body()[..16], OperationState::Succeeded)?;
            if status(&mut controller)?.state != SessionState::Connected { return Err("controller did not publish readiness".into()); }
            let mut body = status(&mut controller)?.configuration_generation.to_be_bytes().to_vec();
            body.extend_from_slice(b"malformed");
            rejection(dispatch(&mut controller, Kind::InstallConfig, body)?, Code::Busy)?;
            let disconnect = command(&mut controller, Kind::Disconnect, 16)?;
            Ok((controller, disconnect))
        }).await?;
        controller = Some(owned);
        timeout(Duration::from_secs(5), application()).await??;
        if task.is_finished() || *observed.borrow() != State::Connected { return Err("requesting peer/application detach stopped service work".into()); }
        let owned = controller.take().ok_or("controller missing")?;
        let (owned, disconnect) = native(move || {
            let mut controller = owned;
            let accepted = accepted(submit(&mut controller, &disconnect)?, Kind::Accepted)?;
            if !matches!(accepted.effect, Effect::Stop { epoch: stopped } if stopped == epoch) { return Err("Disconnect lost original network epoch".into()); }
            operation(&mut controller, &disconnect.body()[..16], OperationState::Running)?;
            Ok((controller, disconnect))
        }).await?;
        controller = Some(owned);
        down = Some(disconnect);
        Ok::<_, Failure>(())
    }.await;
    stop.send_replace(true);
    let joined = match early {
        Some(result) => result,
        None => task.await,
    };
    let mut cleanup = Vec::new();
    match joined {
        Ok((mut network, result)) => {
            if let Some(mut owned) = controller.take() {
                let down = down.take();
                match native(move || {
                    let completion = owned.finished(epoch, &result);
                    if let Err(error) = result {
                        let secondary = completion
                            .err()
                            .map(|error| Box::new(error) as Failure)
                            .into_iter()
                            .collect();
                        return preserve(Err(Box::new(error) as Failure), secondary);
                    }
                    completion?;
                    if let Some(down) = down {
                        operation(&mut owned, &down.body()[..16], OperationState::Succeeded)?;
                        if status(&mut owned)?.state != SessionState::Disconnected {
                            return Err("Disconnect completion preceded verified retirement".into());
                        }
                    }
                    Ok(())
                })
                .await
                {
                    Ok(()) => {}
                    Err(error) => cleanup.push(error),
                }
            } else {
                cleanup.push("controller lost before joined network completion".into());
            }
            if let Err(error) = network.cleanup().await {
                cleanup.push(Box::new(error) as Failure);
            }
            drop(network);
        }
        Err(error) => cleanup.push(Box::new(error) as Failure),
    }
    if outcome.is_err() {
        peers.abort_all();
    }
    while !peers.is_empty() {
        match timeout(Duration::from_secs(1), peers.join_next()).await {
            Ok(Some(Ok(Ok(())))) => {}
            Ok(Some(Ok(Err(error)))) => {
                cleanup.push(error);
                peers.abort_all();
            }
            Ok(Some(Err(error))) if error.is_cancelled() => {}
            Ok(Some(Err(error))) => {
                cleanup.push(Box::new(error) as Failure);
                peers.abort_all();
            }
            Ok(None) => break,
            Err(error) => {
                cleanup.push(Box::new(error) as Failure);
                peers.abort_all();
            }
        }
    }
    preserve(outcome, cleanup)?;
    println!(
        "PASS native controller authorization, owner replacement, durable idempotence, one-record Disconnect, superseded readiness, retained approval and actual kernel TCP/FIN lifecycle"
    );
    Ok(())
}
