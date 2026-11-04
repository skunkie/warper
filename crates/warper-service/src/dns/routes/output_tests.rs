// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

use super::{
    tests::{address, create, key},
    *,
};
use crate::dns::{Limits, Packet};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{oneshot, watch},
};
use warper_core::transport::{Error as TransportError, Request};

type TestError = Box<dyn std::error::Error + Send + Sync>;

fn response(controller: &Controller, deadline: Instant) -> (Response, Route) {
    let response = controller
        .reserve(
            RoutingMode::Mixed,
            key(7),
            &[Contribution {
                address: address(),
                expires_at: Duration::ZERO,
            }],
            deadline,
        )
        .unwrap();
    let route = controller.response_route(&response, 0).unwrap();
    controller.confirm_publication(route).unwrap();
    (response, route)
}
fn wire_response() -> (Packet, Vec<u8>, Limits) {
    let limits = Limits::new(512, 8).unwrap();
    let mut bytes = vec![0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    bytes.extend_from_slice(key(7).name.wire());
    bytes.extend_from_slice(&[0, 1, 0, 1]);
    let query = Packet::request(&bytes, limits).unwrap();
    bytes[2..4].copy_from_slice(&[0x81, 0x80]);
    bytes[7] = 1;
    bytes.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 192, 0, 2, 9]);
    let wire = Packet::response(&bytes, &query, limits)
        .unwrap()
        .encode()
        .unwrap();
    (query, wire, limits)
}

#[tokio::test(start_paused = true)]
async fn delivered_zero_ttl_frame_keeps_coverage_across_late_completion_observation() {
    let controller = Arc::new(create(&[]));
    let deadline = Instant::now() + Duration::from_secs(1);
    let (response, route) = response(&controller, deadline);
    let mut output = controller.begin_output(response).unwrap();
    let (query, wire, limits) = wire_response();
    let (mut stream, mut client) = tokio::io::duplex(1);
    let (written, observed) = oneshot::channel();
    let (finalize, ready) = oneshot::channel();
    let (_request_owner, cancellation) = watch::channel(false);
    let service_controller = controller.clone();
    let service = tokio::spawn(async move {
        Request {
            deadline,
            cancellation,
        }
        .run(async {
            stream
                .write_all(&(wire.len() as u16).to_be_bytes())
                .await
                .map_err(|error| TransportError::Io(error.kind()))?;
            stream
                .write_all(&wire)
                .await
                .map_err(|error| TransportError::Io(error.kind()))
        })
        .await?;
        written.send(()).map_err(|_| "output observer stopped")?;
        ready.await?;
        service_controller.complete_output(&mut output, Duration::from_secs(5))?;
        Ok::<_, TestError>(())
    });
    let observations = async {
        let length = client.read_u16().await?;
        let mut wire = vec![0; usize::from(length)];
        client.read_exact(&mut wire).await?;
        let packet = Packet::response(&wire, &query, limits)?;
        observed.await?;
        tokio::time::advance(Duration::from_secs(2)).await;
        controller.advance()?;
        let pending = controller.stats()?;
        let retirement = controller.begin_retirement(route);
        let first_connection = controller.selector().select_flow(address())?;
        let completed_at = Instant::now();
        finalize.send(()).map_err(|_| "output service stopped")?;
        Ok::<_, TestError>((
            wire,
            packet,
            pending,
            retirement,
            first_connection,
            completed_at,
        ))
    }
    .await;
    let joined = service.await;
    let (wire, packet, pending, retirement, first_connection, completed_at) = observations.unwrap();
    joined.unwrap().unwrap();
    assert_eq!(packet.question(), query.question());
    assert_eq!(
        u32::from_be_bytes(wire[wire.len() - 10..wire.len() - 6].try_into().unwrap()),
        0
    );
    assert_eq!(pending.responses, 1);
    assert_eq!(retirement, Err(Error::Ledger(lease::Error::Referenced)));
    assert_eq!(
        controller.next_expiry().unwrap(),
        Some(completed_at + Duration::from_secs(5))
    );
    assert_eq!(first_connection.backend(), BackendId(7));
    drop(first_connection);
    tokio::time::advance(Duration::from_secs(4)).await;
    let later_connection = controller.selector().select_flow(address()).unwrap();
    tokio::time::advance(Duration::from_secs(2)).await;
    controller.advance().unwrap();
    assert_eq!(controller.stats().unwrap().leases, 0);
    assert_eq!(controller.route_info(route).unwrap().flows, 1);
    drop(later_connection);
    controller.begin_retirement(route).unwrap();
    controller.finish_retirement(route).unwrap();
}

#[tokio::test(start_paused = true)]
async fn partial_frame_deadline_destroys_io_before_releasing_the_pending_reference() {
    let controller = Arc::new(create(&[]));
    let deadline = Instant::now() + Duration::from_secs(1);
    let (response, route) = response(&controller, deadline);
    let output = controller.begin_output(response).unwrap();
    let (_, wire, _) = wire_response();
    let (mut stream, mut client) = tokio::io::duplex(1);
    let (_request_owner, cancellation) = watch::channel(false);
    let service = tokio::spawn(async move {
        let result = Request {
            deadline,
            cancellation,
        }
        .run(async {
            stream
                .write_all(&(wire.len() as u16).to_be_bytes())
                .await
                .map_err(|error| TransportError::Io(error.kind()))?;
            stream
                .write_all(&wire)
                .await
                .map_err(|error| TransportError::Io(error.kind()))
        })
        .await;
        drop(stream);
        drop(output);
        result
    });
    let first_byte = client.read_u8().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    let result = service.await;
    assert_eq!(first_byte.unwrap(), 0);
    assert_eq!(result.unwrap(), Err(TransportError::Timeout));
    controller.advance().unwrap();
    assert_eq!(controller.stats().unwrap().responses, 0);
    assert_eq!(controller.stats().unwrap().leases, 0);
    assert_eq!(controller.next_expiry().unwrap(), None);
    controller.begin_retirement(route).unwrap();
    controller.finish_retirement(route).unwrap();
}
