// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! The supervisor keeps the native manager outside every observed future.

use super::{
    Controller, Error as NativeError, Failure, Manager, ip, ipv4, preserve, request, reserve,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::{Mutex, watch};
use warper_service::linux::dns_routes::queue::{Driver, Error};

pub(super) async fn exercise(
    manager: &Arc<Mutex<Manager>>,
    controller: &Controller,
    owner: &watch::Sender<bool>,
) -> Result<(), Failure> {
    if !ip(&["route", "show", "exact", "203.0.113.168/32"])?.is_empty() {
        return Err("owned driver test address is already routed".into());
    }
    if !matches!(Driver::owned(manager, 0), Err(Error::InvalidLimit)) || manager.try_lock().is_err()
    {
        return Err("rejected owned driver construction lost manager access".into());
    }
    let (mailbox, mut driver) = Driver::owned(manager, 1)?;
    let _: &(dyn Send + 'static) = &driver;
    let outcome = async {
        if !matches!(
            Driver::owned(manager, 1),
            Err(Error::Operation(NativeError::Busy))
        ) {
            return Err("owned native driver allowed a second exclusive owner".into());
        }
        if driver.enable_maintenance(Duration::ZERO, owner.subscribe()) != Err(Error::InvalidLimit)
        {
            return Err("owned driver accepted an invalid maintenance deadline".into());
        }
        driver.enable_maintenance(Duration::from_secs(2), owner.subscribe())?;
        if driver.enable_maintenance(Duration::from_secs(2), owner.subscribe())
            != Err(Error::Operation(NativeError::Busy))
        {
            return Err("owned driver allowed duplicate maintenance ownership".into());
        }
        let response = reserve(controller, &[ipv4(168)])?;
        let route = controller.response_route(&response, 0)?;
        let mut receipt = mailbox.submit(response, request(owner))?;
        let (cancelled, _) = watch::channel(true);
        if driver.run(request(&cancelled)).await != Err(Error::WaitCancelled)
            || manager.try_lock().is_ok()
            || mailbox.active() != 1
        {
            return Err("cancelled observation released accepted native ownership".into());
        }
        driver.close();
        driver.run(request(owner)).await?;
        if mailbox.active() != 1 {
            return Err("unconsumed native result lost its admission".into());
        }
        let mut response = receipt.wait(request(owner)).await?;
        if mailbox.active() != 0
            || controller.route_info(route)?.publication
                != warper_core::dns::lease::Publication::Committed
            || ip(&["route", "show", "exact", "203.0.113.168/32"])?.is_empty()
        {
            return Err("owned driver returned an uncommitted native result".into());
        }
        controller.cancel(&mut response)?;
        Ok::<_, Failure>(())
    }
    .await;
    // Close and join before releasing exclusive access. On observation error,
    // the supervisor Arc still retains the native task for outer cleanup.
    driver.close();
    let mut cleanup = Vec::new();
    if let Err(error) = driver.run(request(owner)).await {
        cleanup.push(Box::new(error) as Failure);
    }
    if let Some(failure) = driver.failure() {
        for error in failure.cleanup.into_iter().flatten() {
            cleanup.push(Box::new(error) as Failure);
        }
    }
    if let Some(error) = driver.join_error() {
        cleanup.push(Box::new(error) as Failure);
    }
    drop(driver);
    if manager.try_lock().is_err() {
        cleanup.push("owned native driver did not return exclusive access".into());
    }
    preserve(outcome, cleanup)?;
    println!(
        "PASS supervisor-owned DNS driver rejects duplicate access, retains cancelled observation and unconsumed results, commits a real route and returns its native manager for joined cleanup"
    );
    Ok(())
}
