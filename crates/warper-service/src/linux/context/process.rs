// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! PIDFD/procfs observation after the caller verifies the recorded PID scope.

use super::{Error, Process, ProcessState, open_proc, os_error, read_process};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::OwnedFd,
    io::{FdFlags, fcntl_getfd},
    process::{Pid, PidfdFlags, pidfd_open},
};

pub(super) fn inspect(recorded: Process) -> Result<ProcessState, Error> {
    let pid = i32::try_from(recorded.pid).map_err(|_| Error::InvalidRecord)?;
    let pid = Pid::from_raw(pid).ok_or(Error::InvalidRecord)?;
    let descriptor = match pidfd_open(pid, PidfdFlags::empty()) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::SRCH) => return Ok(ProcessState::Exited),
        Err(error) => return Err(os_error(error)),
    };
    if !fcntl_getfd(&descriptor)
        .map_err(os_error)?
        .contains(FdFlags::CLOEXEC)
    {
        return Err(Error::InvalidEvidence);
    }
    if exited(&descriptor)? {
        return Ok(ProcessState::Exited);
    }
    let proc = open_proc()?;
    let observed = read_process(&proc, &format!("{}/stat", recorded.pid), recorded.pid);
    match observed {
        Ok(observed) if observed.start_ticks != recorded.start_ticks => Ok(ProcessState::Reused),
        Ok(_) => Ok(if exited(&descriptor)? {
            ProcessState::Exited
        } else {
            ProcessState::Alive
        }),
        Err(error) => {
            // A leader's procfs view may disappear before its entire group is
            // gone. Only the kernel process descriptor can establish death.
            if exited(&descriptor)? {
                Ok(ProcessState::Exited)
            } else {
                Err(error)
            }
        }
    }
}
fn exited(descriptor: &OwnedFd) -> Result<bool, Error> {
    let mut descriptors = [PollFd::new(descriptor, PollFlags::IN)];
    poll(&mut descriptors, Some(&Timespec::default())).map_err(os_error)?;
    let events = descriptors[0].revents();
    if !(events - PollFlags::IN - PollFlags::HUP).is_empty() {
        return Err(Error::InvalidEvidence);
    }
    Ok(events.intersects(PollFlags::IN | PollFlags::HUP))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_self_process_and_changed_start_ticks_are_observations_only() {
        let proc = open_proc().unwrap();
        let current = read_process(&proc, "self/stat", std::process::id()).unwrap();
        assert_eq!(inspect(current), Ok(ProcessState::Alive));
        assert_eq!(
            inspect(Process {
                start_ticks: current.start_ticks.wrapping_add(1),
                ..current
            }),
            Ok(ProcessState::Reused)
        );
    }
    #[test]
    fn invalid_pid_cannot_open_a_process_descriptor() {
        for pid in [0, u32::MAX] {
            assert_eq!(
                inspect(Process {
                    pid,
                    start_ticks: 0
                }),
                Err(Error::InvalidRecord)
            );
        }
    }
    #[test]
    #[ignore = "controlled release workload"]
    fn native_process_observation_workload() {
        fn cpu_ns() -> i128 {
            let value = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
            i128::from(value.tv_sec) * 1_000_000_000 + i128::from(value.tv_nsec)
        }
        let proc = open_proc().unwrap();
        let current = read_process(&proc, "self/stat", std::process::id()).unwrap();
        let started = std::time::Instant::now();
        let cpu = cpu_ns();
        let mut latencies = Vec::with_capacity(1000);
        for _ in 0..1000 {
            let before = std::time::Instant::now();
            assert_eq!(inspect(current), Ok(ProcessState::Alive));
            latencies.push(before.elapsed().as_nanos());
        }
        let elapsed = started.elapsed().as_nanos();
        let cpu = cpu_ns() - cpu;
        latencies.sort_unstable();
        let memory = std::fs::read_to_string("/proc/self/status").unwrap();
        let peak = memory
            .lines()
            .find(|line| line.starts_with("VmHWM:"))
            .unwrap();
        println!(
            "iterations=1000 concurrency=1 elapsed_ns={elapsed} cpu_ns={cpu} p50_ns={} p95_ns={} p99_ns={} app_bytes=0 failures=0 {peak}",
            latencies[499], latencies[949], latencies[989]
        );
    }
}
