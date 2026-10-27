#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Measure Linux UDP error-queue payloads for synthetic short ICMP quotes.

Run only in a disposable, single-UID mapped user and network namespace with
loopback enabled. The quoted packets and addresses are entirely synthetic.
"""

import errno
from pathlib import Path
import socket
import struct


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def run_case(ipv6):
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    address = "::1" if ipv6 else "127.0.0.1"
    level = socket.IPPROTO_IPV6 if ipv6 else socket.IPPROTO_IP
    receive_errors = 25 if ipv6 else 11  # IPV6_RECVERR / IP_RECVERR on Linux.
    protocol = socket.IPPROTO_ICMPV6 if ipv6 else socket.IPPROTO_ICMP
    with socket.socket(family, socket.SOCK_DGRAM) as receiver, socket.socket(
        family, socket.SOCK_DGRAM
    ) as sender, socket.socket(family, socket.SOCK_RAW, protocol) as router:
        receiver.bind((address, 0))
        sender.bind((address, 0))
        sender.connect(receiver.getsockname())
        sender.setsockopt(level, receive_errors, 1)
        payload = bytes(range(64))
        sender.sendall(payload)
        receiver.settimeout(1)
        if receiver.recv(128) != payload:
            raise RuntimeError("synthetic datagram was not delivered")
        udp = struct.pack(
            "!HHHH", sender.getsockname()[1], receiver.getsockname()[1], 72, 0
        )
        packed_address = socket.inet_pton(family, address)
        if ipv6:
            ip = struct.pack(
                "!IHBB16s16s", 6 << 28, 72, 17, 64, packed_address, packed_address
            )
        else:
            ip = struct.pack(
                "!BBHHHBBH4s4s",
                0x45, 0, 92, 1, 0, 64, 17, 0, packed_address, packed_address,
            )
            ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
        for length in (0, 4, 8, 15, 16):
            quote = ip + udp + payload[:length]
            message = struct.pack("!BBHI", 2 if ipv6 else 3, 0 if ipv6 else 4, 0, 1400) + quote
            if not ipv6:
                message = message[:2] + struct.pack("!H", checksum(message)) + message[4:]
            router.sendto(message, (address, 0))
            returned, controls, flags, destination = sender.recvmsg(
                2048, 512, socket.MSG_ERRQUEUE | socket.MSG_DONTWAIT
            )
            if returned != payload[:length] or destination[:2] != receiver.getsockname()[:2]:
                raise RuntimeError("error queue returned unexpected quote or destination")
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or not flags & socket.MSG_ERRQUEUE:
                raise RuntimeError("error queue report was truncated or misclassified")
            if len(controls) != 1 or controls[0][:2] != (level, receive_errors):
                raise RuntimeError("unexpected error queue control message")
            error, origin, kind, code, _, mtu, _ = struct.unpack_from("=IBBBBII", controls[0][2])
            if (error, origin, kind, code, mtu) != (errno.EMSGSIZE, 3 if ipv6 else 2, 2 if ipv6 else 3, 0 if ipv6 else 4, 1400):
                raise RuntimeError("unexpected ICMP error metadata")
            print(f"PASS ipv6={ipv6} quoted_payload_bytes={length} returned_bytes={len(returned)}")

        # Two sends precede both reports, so the first error is delayed until
        # after a distinct later operation has already used the same socket.
        first = bytearray(payload)
        first[:16] = bytes([4, 0, 0, 0, 17, 0, 0, 0, 29, 0, 0, 0, 0, 0, 0, 0])
        second = bytearray(first)
        second[8] += 1
        for packet in (first, second):
            sender.sendall(packet)
            if receiver.recv(128) != packet:
                raise RuntimeError("successive datagram was not delivered")
        for packet in (first, second):
            message = struct.pack("!BBHI", 2 if ipv6 else 3, 0 if ipv6 else 4, 0, 1400)
            message += ip + udp + packet[:16]
            if not ipv6:
                message = message[:2] + struct.pack("!H", checksum(message)) + message[4:]
            router.sendto(message, (address, 0))
            returned, controls, flags, destination = sender.recvmsg(
                2048, 512, socket.MSG_ERRQUEUE | socket.MSG_DONTWAIT
            )
            if (returned != packet[:16] or destination[:2] != receiver.getsockname()[:2]
                    or len(controls) != 1 or controls[0][:2] != (level, receive_errors)
                    or not flags & socket.MSG_ERRQUEUE
                    or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)):
                raise RuntimeError("delayed report did not retain its quoted header")
            error, origin, kind, code, _, mtu, _ = struct.unpack_from("=IBBBBII", controls[0][2])
            if (error, origin, kind, code, mtu) != (errno.EMSGSIZE, 3 if ipv6 else 2, 2 if ipv6 else 3, 0 if ipv6 else 4, 1400):
                raise RuntimeError("unexpected delayed ICMP error metadata")
        print(f"PASS ipv6={ipv6} delayed_report_preserves_original_header=true")


def main():
    uid_map = Path("/proc/self/uid_map").read_text().split()
    if len(uid_map) != 3 or uid_map[0] != "0" or uid_map[2] != "1":
        raise RuntimeError("requires a single-UID mapped user namespace")
    for ipv6 in (False, True):
        run_case(ipv6)


if __name__ == "__main__":
    main()
