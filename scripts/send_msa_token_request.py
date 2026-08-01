#!/usr/bin/env python3

import argparse
import socket
import struct
import sys
from xml.sax.saxutils import escape


XML_MAGIC = 0x58445358
XML_MAGIC_V2 = 0x59445358
XSTS_TOKEN_REQUEST = 3


def build_xml(url: str) -> bytes:
    # Match serde PascalCase field naming in MSATokenRequest.
    xml = f"<?xml version=\"1.0\"?><MSATokenRequest><ClientId>{escape(url)}</ClientId></MSATokenRequest>"
    return xml.encode("utf-8")


def build_packet(payload: bytes, v2: bool) -> bytes:
    # v1 spells the payload size in a u16; v2 widens it to u32 under its own magic.
    if v2:
        return struct.pack("<IHI", XML_MAGIC_V2, XSTS_TOKEN_REQUEST, len(payload)) + payload

    if len(payload) > 0xFFFF:
        raise ValueError("Payload too large for the v1 u16 message_size field; use --v2")

    return struct.pack("<IHH", XML_MAGIC, XSTS_TOKEN_REQUEST, len(payload)) + payload


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Send an MSA_TOKEN_REQUEST XML message to a Unix socket"
    )
    parser.add_argument("socket_path", help="Path to Unix socket (for example /run/user/1000/xodus.sock)")
    parser.add_argument("clientid", help="ClientId field value for MSATokenRequest")
    parser.add_argument(
        "--v2",
        action="store_true",
        help="Use v2 framing (u32 message_size) instead of v1 (u16)",
    )
    args = parser.parse_args()

    payload = build_xml(args.clientid)
    packet = build_packet(payload, args.v2)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(args.socket_path)
            print(packet)
            sock.send(packet)
            response = sock.recv(64 * 1024)
            print("Response:", response)
    except OSError as exc:
        print(f"Failed to send request: {exc}", file=sys.stderr)
        return 1

    print(f"Sent {len(packet)} bytes to {args.socket_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
