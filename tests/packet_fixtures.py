"""Synthetic Ethernet/LLDP fixtures; never captured network traffic."""
import struct


def tlv(kind, value):
    return struct.pack('!H', (kind << 9) | len(value)) + value


def frame(extras=b'', tagged=False, ttl=120):
    eth = bytes.fromhex('0180c200000e020000000001')
    eth += bytes.fromhex('8100006488cc') if tagged else bytes.fromhex('88cc')
    body = tlv(1, b'\x04\x02\x00\x00\x00\x00\x01') + tlv(2, b'\x07port24') + tlv(3, struct.pack('!H', ttl))
    return (eth + body + extras + tlv(0, b'')).ljust(60, b'\0')


def policy(app, vid, tagged=True, unknown=False):
    value = (app << 24) | (unknown << 23) | (tagged << 22) | (vid << 9) | (5 << 6) | 46
    return tlv(127, bytes.fromhex('0012bb02') + value.to_bytes(4, 'big'))
