"""Passive CDP decoding. Wire format/checksum reference: upstream lldpd cdp.c/frame.c."""
import struct
from packets import ethernet_header, PacketError


def checksum(data):
    total = sum((data[i] << 8) + data[i+1] for i in range(0, len(data)-1, 2))
    if len(data) & 1:
        last = data[-1]
        total += 0xff00 + last - 1 if last & 0x80 else last
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return ~total & 0xffff


def decode_cdp(frame):
    length, offset, tags = ethernet_header(frame)
    if frame[:6] != bytes.fromhex('01000ccccccc') or length > 1500:
        return None
    end = offset + length
    if end > len(frame) or length < 12:
        raise PacketError('Truncated CDP frame')
    if frame[offset:offset+8] != bytes.fromhex('aaaa0300000c2000'):
        return None
    payload = frame[offset+8:end]  # Exclude Ethernet padding from checksum.
    if payload[0] not in (1, 2) or checksum(payload):
        raise PacketError('Invalid CDP version or checksum')
    result = dict(source_mac=frame[6:12].hex(':'), version=payload[0], ttl=payload[1],
                  device_id=None, port_id=None, native_vlan=None)
    pos = 4
    seen = set()
    while pos < len(payload):
        if pos + 4 > len(payload):
            raise PacketError('Truncated CDP TLV')
        kind, size = struct.unpack_from('!HH', payload, pos)
        if size < 4 or pos + size > len(payload):
            raise PacketError('Invalid CDP TLV length')
        value = payload[pos+4:pos+size]
        pos += size
        if kind in (1, 3, 10):
            if kind in seen:
                raise PacketError('Duplicate CDP identity or native VLAN')
            seen.add(kind)
        if kind in (1, 3):
            if not value:
                raise PacketError('Empty CDP identity')
            result['device_id' if kind == 1 else 'port_id'] = value.decode('utf-8', 'replace')
        elif kind == 10:
            if len(value) != 2:
                raise PacketError('Invalid CDP native VLAN length')
            vlan = int.from_bytes(value, 'big')
            if not 1 <= vlan <= 4094:
                raise PacketError('Invalid CDP native VLAN')
            result['native_vlan'] = vlan
    if not result['device_id'] or not result['port_id']:
        raise PacketError('Missing CDP device or port ID')
    return result


def selected_cdp(report, lldp):
    """Only associate a unique active neighbor; never merge arbitrary devices."""
    neighbors = [n for n in report.get('cdp_neighbors', []) if n.get('active')]
    if lldp:
        neighbors = [n for n in neighbors if n['source_mac'] == lldp.get('source_mac')]
    return neighbors[0] if len(neighbors) == 1 else None
