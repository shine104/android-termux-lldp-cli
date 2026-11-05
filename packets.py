"""Offline Ethernet, VLAN, and LLDP decoding. No USB access."""
import ipaddress
import struct


class PacketError(ValueError):
    pass


def network_address(family, data):
    if family == 1:
        if len(data) != 4:
            raise PacketError('Invalid IPv4 address length')
        return str(ipaddress.IPv4Address(data))
    if family == 2:
        if len(data) != 16:
            raise PacketError('Invalid IPv6 address length')
        return str(ipaddress.IPv6Address(data))
    return None


def identifier(data, chassis):
    if not 2 <= len(data) <= 256 or not 1 <= data[0] <= 7:
        raise PacketError('Invalid LLDP identifier')
    subtype, raw = data[0], data[1:]
    mac_type, ip_type = (4, 5) if chassis else (3, 4)
    if subtype == mac_type:
        if len(raw) != 6:
            raise PacketError('Invalid MAC identifier')
        value = raw.hex(':')
    elif subtype == ip_type:
        value = network_address(raw[0], raw[1:]) or raw.hex()
    else:
        value = raw.decode('utf-8', 'replace')
    return dict(subtype=subtype, value=value, raw_hex=raw.hex())


def management(data):
    if not data or not 2 <= data[0] <= 31:
        raise PacketError('Invalid management address length')
    size = data[0]
    pos = 1 + size
    if len(data) < pos + 6:
        raise PacketError('Truncated management address')
    family = data[1]
    address = network_address(family, data[2:pos])
    oid_size = data[pos+5]
    if len(data) != pos + 6 + oid_size:
        raise PacketError('Invalid management OID length')
    return dict(family=family, address=address, raw_address_hex=data[2:pos].hex(),
        interface_subtype=data[pos], interface_number=int.from_bytes(data[pos+1:pos+5], 'big'),
        oid_hex=data[pos+6:].hex())


def ethernet_header(frame):
    """Parse the Ethernet envelope without retaining unrelated payloads."""
    if len(frame) < 14:
        raise PacketError('Truncated Ethernet header')
    ethertype = int.from_bytes(frame[12:14], 'big')
    offset = 14
    tags = []
    while ethertype in (0x8100, 0x88A8):
        if offset + 4 > len(frame) or len(tags) >= 4:
            raise PacketError('Invalid Ethernet VLAN tags')
        tci, next_type = struct.unpack_from('!HH', frame, offset)
        tags.append(dict(tpid=ethertype, tci=tci, vid=tci & 0xFFF, pcp=tci >> 13, dei=bool(tci & 0x1000)))
        ethertype = next_type
        offset += 4
    return ethertype, offset, tags


def decode_lldp(frame):
    """Return None for other EtherTypes; raise PacketError for malformed LLDP."""
    ethertype, offset, tags = ethernet_header(frame)
    if ethertype != 0x88CC:
        return None
    result = dict(destination_mac=frame[:6].hex(':'), source_mac=frame[6:12].hex(':'),
        ethernet_tags=tags, chassis_id=None, port_id=None, ttl=None, port_description=None,
        system_name=None, system_description=None, management_addresses=[], pvid=None,
        med_policies=[], voice_vlans=[], voice_signalling_vlans=[], unknown_tlvs=[])
    seen = set()
    mandatory_index = 0
    while offset < len(frame):
        if offset + 2 > len(frame):
            raise PacketError('Truncated TLV header')
        header = int.from_bytes(frame[offset:offset+2], 'big')
        kind, size = header >> 9, header & 0x1FF
        offset += 2
        if offset + size > len(frame):
            raise PacketError('Truncated TLV value')
        data = frame[offset:offset+size]
        offset += size
        if mandatory_index < 3:
            if kind != mandatory_index + 1:
                raise PacketError('Missing or unordered mandatory LLDP TLVs')
            mandatory_index += 1
        if kind in (1, 2, 3, 4, 5, 6, 7):
            if kind in seen:
                raise PacketError('Duplicate singleton LLDP TLV')
            seen.add(kind)
        if kind == 0:
            if size:
                raise PacketError('Invalid end TLV')
            result['shutdown'] = result['ttl'] == 0
            return result
        if kind in (1, 2):
            result['chassis_id' if kind == 1 else 'port_id'] = identifier(data, kind == 1)
        elif kind == 3:
            if size != 2:
                raise PacketError('Invalid TTL length')
            result['ttl'] = int.from_bytes(data, 'big')
        elif kind in (4, 5, 6):
            if size > 255:
                raise PacketError('Oversize LLDP text')
            result[{4: 'port_description', 5: 'system_name', 6: 'system_description'}[kind]] = data.decode('utf-8', 'replace')
        elif kind == 7:
            if size != 4:
                raise PacketError('Invalid capability length')
        elif kind == 8:
            result['management_addresses'].append(management(data))
        elif kind == 127:
            if size < 4:
                raise PacketError('Truncated organizational TLV')
            if data[:4] == bytes.fromhex('0080c201'):
                if size != 6 or result['pvid'] is not None:
                    raise PacketError('Invalid or duplicate PVID')
                pvid = int.from_bytes(data[4:], 'big')
                if pvid > 4094:
                    raise PacketError('Invalid PVID')
                result['pvid'] = pvid
            elif data[:4] == bytes.fromhex('0012bb02'):
                if size != 8:
                    raise PacketError('Invalid MED policy length')
                policy = int.from_bytes(data[4:], 'big')
                app = policy >> 24
                unknown, tagged = bool(policy & 0x800000), bool(policy & 0x400000)
                vid = (policy >> 9) & 0xFFF
                effective = vid if not unknown and tagged and 1 <= vid <= 4094 else None
                result['med_policies'].append(dict(application=app,
                    application_name={1: 'voice', 2: 'voice_signalling'}.get(app, 'other'),
                    unknown=unknown, tagged=tagged, advertised_vid=vid, vlan_id=effective,
                    priority=(policy >> 6) & 7, dscp=policy & 63))
                if effective is not None and app in (1, 2):
                    key = 'voice_vlans' if app == 1 else 'voice_signalling_vlans'
                    if effective not in result[key]:
                        result[key].append(effective)
            else:
                result['unknown_tlvs'].append(dict(type=kind, oui=data[:3].hex(), subtype=data[3]))
        else:
            result['unknown_tlvs'].append(dict(type=kind, length=size))
    raise PacketError('Missing end TLV')


def new_vlan_observations():
    return dict(duration_seconds=10, completed=False, tagged_frames=0,
        untagged_lldp_frames=0, untagged_other_frames=0,
        priority_tags=0, reserved_tags=0, vlans={},
        interpretation='Tags as delivered by the adapter; absence does not prove absence on the wire. Observations are not an allowed-VLAN inventory.')


def observe_vlans(observations, ethertype, tags):
    if not tags:
        key = 'untagged_lldp_frames' if ethertype == 0x88CC else 'untagged_other_frames'
        observations[key] += 1
        return
    observations['tagged_frames'] += 1
    # Count each VLAN once per frame, plus its positions in stacked tags.
    seen = set()
    for depth, tag in enumerate(tags):
        vid = tag['vid']
        if vid == 0:
            observations['priority_tags'] += 1
            continue
        if vid == 4095:
            observations['reserved_tags'] += 1
            continue
        entry = observations['vlans'].setdefault(str(vid), dict(frames=0, outer_tags=0, inner_tags=0))
        if vid not in seen:
            entry['frames'] += 1
            seen.add(vid)
        entry['outer_tags' if depth == 0 else 'inner_tags'] += 1
