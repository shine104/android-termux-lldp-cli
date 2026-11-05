#!/data/data/com.termux/files/usr/bin/python
"""Read-only RTL8153 USB diagnostics; no claim, reset, write or capture API."""
import argparse
import ctypes
from datetime import datetime, timezone
import errno
import fcntl
import json
import os
from pathlib import Path
import platform
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
SOURCE_COMMIT = '168151cdb0f93d26557f9f3c7aae659b8d6b1863'
TARGET = (0x0BDA, 0x8153)
WINDOWS = (0xE610, 0xC010, 0xE810, 0xE908, 0xCD00, 0xCD04, 0xE858, 0xE84C, 0xE8DC)


class Control(ctypes.Structure):
    _fields_ = [('request_type', ctypes.c_uint8), ('request', ctypes.c_uint8),
                ('value', ctypes.c_uint16), ('index', ctypes.c_uint16),
                ('length', ctypes.c_uint16), ('timeout', ctypes.c_uint32),
                ('data', ctypes.c_void_p)]


def ioctl_code(direction, number, size):
    return (direction << 30) | (size << 16) | (ord('U') << 8) | number


CONTROL = ioctl_code(3, 0, ctypes.sizeof(Control))


def check_abi():
    if platform.machine() not in ('aarch64', 'arm64') or sys.byteorder != 'little':
        raise RuntimeError('Only the verified little-endian ARM64 ABI is supported')
    if (ctypes.sizeof(Control), Control.data.offset, CONTROL) != (24, 16, 0xC0185500):
        raise RuntimeError('Unexpected USB control ABI')


def multicast_hash_bit(mac):
    # Linux ether_crc: MSB-first CRC polynomial, LSB-first input bits,
    # initial all-ones and no final XOR.
    crc = 0xFFFFFFFF
    for octet in mac:
        for bit in range(8):
            carry = ((crc >> 31) ^ (octet >> bit)) & 1
            crc = (crc << 1) & 0xFFFFFFFF
            if carry:
                crc ^= 0x04C11DB7
    return crc >> 26


class ReadOnlyUSB:
    def __init__(self, fd):
        check_abi()
        os.fstat(fd)
        self.fd = fd

    def get_driver(self):
        query = bytearray(260)  # interface 0 followed by char driver[256]
        try:
            fcntl.ioctl(self.fd, ioctl_code(1, 8, len(query)), query, True)
        except OSError as exc:
            if exc.errno == errno.ENODATA:
                return dict(state='unbound', name=None)
            return dict(state='error', name=None, error=error_info(exc, 'get_driver'))
        name = bytes(query[4:]).split(b'\0', 1)[0].decode('ascii', 'strict')
        return dict(state='bound', name=name)

    def read(self, request_type, request, value, index, length):
        # Explicit allowlist: standard descriptor/configuration reads and verified
        # directly addressable PLA windows. No PHY bank/page-selection writes.
        allowed = (
            (request_type == 0x80 and request == 6 and index == 0
             and value >> 8 in (1, 2) and 1 <= length <= 65535)
            or (request_type, request, value, index, length) == (0x80, 8, 0, 0, 1)
            or (request_type == 0xC0 and request == 5 and value in WINDOWS
                and index == 0x100 and length == 4)
        )
        if not allowed:
            raise ValueError('Transfer outside diagnostic read allowlist')
        buf = ctypes.create_string_buffer(length)
        control = Control(request_type, request, value, index, length, 1000,
                          ctypes.addressof(buf))
        count = fcntl.ioctl(self.fd, CONTROL, control, True)
        if count != length:
            raise RuntimeError(f'Short USB read: expected {length}, received {count}')
        return buf.raw


def parse_device(data):
    if len(data) != 18 or data[:2] != b'\x12\x01':
        raise ValueError('Invalid USB device descriptor')
    vid, pid, release = struct.unpack_from('<HHH', data, 8)
    if data[17] == 0:
        raise ValueError('Device advertises zero configurations')
    return dict(vid=f'{vid:04X}', pid=f'{pid:04X}', release=f'{release:04X}',
                configuration_count=data[17])


def parse_configuration(data):
    if len(data) < 9 or data[0] != 9 or data[1] != 2:
        raise ValueError('Invalid configuration header')
    total = struct.unpack_from('<H', data, 2)[0]
    if total != len(data):
        raise ValueError('Configuration total length mismatch')
    result = dict(value=data[5], interface_count=data[4], interfaces=[])
    offset = 9
    interface = None
    seen = set()
    while offset < total:
        if offset + 2 > total:
            raise ValueError('Truncated descriptor header')
        length, kind = data[offset:offset+2]
        if length < 2 or offset + length > total:
            raise ValueError('Invalid descriptor length')
        d = data[offset:offset+length]
        if kind == 4:
            if length < 9:
                raise ValueError('Short interface descriptor')
            key = (d[2], d[3])
            if key in seen:
                raise ValueError('Duplicate interface alternate setting')
            seen.add(key)
            interface = dict(number=d[2], alternate=d[3], endpoint_count=d[4],
                             interface_class=f'{d[5]:02X}', subclass=f'{d[6]:02X}',
                             protocol=f'{d[7]:02X}', endpoints=[])
            result['interfaces'].append(interface)
        elif kind == 5:
            if length < 7 or interface is None:
                raise ValueError('Invalid endpoint descriptor')
            address = d[2]
            if any(e['address'] == f'0x{address:02X}' for e in interface['endpoints']):
                raise ValueError('Duplicate endpoint')
            interface['endpoints'].append(dict(address=f'0x{address:02X}',
                direction='IN' if address & 0x80 else 'OUT',
                transfer_type=('control', 'isochronous', 'bulk', 'interrupt')[d[3] & 3],
                max_packet_size=struct.unpack_from('<H', d, 4)[0] & 0x7FF))
        offset += length
    if len({i['number'] for i in result['interfaces']}) != result['interface_count']:
        raise ValueError('Interface count mismatch')
    for i in result['interfaces']:
        if len(i['endpoints']) != i['endpoint_count']:
            raise ValueError('Endpoint count mismatch')
    return result


def decode_registers(values):
    result = {}
    if 0xE610 in values:
        tcr1 = values[0xE610] >> 16
        signature = tcr1 & 0x7CF0
        result['revision'] = dict(tcr1=f'0x{tcr1:04X}', signature=f'0x{signature:04X}',
            driver_version='RTL_VER_14' if signature == 0x6400 else 'unmapped',
            family='RTL8153C' if signature == 0x6400 else 'unknown',
            source_match=signature == 0x6400)
    if 0xE810 in values:
        cr = (values[0xE810] >> 24) & 0xFF
        result['command'] = dict(address='0xE813', value=f'0x{cr:02X}',
            rx_enabled=bool(cr & 8), tx_enabled=bool(cr & 4), reset_bit=bool(cr & 16))
    if 0xC010 in values:
        rcr = values[0xC010]
        result['receive_filter'] = dict(accept_all_physical=bool(rcr & 1),
            accept_own_mac=bool(rcr & 2), accept_multicast=bool(rcr & 4),
            accept_broadcast=bool(rcr & 8),
            lldp_multicast_hash_verified=False)
    if 0xE908 in values:
        phy = values[0xE908] & 0xFF
        link = bool(phy & 2)
        speeds = [speed for bit, speed in ((0x10, 1000), (8, 100), (4, 10)) if phy & bit]
        result['phy'] = dict(address='0xE908', value=f'0x{phy:02X}', link_up=link,
            speed_mbps=speeds[0] if link and len(speeds) == 1 else None,
            full_duplex=bool(phy & 1) if link else None)
    if 0xE84C in values:
        oob = (values[0xE84C] >> 24) & 0xFF
        result['out_of_band'] = dict(address='0xE84F', value=f'0x{oob:02X}',
                                    active=bool(oob & 0x80))
    if 0xE8DC in values:
        result['sff_status'] = dict(address='0xE8DE',
                                   value=f'0x{(values[0xE8DC] >> 16) & 0xFFFF:04X}')
    if 0xE858 in values:
        misc = (values[0xE858] >> 16) & 0xFFFF
        result['receive_gate'] = dict(address='0xE85A', value=f'0x{misc:04X}',
                                      gated=bool(misc & 8))
    if all(a in values for a in (0xCD00, 0xCD04, 0xC010)):
        # Driver writes swab32(mc_filter[1]), then swab32(mc_filter[0]).
        high = int.from_bytes(values[0xCD00].to_bytes(4, 'little'), 'big')
        low = int.from_bytes(values[0xCD04].to_bytes(4, 'little'), 'big')
        bit = multicast_hash_bit(bytes.fromhex('0180c200000e'))
        selected = bool(((high << 32) | low) & (1 << bit))
        result['receive_filter'].update(lldp_multicast_hash_verified=True,
            lldp_hash_bit=bit, lldp_hash_selected=selected,
            lldp_admitted=bool(values[0xC010] & 4) and selected)
    return result


def error_info(exc, stage):
    hints = {errno.EACCES: 'Android USB permission is required.',
             errno.EPERM: 'Android denied this operation.',
             errno.ENODEV: 'Adapter disconnected; rediscover its path.',
             errno.ETIMEDOUT: 'USB read timed out; no register writes attempted.',
             errno.EPIPE: 'USB request stalled; no reset attempted.'}
    return dict(stage=stage, message=str(exc), errno=getattr(exc, 'errno', None),
                hint=hints.get(getattr(exc, 'errno', None)))


def diagnose(usb):
    report = dict(status='error', timestamp=datetime.now(timezone.utc).isoformat(),
                  source_commit=SOURCE_COMMIT, errors=[], configurations=[],
                  raw_registers={}, decoded={}, lldp='not_attempted',
                  ethernet_ip=dict(address=None, subnet=None, gateway=None, dns=None,
                      reason='No Ethernet-specific Android network evidence available'))
    stage = 'device_descriptor'
    try:
        device = parse_device(usb.read(0x80, 6, 0x100, 0, 18))
        report['device'] = device
        if (int(device['vid'], 16), int(device['pid'], 16)) != TARGET:
            report['status'] = 'not_target'
            return report
        stage = 'active_configuration'
        active = usb.read(0x80, 8, 0, 0, 1)[0]
        report['active_configuration'] = active
        stage = 'configuration_descriptors'
        for index in range(device['configuration_count']):
            head = usb.read(0x80, 6, 0x200 | index, 0, 9)
            if head[:2] != b'\x09\x02':
                raise ValueError('Invalid configuration header')
            total = struct.unpack_from('<H', head, 2)[0]
            if total < 9:
                raise ValueError('Invalid configuration total length')
            config = parse_configuration(usb.read(0x80, 6, 0x200 | index, 0, total))
            report['configurations'].append(config)
        configurations = report['configurations']
        if len({c['value'] for c in configurations}) != len(configurations):
            raise ValueError('Duplicate configuration values')
        if active != 1:
            raise ValueError(f'Active configuration {active}; vendor-register reads require configuration 1')
        selected = next((c for c in configurations if c['value'] == active), None)
        if selected is None or not any(i['number'] == 0 and i['interface_class'] == 'FF'
                                       for i in selected['interfaces']):
            raise ValueError('Expected vendor interface 0 absent from configuration 1')
        report['driver'] = usb.get_driver()
        if report['driver']['state'] == 'error':
            report['errors'].append(report['driver']['error'])
        values = {}
        for address in WINDOWS:
            try:
                raw = usb.read(0xC0, 5, address, 0x100, 4)
                values[address] = int.from_bytes(raw, 'little')
                report['raw_registers'][f'0x{address:04X}'] = dict(
                    bytes_hex=raw.hex(' '), little_endian_u32=f'0x{values[address]:08X}')
            except (OSError, RuntimeError, ValueError) as exc:
                report['errors'].append(error_info(exc, f'register_0x{address:04X}'))
                if getattr(exc, 'errno', None) in (errno.ENODEV, errno.EBADF):
                    break
        report['decoded'] = decode_registers(values)
        report['status'] = 'partial' if report['errors'] else 'ok'
    except (OSError, RuntimeError, ValueError) as exc:
        report['errors'].append(error_info(exc, stage))
    return report


def save_report(report):
    directory = ROOT / 'logs'
    directory.mkdir(mode=0o700, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    path = directory / f'diagnostic-{stamp}-{os.getpid()}.json'
    with path.open('x') as out:
        os.chmod(path, 0o600)
        json.dump(report, out, indent=2)
        out.write('\n')
    return path


def summarize(report):
    print(f"Diagnostic: {report['status']}")
    print('USB configuration:', report.get('active_configuration', 'unavailable'))
    decoded = report.get('decoded', {})
    revision = decoded.get('revision', {})
    print('Controller:', revision.get('family', 'unavailable'), revision.get('signature', ''))
    phy = decoded.get('phy')
    if phy:
        print('Ethernet link:', 'UP' if phy['link_up'] else 'DOWN',
              f"{phy['speed_mbps']} Mbps" if phy['speed_mbps'] else '(speed unavailable)')
    command = decoded.get('command')
    if command:
        print(f"Receiver enabled: {command['rx_enabled']}; transmitter enabled: {command['tx_enabled']}")
    print('Driver:', report.get('driver', {}))
    print('Receive gating:', decoded.get('receive_gate', {}).get('gated', 'unavailable'))
    print('LLDP filter admitted:', decoded.get('receive_filter', {}).get('lldp_admitted', 'unavailable'))
    print('Ethernet IP/DHCP: unavailable; LLDP: not attempted')
    for error in report.get('errors', []):
        print(f"ERROR [{error['stage']}]: {error['message']}")


def run_command(args, timeout):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError((result.stdout + result.stderr).strip() or f'Command failed: {args[0]}')
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', help='Select a path returned by termux-usb -l')
    parser.add_argument('--fd', type=int, help=argparse.SUPPRESS)
    parser.add_argument('--no-prompt', action='store_true', help='Do not request Android USB permission')
    args = parser.parse_args()
    if args.fd is not None:
        try:
            report = diagnose(ReadOnlyUSB(args.fd))
        except (OSError, RuntimeError, ValueError) as exc:
            report = dict(status='error', errors=[error_info(exc, 'open_fd')])
        print(json.dumps(report))
        # termux-usb does not reliably propagate callback exit codes. The parent
        # evaluates the explicit JSON status instead.
        return 0
    report = dict(status='error', timestamp=datetime.now(timezone.utc).isoformat(),
                  source_commit=SOURCE_COMMIT, errors=[], attempts=[])
    try:
        paths = json.loads(run_command(['termux-usb', '-l'], 12))
        if not isinstance(paths, list) or not all(isinstance(p, str) and
                re.fullmatch(r'/dev/bus/usb/\d+/\d+', p) for p in paths):
            raise ValueError('Unexpected USB device list')
        if args.device:
            if args.device not in paths:
                raise ValueError('Selected device is not currently enumerated')
            paths = [args.device]
        if not paths:
            raise RuntimeError('No USB devices found; attach the adapter and retry')
        matches = []
        for path in paths:
            attempt = dict(device_path=path)
            try:
                # Ask only if the permission probe reports denial.
                try:
                    permission = run_command(['termux-usb', path], 12)
                except RuntimeError as exc:
                    if 'permission' not in str(exc).lower():
                        raise
                    permission = str(exc)
                if permission != 'Permission granted.':
                    if args.no_prompt:
                        raise PermissionError(errno.EACCES, permission)
                    print(f'Android USB permission needed for {path}; accept the phone dialog.', flush=True)
                    permission = run_command(['termux-usb', '-r', path], 45)
                    if permission != 'Permission granted.':
                        raise PermissionError(errno.EACCES, permission)
                output = run_command(['termux-usb', '-e', str(ROOT/'usb-callback.sh'), path], 40)
                child = json.loads(output)
                if not isinstance(child, dict) or 'status' not in child:
                    raise ValueError('Invalid USB callback result')
                attempt.update(child)
                if child.get('device', {}).get('vid') == '0BDA' and child.get('device', {}).get('pid') == '8153':
                    matches.append(attempt)
            except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
                attempt.update(status='error', errors=[error_info(exc, 'usb_access')])
            report['attempts'].append(attempt)
        if len(matches) == 1:
            attempts = report['attempts']
            report.update(matches[0])
            report['attempts'] = attempts
        elif len(matches) > 1:
            raise RuntimeError('Multiple RTL8153 adapters found; select one with --device')
        else:
            raise RuntimeError('No accessible RTL8153 adapter validated; see per-device errors')
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        report['errors'].append(error_info(exc, 'discovery'))
    summarize(report)
    for attempt in report['attempts']:
        if attempt.get('errors') and attempt.get('device_path') != report.get('device_path'):
            print(attempt['device_path'], json.dumps(attempt['errors']))
    print('Log:', save_report(report))
    return 0 if report['status'] == 'ok' else 1


if __name__ == '__main__':
    raise SystemExit(main())
