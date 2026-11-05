#!/data/data/com.termux/files/usr/bin/python
"""CDC-ECM LLDP and VLAN capture. Without --execute, inspect USB compatibility only."""
import argparse
import ctypes
from datetime import datetime, timezone
import errno
import fcntl
import json
import signal
import struct
import subprocess
import time

import diagnostic as d
from display import compact_summary, untagged_vlan_summary, summarize
from cdp import decode_cdp
from packets import decode_lldp, PacketError, ethernet_header, new_vlan_observations, observe_vlans


class Bulk(ctypes.Structure):
    _fields_ = [('ep', ctypes.c_uint), ('length', ctypes.c_uint),
                ('timeout', ctypes.c_uint), ('data', ctypes.c_void_p)]


class ECMUSB(d.ReadOnlyUSB):
    def configuration(self):
        return self.read(0x80, 8, 0, 0, 1)[0]

    def driver(self, interface):
        query = bytearray(struct.pack('=I256s', interface, b''))
        try:
            fcntl.ioctl(self.fd, d.ioctl_code(1, 8, 260), query, True)
        except OSError as exc:
            if exc.errno == errno.ENODATA:
                return None
            raise
        return bytes(query[4:]).split(b'\0', 1)[0].decode('ascii')

    def claim(self, interface, driver=None):
        if driver:
            if driver not in ('r8152', 'cdc_ether', 'r8153_ecm', 'cdc_ncm'):
                raise RuntimeError(f'Unexpected owner {driver!r} on interface {interface}; stop competing USB apps')
            query = bytearray(struct.pack('=II256s', interface, 1, driver.encode('ascii')))
            fcntl.ioctl(self.fd, d.ioctl_code(2, 27, 264), query, True)
        else:
            fcntl.ioctl(self.fd, d.ioctl_code(2, 15, 4), struct.pack('=I', interface))

    def release(self, interface):
        fcntl.ioctl(self.fd, d.ioctl_code(2, 16, 4), struct.pack('=I', interface))

    def set_configuration(self, value):
        if value not in (1, 2):
            raise ValueError('Configuration outside experiment allowlist')
        fcntl.ioctl(self.fd, d.ioctl_code(2, 5, 4), struct.pack('=I', value))

    def alternate(self, interface, value):
        if interface != 1 or value not in (0, 1):
            raise ValueError('Alternate setting outside experiment allowlist')
        fcntl.ioctl(self.fd, d.ioctl_code(2, 4, 8), struct.pack('=II', interface, value))

    def packet_filter(self, value):
        if value not in (0, 0x0E):
            raise ValueError('Only disabled or all-multicast/directed/broadcast filters permitted')
        # CDC SET_ETHERNET_PACKET_FILTER, control interface 0, no payload.
        control = d.Control(0x21, 0x43, value, 0, 0, 1000, None)
        count = fcntl.ioctl(self.fd, d.CONTROL, control, True)
        if count != 0:
            raise RuntimeError(f'Unexpected zero-length filter transfer result: {count}')

    def receive(self, timeout_ms):
        if ctypes.sizeof(Bulk) != 24 or Bulk.data.offset != 16:
            raise RuntimeError('Unexpected bulk ABI')
        buffer = ctypes.create_string_buffer(16384)
        control = Bulk(0x81, len(buffer), max(1, min(1000, timeout_ms)), ctypes.addressof(buffer))
        count = fcntl.ioctl(self.fd, d.ioctl_code(3, 2, 24), control, True)
        if not 0 <= count < len(buffer):
            raise RuntimeError('Invalid or potentially truncated ECM transfer')
        return buffer.raw[:count]


def inspect(usb):
    device = d.parse_device(usb.read(0x80, 6, 0x100, 0, 18))
    if (device['vid'], device['pid']) != ('0BDA', '8153'):
        raise ValueError('Expected Realtek 0BDA:8153')
    original = usb.configuration()
    if original not in (1, 2):
        raise ValueError(f'Unexpected active configuration {original}')
    configs = []
    for index in range(device['configuration_count']):
        header = usb.read(0x80, 6, 0x200 | index, 0, 9)
        if header[:2] != b'\x09\x02':
            raise ValueError('Invalid configuration descriptor')
        size = int.from_bytes(header[2:4], 'little')
        if size < 9:
            raise ValueError('Invalid descriptor total length')
        configs.append(d.parse_configuration(usb.read(0x80, 6, 0x200 | index, 0, size)))
    if len({c['value'] for c in configs}) != len(configs):
        raise ValueError('Duplicate configuration values')
    target = next((c for c in configs if c['value'] == 2), None)
    if target is None:
        raise ValueError('Configuration 2 absent')
    interfaces = target['interfaces']
    control = [i for i in interfaces if i['number'] == 0 and i['alternate'] == 0
               and i['interface_class'] == '02' and i['subclass'] == '06']
    idle = [i for i in interfaces if i['number'] == 1 and i['alternate'] == 0
            and i['interface_class'] == '0A']
    active = [i for i in interfaces if i['number'] == 1 and i['alternate'] == 1
              and i['interface_class'] == '0A']
    if len(control) != 1 or len(idle) != 1 or len(active) != 1:
        raise ValueError('Expected CDC-ECM control/data alternate settings absent')
    bulk = {e['address'] for e in active[0]['endpoints'] if e['transfer_type'] == 'bulk'}
    if bulk != {'0x81', '0x02'} or {i['number'] for i in interfaces} != {0, 1}:
        raise ValueError('Unexpected ECM endpoint or interface layout')
    source = next((c for c in configs if c['value'] == original), None)
    if source is None:
        raise ValueError('Active configuration not present in descriptors')
    bindings = {str(i): usb.driver(i) for i in sorted({x['number'] for x in source['interfaces']})}
    for name in bindings.values():
        if name not in (None, 'r8152', 'cdc_ether', 'r8153_ecm', 'cdc_ncm'):
            raise RuntimeError(f'USB owned by {name!r}; close competing USB apps before running')
    return dict(device=device, original_configuration=original, configurations=configs, bindings=bindings)


def read_ethernet_link(usb, baseline):
    """Optional native PHY snapshot, taken before any capture state changes."""
    result = dict(status='unavailable', phase='before_scan',
                  timestamp=datetime.now(timezone.utc).isoformat())
    if baseline['original_configuration'] != 1:
        result['reason'] = 'Native PHY reads require configuration 1'
        return result
    native = next(c for c in baseline['configurations'] if c['value'] == 1)
    if not any(i['number'] == 0 and i['interface_class'] == 'FF'
               for i in native['interfaces']):
        result['reason'] = 'Expected native vendor interface absent'
        return result
    try:
        def window(address):
            raw = usb.read(0xC0, 5, address, 0x100, 4)
            if len(raw) != 4:
                raise ValueError('Short PHY diagnostic register read')
            return int.from_bytes(raw, 'little')

        revision = d.decode_registers({0xE610: window(0xE610)})['revision']
        result['revision'] = revision
        if not revision['source_match']:
            result['reason'] = 'Controller revision not verified for link reporting'
            return result
        result.update(d.decode_registers({0xE908: window(0xE908)})['phy'])
        result['status'] = 'ok'
    except (OSError, RuntimeError, ValueError) as exc:
        result['error'] = d.error_info(exc, 'read_ethernet_link')
    return result


def run(usb, execute=False, clock=time.monotonic, persist=d.save_report, vlans=False):
    report = dict(kind='cdc_ecm_experiment', status='error', errors=[], events=[], cleanup_errors=[],
        timestamp=datetime.now(timezone.utc).isoformat(), lldp=None, detached=False,
        duration_seconds=10, elapsed_seconds=0, cdp_neighbors=[],
        counters=dict(transfers=0, timeouts=0, non_lldp=0, malformed=0),
        recovery='Unplug/reconnect the adapter if Android Ethernet does not recover; USB configuration restoration does not guarantee driver rebinding.')
    if vlans:
        report["vlan_observations"] = new_vlan_observations()
    claims = []
    original = None
    touched = False
    filter_attempted = False
    alternate_attempted = False
    stage = 'inspect'

    def claim(interface, owner):
        nonlocal touched
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
        try:
            usb.claim(interface, owner)
            claims.append(interface)
            touched = True
            if owner:
                report['detached'] = True
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)

    try:
        report['baseline'] = inspect(usb)
        original = report['baseline']['original_configuration']
        report['ethernet_link'] = read_ethernet_link(usb, report['baseline'])
        if not execute:
            report['status'] = 'ready_for_authorized_experiment'
            return report
        stage = 'save_baseline'
        report['baseline_log'] = str(persist(report))
        if original != 2:
            for number, owner in report['baseline']['bindings'].items():
                if owner is None:
                    continue
                interface = int(number)
                stage = f'detach_original_interface_{interface}'
                claim(interface, owner)
                stage = f'release_before_configuration_interface_{interface}'
                usb.release(interface)
                claims.remove(interface)
            stage = 'set_configuration_2'
            touched = True  # A failed request may still have affected device state.
            usb.set_configuration(2)
            stage = 'verify_configuration_2'
            actual = usb.configuration()
            report['configuration_after_switch'] = actual
            if actual != 2:
                raise RuntimeError(f'Configuration switch did not take effect: expected 2, got {actual}')
        else:
            report['configuration_after_switch'] = 2
        for interface in (0, 1):
            stage = f'get_driver_ecm_interface_{interface}'
            owner = usb.driver(interface)
            report['events'].append(dict(stage=stage, driver=owner))
            stage = f'claim_ecm_interface_{interface}'
            claim(interface, owner)
        stage = 'set_ecm_filter_before_alternate'
        filter_attempted = True
        usb.packet_filter(0x0E)
        stage = 'activate_data_interface_1_alternate_1'
        alternate_attempted = True
        usb.alternate(1, 1)
        stage = 'set_ecm_filter_after_alternate'
        usb.packet_filter(0x0E)
        report['status'] = 'no_lldp_observed'
        stage = 'receive_ecm'
        deadline = clock() + 10
        while True:
            remaining = deadline - clock()
            elapsed = max(0, 10 - remaining)
            report["elapsed_seconds"] = elapsed
            if remaining <= 0:
                if vlans:
                    report["vlan_observations"]["completed"] = True
                break
            try:
                data = usb.receive(min(1000, max(1, int(remaining * 1000))))
            except OSError as exc:
                if exc.errno == errno.ETIMEDOUT:
                    report['counters']['timeouts'] += 1
                    continue
                raise
            if not data:  # Zero-length packet is a delimiter, not an Ethernet frame.
                continue
            report['counters']['transfers'] += 1
            try:
                if vlans:
                    ethertype, _, tags = ethernet_header(data)
                    observe_vlans(report["vlan_observations"], ethertype, tags)
                if vlans:
                    cdp = decode_cdp(data)
                    if cdp is not None:
                        cdp['expires_elapsed'] = elapsed + cdp['ttl']
                        key = (cdp['source_mac'], cdp['device_id'], cdp['port_id'])
                        neighbors = report['cdp_neighbors']
                        neighbors[:] = [n for n in neighbors if
                            (n['source_mac'], n['device_id'], n['port_id']) != key]
                        if len(neighbors) < 256:
                            neighbors.append(cdp)
                        continue
                decoded = decode_lldp(data)  # ECM: no Realtek header and no FCS removal.
            except PacketError:
                report['counters']['malformed'] += 1
                continue
            if decoded is None:
                report['counters']['non_lldp'] += 1
                continue
            # Preserve the first discovery, as the quick command does. Later
            # minimal advertisements must not erase its optional switch fields.
            if report['lldp'] is None:
                report['lldp'] = dict(frame_hex=data.hex(), decoded=decoded,
                    timestamp=datetime.now(timezone.utc).isoformat(), transport='cdc_ecm')
            first = report['lldp']['decoded']
            if (decoded['source_mac'], decoded['chassis_id'], decoded['port_id']) == (first['source_mac'], first['chassis_id'], first['port_id']):
                report['lldp_expires_elapsed'] = elapsed + decoded['ttl']
            report['status'] = 'lldp_captured'
            if not vlans:
                break
    except KeyboardInterrupt:
        report['status'] = 'interrupted'
    except (OSError, RuntimeError, ValueError) as exc:
        report['status'] = 'error'
        report['errors'].append(d.error_info(exc, stage))
    finally:
        if execute and touched:
            # Defer additional termination signals until cleanup has finished.
            mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
            def cleanup(name, action):
                try:
                    result = action()
                    report['events'].append(dict(stage=name, result=result))
                    return True
                except (OSError, RuntimeError, ValueError) as exc:
                    report['cleanup_errors'].append(d.error_info(exc, name))
                    return False
            try:
                if filter_attempted and 0 in claims:
                    cleanup('disable_ecm_filter', lambda: usb.packet_filter(0))
                if alternate_attempted and 1 in claims:
                    cleanup('idle_data_interface', lambda: usb.alternate(1, 0))
                for interface in list(reversed(claims)):
                    if cleanup(f'release_interface_{interface}', lambda i=interface: usb.release(i)):
                        claims.remove(interface)
                report['unreleased_interfaces'] = list(claims)
                def restore():
                    actual = usb.configuration()
                    report['configuration_before_restore'] = actual
                    if actual != original:
                        if claims:
                            raise RuntimeError('Cannot restore configuration while releases are failing')
                        usb.set_configuration(original)
                    verified = usb.configuration()
                    report['configuration_after_restore'] = verified
                    if verified != original:
                        raise RuntimeError(f'Restore readback mismatch: expected {original}, got {verified}')
                    report['configuration_restored'] = True
                    report['final_bindings'] = {i: usb.driver(int(i)) for i in report['baseline']['bindings']}
                report['configuration_restored'] = False
                cleanup('restore_original_configuration', restore)
            finally:
                try:
                    signal.pthread_sigmask(signal.SIG_SETMASK, mask)
                except KeyboardInterrupt:
                    report['interrupted_during_cleanup'] = True
    elapsed = report['elapsed_seconds']
    for neighbor in report['cdp_neighbors']:
        neighbor['active'] = neighbor['ttl'] > 0 and neighbor['expires_elapsed'] > elapsed
    if report.get('lldp'):
        report['lldp_active'] = report.get('lldp_expires_elapsed', 0) > elapsed
    if report['status'] == 'no_lldp_observed' and any(n['active'] for n in report['cdp_neighbors']):
        report['status'] = 'cdp_captured'
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', help='Capture using USB configuration 2; temporarily interrupts Android Ethernet')
    parser.add_argument('--vlans', action='store_true', default=True, help=argparse.SUPPRESS)
    parser.add_argument('--verbose', action='store_true', help='Show diagnostic details and log path')
    parser.add_argument('--device')
    parser.add_argument('--fd', type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.fd is not None:
        def stop(signum, frame):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, stop)
        try:
            report = run(ECMUSB(args.fd), args.execute, vlans=args.vlans)
        except (OSError, ValueError, RuntimeError) as exc:
            report = dict(status='error', errors=[d.error_info(exc, 'open_fd')])
        report['log'] = str(d.save_report(report))
        print(json.dumps(report))
        return 0
    try:
        paths = json.loads(d.run_command(['termux-usb', '-l'], 12))
        if not isinstance(paths, list) or not all(isinstance(p, str) and
                d.re.fullmatch(r'/dev/bus/usb/\d+/\d+', p) for p in paths):
            raise ValueError('Invalid USB device list')
        path = args.device or (paths[0] if len(paths) == 1 else None)
        if path is None or path not in paths:
            raise ValueError('Connect the adapter or select a currently enumerated path with --device')
        try:
            permission = d.run_command(['termux-usb', path], 12)
        except RuntimeError as exc:
            if 'permission' not in str(exc).lower():
                raise
            permission = str(exc)
        if permission != 'Permission granted.':
            print('Please accept the Android USB permission dialog.', flush=True)
            permission = d.run_command(['termux-usb', '-r', path], 45)
            if permission != 'Permission granted.':
                raise PermissionError(errno.EACCES, permission)
        callback = 'ecm-execute.sh' if args.execute else 'ecm-prepare.sh'
        if args.vlans:
            callback = callback.replace('.sh', '-vlans.sh')
        if args.execute:
            print('Listening for ' + ('10 seconds (VLAN scan)' if args.vlans else 'LLDP (up to 10 seconds)') + '...', flush=True)
        report = json.loads(d.run_command(['termux-usb', '-e', str(d.ROOT/callback), path], 150))
        report['device_path'] = path
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        report = dict(status='error', errors=[d.error_info(exc, 'launch')])
    if args.verbose:
        summarize(report)
        print("Untagged VLAN:", untagged_vlan_summary(report))
        print("CDP neighbors:", json.dumps(report.get("cdp_neighbors", []), ensure_ascii=True))
        for error in report.get('errors', []):
            print('Failed operation:', error['stage'], 'errno:', error.get('errno'))
        for error in report.get('cleanup_errors', []):
            print('Recovery error:', error['stage'], error['message'])
        if 'configuration_restored' in report:
            print('Original configuration restored:', report['configuration_restored'])
            print('Final driver bindings:', report.get('final_bindings', 'unavailable'))
    else:
        compact_summary(report)
    log_path = d.save_report(report)
    if args.verbose:
        print('Log:', log_path)
    return 0 if report['status'] in ('ready_for_authorized_experiment', 'lldp_captured', 'cdp_captured') and not report.get('cleanup_errors') else 1


if __name__ == '__main__':
    raise SystemExit(main())
