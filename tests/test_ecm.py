"""Synthetic ECM frames and mocked USB state; no hardware is touched by tests."""
import errno
import json
import struct
import sys
from pathlib import Path
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import diagnostic as d
import ecm_capture as e
from test_diagnostic import device, configuration
from packet_fixtures import frame, tlv


def ecm_descriptor():
    body = bytes([9,4,0,0,1,2,6,0,0]) + struct.pack('<BBBBHB',7,5,0x83,3,16,8)
    body += bytes([9,4,1,0,0,10,0,0,0, 9,4,1,1,2,10,0,0,0])
    body += struct.pack('<BBBBHB',7,5,0x81,2,1024,0) + struct.pack('<BBBBHB',7,5,2,2,1024,0)
    return struct.pack('<BBHBBBBB',9,2,len(body)+9,2,2,0,0x80,50) + body


class USB:
    def __init__(self, fail=None, wrong_readback=False, receive_error=None):
        self.config = 1
        self.owners = {0:'r8152'}
        self.claimed = set()
        self.calls = []
        self.fail = fail
        self.wrong_readback = wrong_readback
        self.receive_error = receive_error
        self.frames = [frame(tlv(5, b'SYNTHETIC-ECM'))]
        self.registers = {0xE610: 0x67000880, 0xE908: 0x93}

    def record(self, op, *args):
        self.calls.append((op, *args))
        if (op, *args) == self.fail:
            raise OSError(errno.EACCES, 'synthetic injected denial')

    def read(self, kind, request, value, index, length):
        self.record('read', kind, request, value, index, length)
        if kind == 0xC0:
            return self.registers[value].to_bytes(4, 'little')
        if value == 0x100:
            raw = bytearray(device()); raw[17] = 2
            return bytes(raw)
        return (configuration() if value == 0x200 else ecm_descriptor())[:length]

    def configuration(self):
        self.record('configuration')
        return self.config

    def driver(self, interface):
        self.record('driver', interface)
        return self.owners.get(interface)

    def claim(self, interface, driver):
        self.record('claim', interface, driver)
        self.claimed.add(interface)
        self.owners[interface] = None

    def release(self, interface):
        self.record('release', interface)
        self.claimed.remove(interface)

    def set_configuration(self, value):
        self.record('set_configuration', value)
        if self.claimed:
            raise RuntimeError('Cannot switch with claims held')
        if not self.wrong_readback:
            self.config = value
        self.owners = {0:None, 1:None} if self.config == 2 else {0:None}

    def packet_filter(self, value):
        self.record('filter', value)

    def alternate(self, interface, value):
        self.record('alternate', interface, value)

    def receive(self, timeout):
        self.record('receive', timeout)
        if self.receive_error:
            raise self.receive_error
        return self.frames.pop(0)


def run(usb, clock=lambda: 0):
    return e.run(usb, execute=True, clock=clock, persist=lambda r:'synthetic-baseline')


class ECMTests(unittest.TestCase):
    def test_link_snapshot_before_detach(self):
        usb = USB()
        r = run(usb)
        self.assertEqual(r['ethernet_link']['speed_mbps'], 1000)
        self.assertTrue(r['ethernet_link']['full_duplex'])
        self.assertEqual(r['ethernet_link']['phase'], 'before_scan')
        self.assertIn('timestamp', r['ethernet_link'])
        reads = [i for i, c in enumerate(usb.calls) if c[:2] == ('read', 0xC0)]
        first_claim = next(i for i, c in enumerate(usb.calls) if c[0] == 'claim')
        self.assertEqual(len(reads), 2)
        self.assertLess(max(reads), first_claim)

    def test_optional_link_failures_do_not_block_capture(self):
        for address in (0xE610, 0xE908):
            with self.subTest(address=address):
                usb = USB(fail=('read', 0xC0, 5, address, 0x100, 4))
                r = run(usb)
                self.assertEqual(r['ethernet_link']['status'], 'unavailable')
                self.assertIn('error', r['ethernet_link'])
                self.assertEqual(r['status'], 'lldp_captured')
                self.assertEqual(r['errors'], [])
                self.assertTrue(r['configuration_restored'])

    def test_unknown_revision_skips_phy(self):
        usb = USB(); usb.registers[0xE610] = 0x12340000
        r = run(usb)
        self.assertEqual(r['ethernet_link']['status'], 'unavailable')
        self.assertNotIn(('read', 0xC0, 5, 0xE908, 0x100, 4), usb.calls)
        self.assertEqual(r['status'], 'lldp_captured')

    def test_ecm_configuration_skips_vendor_reads(self):
        usb = USB(); usb.config = 2; usb.owners = {0: None, 1: None}
        r = run(usb)
        self.assertEqual(r['ethernet_link']['status'], 'unavailable')
        self.assertFalse(any(c[:2] == ('read', 0xC0) for c in usb.calls))
        self.assertEqual(r['status'], 'lldp_captured')

    def test_short_link_read_is_optional(self):
        usb = USB(); baseline = e.inspect(usb)
        with patch.object(usb, 'read', return_value=b'\x00'):
            link = e.read_ethernet_link(usb, baseline)
        self.assertEqual(link['status'], 'unavailable')
        self.assertIn('Short', link['error']['message'])

    def test_preparation_is_read_only(self):
        usb = USB()
        self.assertEqual(e.run(usb)['status'], 'ready_for_authorized_experiment')
        self.assertTrue(all(c[0] in ('read','configuration','driver') for c in usb.calls))

    def test_success_ecm_frame_unmodified_and_restore(self):
        usb = USB()
        expected = usb.frames[0]
        r = run(usb)
        self.assertEqual(r['status'], 'lldp_captured')
        self.assertEqual(bytes.fromhex(r['lldp']['frame_hex']), expected)
        self.assertEqual(r['lldp']['decoded']['system_name'], 'SYNTHETIC-ECM')
        self.assertTrue(r['configuration_restored'])
        self.assertEqual(usb.config, 1)
        self.assertEqual(usb.claimed, set())
        self.assertEqual([c for c in usb.calls if c[0]=='filter'], [('filter',14),('filter',14),('filter',0)])

    def test_switch_rejected_exact_errno_no_claim_ecm(self):
        usb = USB(fail=('set_configuration',2))
        r = run(usb)
        self.assertEqual(r['errors'][0]['stage'], 'set_configuration_2')
        self.assertEqual(r['errors'][0]['errno'], errno.EACCES)
        self.assertFalse(any(c[0]=='receive' or (c[0]=='claim' and c[1]==1) for c in usb.calls))
        self.assertTrue(r['configuration_restored'])

    def test_wrong_readback_stops_before_claim(self):
        usb = USB(wrong_readback=True)
        r = run(usb)
        self.assertEqual(r['errors'][0]['stage'], 'verify_configuration_2')
        self.assertFalse(any(c[0]=='claim' and c[1]==1 for c in usb.calls))

    def test_claim_failure_releases_control(self):
        usb = USB(fail=('claim',1,None))
        r = run(usb)
        self.assertEqual(r['errors'][0]['stage'], 'claim_ecm_interface_1')
        self.assertEqual(usb.claimed,set())
        self.assertTrue(r['configuration_restored'])

    def test_filter_and_alternate_rejections_restore(self):
        for failure, stage in [(('filter',14),'set_ecm_filter_before_alternate'),
                               (('alternate',1,1),'activate_data_interface_1_alternate_1')]:
            usb = USB(fail=failure)
            r = run(usb)
            self.assertEqual(r['errors'][0]['stage'],stage)
            self.assertFalse(any(c[0]=='receive' for c in usb.calls))
            self.assertEqual(usb.claimed,set())
            self.assertTrue(r['configuration_restored'])

    def test_timeout_has_deadline(self):
        usb = USB(receive_error=OSError(errno.ETIMEDOUT,'timeout'))
        r = run(usb,clock=iter([0,0,60]).__next__)
        self.assertEqual(r['status'],'no_lldp_observed')
        self.assertEqual(r['counters']['timeouts'],1)
        self.assertTrue(r['configuration_restored'])

    def test_interrupt_and_unplug_cleanup(self):
        for exc, status in [(KeyboardInterrupt(),'interrupted'),(OSError(errno.ENODEV,'unplug'),'error')]:
            usb = USB(receive_error=exc)
            r = run(usb)
            self.assertEqual(r['status'],status)
            self.assertEqual(usb.claimed,set())

    def test_restore_failure_preserves_success(self):
        usb = USB(fail=('set_configuration',1))
        r = run(usb)
        self.assertEqual(r['status'],'lldp_captured')
        self.assertFalse(r['configuration_restored'])
        self.assertEqual(r['cleanup_errors'][0]['stage'],'restore_original_configuration')

    def test_original_configuration_2(self):
        usb = USB(); usb.config=2; usb.owners={0:'cdc_ether',1:'cdc_ether'}
        r=run(usb)
        self.assertTrue(r['configuration_restored'])
        self.assertEqual(usb.config,2)
        self.assertFalse(any(c[0]=='set_configuration' for c in usb.calls))

    def test_unknown_owner_stops(self):
        usb=USB(); usb.owners={0:'usbfs'}
        r=run(usb)
        self.assertEqual(r['status'],'error')
        self.assertFalse(any(c[0]=='claim' for c in usb.calls))

    def test_unrelated_payload_not_logged(self):
        usb=USB()
        unrelated=bytes.fromhex('ffffffffffff0200000000010800')+b'SECRET_OTHER_PAYLOAD'
        usb.frames.insert(0,unrelated)
        r=run(usb)
        self.assertEqual(r['counters']['non_lldp'],1)
        self.assertNotIn(unrelated.hex(),json.dumps(r))

    def test_vlan_scan_continues_after_lldp_and_preserves_privacy(self):
        usb = USB()
        raw = bytes.fromhex('ffffffffffff0200000000010800') + b'PRIVATE_PAYLOAD'
        tagged = raw[:12] + bytes.fromhex('88a80064810000c8') + raw[12:]
        usb.frames += [tagged, raw, raw[:12] + bytes.fromhex('8100a000') + raw[12:]]
        r = e.run(usb, execute=True, vlans=True,
            clock=iter([0,0,1,2,3,60]).__next__, persist=lambda r:'synthetic')
        o = r['vlan_observations']
        self.assertTrue(o['completed'])
        self.assertEqual(o['untagged_lldp_frames'], 1)
        self.assertEqual(o['untagged_other_frames'], 1)
        self.assertEqual(o['tagged_frames'], 2)
        self.assertEqual(o['priority_tags'], 1)
        self.assertEqual(o['vlans']['100'], dict(frames=1, outer_tags=1, inner_tags=0))
        self.assertEqual(o['vlans']['200'], dict(frames=1, outer_tags=0, inner_tags=1))
        self.assertNotIn('0', o['vlans'])
        self.assertNotIn(b'PRIVATE_PAYLOAD'.hex(), json.dumps(r))
        self.assertNotIn('PRIVATE_PAYLOAD', json.dumps(r))
        self.assertTrue(r['configuration_restored'])
        self.assertEqual(usb.claimed, set())
        self.assertEqual(r['status'], 'lldp_captured')

    def test_vlan_scan_malformed_and_reserved_tags(self):
        usb = USB()
        usb.frames = [b'short', bytes.fromhex('ffffffffffff020000000001810000'),
            bytes.fromhex('ffffffffffff02000000000181000fff0800')]
        r = e.run(usb, execute=True, vlans=True,
            clock=iter([0,0,1,2,60]).__next__, persist=lambda r:'synthetic')
        self.assertEqual(r['counters']['malformed'], 2)
        self.assertEqual(r['vlan_observations']['reserved_tags'], 1)
        self.assertEqual(r['vlan_observations']['vlans'], {})
        self.assertTrue(r['configuration_restored'])

    def test_vlan_scan_timeout_and_interrupt(self):
        for exc in (OSError(errno.ETIMEDOUT, 'timeout'), OSError(errno.ENODEV, 'unplug'), KeyboardInterrupt()):
            usb = USB(receive_error=exc)
            r = e.run(usb, execute=True, vlans=True,
                clock=iter([0,0,60]).__next__, persist=lambda r:'synthetic')
            self.assertEqual(r['vlan_observations']['completed'],
                isinstance(exc, OSError) and exc.errno == errno.ETIMEDOUT)
            self.assertTrue(r['configuration_restored'])
            self.assertEqual(usb.claimed, set())

    def test_vlan_scan_preserves_first_discovery(self):
        usb = USB()
        usb.frames += [frame()]
        r = e.run(usb, execute=True, vlans=True,
            clock=iter([0,0,1,60]).__next__, persist=lambda r:'synthetic')
        self.assertEqual(r['lldp']['decoded']['system_name'], 'SYNTHETIC-ECM')
        self.assertEqual(r['vlan_observations']['untagged_lldp_frames'], 2)
        self.assertTrue(r['configuration_restored'])

    def test_vlan_callbacks_forward_mode(self):
        root = Path(e.__file__).parent
        for mode in ('execute', 'prepare'):
            callback = root / ('ecm-' + mode + '-vlans.sh')
            text = callback.read_text()
            self.assertIn('--vlans', text)
            self.assertIn('--fd "$1"', text)
            self.assertEqual('--execute' in text, mode == 'execute')

    def test_wire_allowlist(self):
        with open('/dev/null','rb') as f, patch.object(e.fcntl,'ioctl',return_value=0) as ioctl:
            usb=e.ECMUSB(f.fileno())
            usb.set_configuration(2)
            self.assertEqual(ioctl.call_args.args[1],0x80045505)
            usb.alternate(1,1)
            self.assertEqual(ioctl.call_args.args[1],0x80085504)
            usb.packet_filter(14)
            ctrl=ioctl.call_args.args[2]
            self.assertEqual((ctrl.request_type,ctrl.request,ctrl.value,ctrl.index,ctrl.length),(0x21,0x43,14,0,0))
            with self.assertRaises(ValueError): usb.packet_filter(31)
            with self.assertRaises(ValueError): usb.set_configuration(3)
            with self.assertRaises(ValueError): usb.alternate(0,1)


if __name__=='__main__': unittest.main()
