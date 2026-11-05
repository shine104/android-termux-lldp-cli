import binascii
import ctypes
import errno
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import diagnostic as d


def device(vid=0x0BDA, pid=0x8153):
    return struct.pack('<BBHBBBBHHHBBBB', 18, 1, 0x300, 0, 0, 0, 9,
                       vid, pid, 0x3100, 0, 0, 0, 1)


def configuration():
    interface = bytes([9, 4, 0, 0, 3, 255, 255, 0, 0])
    endpoints = b''.join(struct.pack('<BBBBHB', 7, 5, ep, kind, size, 0)
                         for ep, kind, size in [(0x81, 2, 1024), (2, 2, 1024), (0x83, 3, 2)])
    return struct.pack('<BBHBBBBB', 9, 2, 9+len(interface+endpoints), 1, 1, 0, 0x80, 50) + interface + endpoints


VALUES = dict(zip(d.WINDOWS, (0x67000880, 0x2480E, 0, 0x90093, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0)))


class FakeUSB:
    def __init__(self, vid=0x0BDA, active=1, fail=None):
        self.calls = []
        self.vid = vid
        self.active = active
        self.fail = fail

    def get_driver(self):
        return dict(state='bound', name='r8152')

    def read(self, kind, request, value, index, length):
        self.calls.append((kind, request, value, index, length))
        if kind == 0xC0:
            if self.fail:
                raise self.fail
            return VALUES[value].to_bytes(4, 'little')
        if request == 8:
            return bytes([self.active])
        if value == 0x100:
            return device(vid=self.vid)
        return configuration()[:length]


class DiagnosticsTests(unittest.TestCase):
    def test_link_speeds_and_duplex(self):
        for bit, speed in ((4, 10), (8, 100), (16, 1000)):
            for duplex in (False, True):
                with self.subTest(speed=speed, duplex=duplex):
                    phy = d.decode_registers({0xE908: bit | 2 | int(duplex)})['phy']
                    self.assertEqual(phy['speed_mbps'], speed)
                    self.assertEqual(phy['full_duplex'], duplex)
        self.assertIsNone(d.decode_registers({0xE908: 2})['phy']['speed_mbps'])

    def test_recorded_values(self):
        r = d.decode_registers(VALUES)
        self.assertEqual(r['revision']['signature'], '0x6400')
        self.assertEqual(r['revision']['family'], 'RTL8153C')
        self.assertFalse(r['command']['rx_enabled'])
        self.assertFalse(r['command']['tx_enabled'])
        self.assertTrue(r['phy']['link_up'])
        self.assertEqual(r['phy']['speed_mbps'], 1000)
        self.assertTrue(r['phy']['full_duplex'])
        self.assertTrue(r['receive_filter']['accept_multicast'])
        self.assertTrue(r['receive_filter']['lldp_multicast_hash_verified'])

    def test_unknown_revision_and_down_link(self):
        r = d.decode_registers({0xE610: 0x12340000, 0xE908: 0x10})
        self.assertFalse(r['revision']['source_match'])
        self.assertIsNone(r['phy']['speed_mbps'])
        self.assertIsNone(r['phy']['full_duplex'])

    def test_ambiguous_speed(self):
        self.assertIsNone(d.decode_registers({0xE908: 0x1B})['phy']['speed_mbps'])

    def test_command_offset(self):
        r = d.decode_registers({0xE810: 0x0C000000})
        self.assertTrue(r['command']['rx_enabled'])
        self.assertTrue(r['command']['tx_enabled'])

    def test_descriptors(self):
        c = d.parse_configuration(configuration())
        self.assertEqual(c['value'], 1)
        self.assertEqual(c['interfaces'][0]['endpoints'][0]['max_packet_size'], 1024)
        self.assertEqual(d.parse_device(device())['vid'], '0BDA')

    def test_malformed_descriptors(self):
        for raw in (b'', configuration()[:-1], configuration()[:9]+b'\x00'+configuration()[10:]):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                d.parse_configuration(raw)
        bad = bytearray(configuration())
        bad[13] = 4
        with self.assertRaises(ValueError):
            d.parse_configuration(bad)
        with self.assertRaises(ValueError):
            d.parse_device(device()[:-1])

    def test_complete_diagnostic_read_calls(self):
        usb = FakeUSB()
        report = d.diagnose(usb)
        self.assertEqual(report['status'], 'ok')
        self.assertEqual(len(report['raw_registers']), 9)
        self.assertTrue(all(call[0] in (0x80, 0xC0) for call in usb.calls))
        self.assertIsNone(report['ethernet_ip']['address'])
        self.assertEqual(report['lldp'], 'not_attempted')

    def test_no_registers_for_other_device_or_configuration(self):
        for usb, status in [(FakeUSB(vid=1), 'not_target'), (FakeUSB(active=2), 'error')]:
            self.assertEqual(d.diagnose(usb)['status'], status)
            self.assertFalse(any(call[0] == 0xC0 for call in usb.calls))

    def test_timeouts_and_unplug(self):
        for number in (errno.ETIMEDOUT, errno.ENODEV, errno.EACCES):
            usb = FakeUSB(fail=OSError(number, 'test failure'))
            report = d.diagnose(usb)
            self.assertEqual(report['status'], 'partial')
            self.assertEqual(report['errors'][0]['errno'], number)
            if number == errno.ENODEV:
                self.assertEqual(len(report['errors']), 1)

    def test_real_transport_allowlist_and_abi(self):
        with open('/dev/null', 'rb') as f, patch.object(d.fcntl, 'ioctl') as ioctl:
            usb = d.ReadOnlyUSB(f.fileno())
            def receive(fd, code, control, mutate):
                self.assertEqual(code, 0xC0185500)
                self.assertEqual(control.timeout, 1000)
                ctypes.memmove(control.data, b'\x01', 1)
                return 1
            ioctl.side_effect = receive
            self.assertEqual(usb.read(0x80, 8, 0, 0, 1), b'\x01')
            for args in [(0x40, 5, 0xE810, 0x100, 4), (0, 9, 2, 0, 0),
                         (0xC0, 5, 0xFFFF, 0x100, 4), (0x80, 11, 1, 0, 0)]:
                with self.assertRaises(ValueError):
                    usb.read(*args)
            self.assertEqual(ioctl.call_count, 1)

    def test_short_transfer(self):
        with open('/dev/null', 'rb') as f, patch.object(d.fcntl, 'ioctl', return_value=0):
            with self.assertRaisesRegex(RuntimeError, 'Short USB read'):
                d.ReadOnlyUSB(f.fileno()).read(0x80, 8, 0, 0, 1)

    def test_permission_denial_logged(self):
        with patch.object(sys, 'argv', ['diagnostic.py', '--no-prompt']), \
             patch.object(d, 'run_command', side_effect=['["/dev/bus/usb/002/002"]', RuntimeError('Permission denied.')]), \
             patch.object(d, 'save_report', return_value='test-log') as save:
            self.assertEqual(d.main(), 1)
            report = save.call_args.args[0]
            self.assertEqual(report['attempts'][0]['errors'][0]['errno'], errno.EACCES)
            json.dumps(report)

    def test_invalid_fd_is_structured_error(self):
        result = subprocess.run([sys.executable, str(d.ROOT/'diagnostic.py'), '--fd', '-1'], capture_output=True, text=True)
        self.assertEqual(json.loads(result.stdout)['status'], 'error')





class ExtendedDiagnosticTests(unittest.TestCase):
    def test_hash_independent_reference_and_byte_order(self):
        mac = bytes.fromhex('0180c200000e')
        crc = binascii.crc32(mac) ^ 0xFFFFFFFF
        independent = int(f'{crc:032b}'[::-1], 2) >> 26
        self.assertEqual(d.multicast_hash_bit(mac), independent)
        self.assertEqual(independent, 33)
        values = {0xC010: 0xE, 0xCD00: 0x02000000, 0xCD04: 0, 0xE858: 0x00080000}
        decoded = d.decode_registers(values)
        self.assertTrue(decoded['receive_filter']['lldp_admitted'])
        self.assertTrue(decoded['receive_gate']['gated'])
        values[0xCD00] = 0x00000040  # Synthetic register example with the LLDP hash bit absent.
        self.assertFalse(d.decode_registers(values)['receive_filter']['lldp_admitted'])

    def test_get_driver_bound_unbound_error(self):
        with open('/dev/null', 'rb') as fd:
            usb = d.ReadOnlyUSB(fd.fileno())
            def query(fd, number, data, mutate):
                self.assertEqual(number, 0x41045508)
                data[4:10] = b'r8152\0'
                return 0
            with patch.object(d.fcntl, 'ioctl', side_effect=query):
                self.assertEqual(usb.get_driver(), dict(state='bound', name='r8152'))
            for number, state in [(errno.ENODATA, 'unbound'), (errno.EACCES, 'error')]:
                with patch.object(d.fcntl, 'ioctl', side_effect=OSError(number, 'test')):
                    self.assertEqual(usb.get_driver()['state'], state)

    def test_oob_byte_extraction(self):
        r = d.decode_registers({0xE84C: 0x81001234, 0xE8DC: 0xABCD0000})
        self.assertTrue(r['out_of_band']['active'])
        self.assertEqual(r['out_of_band']['value'], '0x81')
        self.assertEqual(r['sff_status']['value'], '0xABCD')


if __name__ == '__main__':
    unittest.main()
