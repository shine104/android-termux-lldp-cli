"""Offline parser tests using synthetic frames."""
import ipaddress
import struct
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from packets import decode_lldp, PacketError
from packet_fixtures import frame, tlv, policy


class PacketTests(unittest.TestCase):
    def test_minimal_and_shutdown(self):
        decoded = decode_lldp(frame(ttl=0))
        self.assertEqual(decoded['port_id']['subtype'], 7)
        self.assertEqual(decoded['chassis_id']['value'], '02:00:00:00:00:01')
        self.assertIsNone(decoded['pvid'])
        self.assertIsNone(decoded['system_name'])
        self.assertTrue(decoded['shutdown'])

    def test_advertised_fields(self):
        extras = tlv(5, b'SYNTHETIC-SWITCH') + tlv(4, b'Test port') + tlv(6, b'Test description')
        extras += tlv(127, bytes.fromhex('0080c201') + struct.pack('!H', 200))
        extras += policy(1, 120) + policy(2, 121) + policy(1, 122)
        decoded = decode_lldp(frame(extras, tagged=True))
        self.assertEqual(decoded['system_name'], 'SYNTHETIC-SWITCH')
        self.assertEqual(decoded['pvid'], 200)
        self.assertEqual(decoded['voice_vlans'], [120, 122])
        self.assertEqual(decoded['voice_signalling_vlans'], [121])
        self.assertEqual(decoded['ethernet_tags'][0]['vid'], 100)

    def test_unknown_untagged_and_priority_only_policy(self):
        decoded = decode_lldp(frame(policy(1, 120, unknown=True) + policy(1, 120, tagged=False) + policy(1, 0)))
        self.assertEqual(decoded['voice_vlans'], [])
        self.assertTrue(all(p['vlan_id'] is None for p in decoded['med_policies']))

    def test_management_ipv4_ipv6_and_unknown(self):
        extras = b''
        for family, address in [(1, ipaddress.ip_address('192.0.2.1').packed),
                                (2, ipaddress.ip_address('2001:db8::1').packed), (99, b'abc')]:
            extras += tlv(8, bytes([len(address)+1, family]) + address + b'\x02' + struct.pack('!I', 7) + b'\0')
        decoded = decode_lldp(frame(extras))
        self.assertEqual([a['address'] for a in decoded['management_addresses']], ['192.0.2.1', '2001:db8::1', None])

    def test_unknown_tlvs(self):
        decoded = decode_lldp(frame(tlv(42, b'opaque') + tlv(127, bytes.fromhex('abcdef55') + b'opaque')))
        self.assertEqual(len(decoded['unknown_tlvs']), 2)

    def test_malformed_lldp(self):
        cases = [frame(tlv(3, b'\0\x01')), frame(tlv(8, b'\x05\x01')),
                 frame(tlv(127, b'\0')), frame(tlv(127, bytes.fromhex('0012bb02') + b'\0')),
                 frame(tlv(127, bytes.fromhex('0080c201ffff')))]
        for data in cases:
            with self.subTest(data=data), self.assertRaises(PacketError):
                decode_lldp(data)
        with self.assertRaises(PacketError):
            decode_lldp(bytes.fromhex('0180c200000e02000000000188cc') + tlv(2, b'\x07port'))
        with self.assertRaises(PacketError):
            decode_lldp(frame()[:20])

    def test_non_lldp_and_tag_truncation(self):
        data = bytearray(frame())
        data[12:14] = b'\x08\x00'
        self.assertIsNone(decode_lldp(data))
        with self.assertRaises(PacketError):
            decode_lldp(frame(tagged=True)[:16])

    def test_missing_end_and_invalid_identifier(self):
        header = bytes.fromhex('0180c200000e02000000000188cc')
        mandatory = tlv(1, b'\x07chassis') + tlv(2, b'\x07port') + tlv(3, b'\x00\x78')
        with self.assertRaises(PacketError):
            decode_lldp(header + mandatory)
        with self.assertRaises(PacketError):
            decode_lldp(header + tlv(1, b'\x04bad-mac') + tlv(2, b'\x07port') + tlv(3, b'\x00\x78') + tlv(0, b''))
