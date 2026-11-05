import contextlib
import io
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cdp import checksum, decode_cdp
from packets import PacketError
from display import compact_summary, untagged_vlan_summary
import ecm_capture as e
from test_ecm import USB


def tlv(kind, value):
    return struct.pack('!HH', kind, len(value)+4)+value


def frame(vlan=100, ttl=180, extra=b'', tagged=False):
    body = bytes([2,ttl,0,0])+tlv(1,b'switch')+tlv(3,b'1/1/24')
    if vlan is not None:
        body += tlv(10,struct.pack('!H',vlan))
    body += extra
    body = body[:2]+struct.pack('!H',checksum(body))+body[4:]
    payload=bytes.fromhex('aaaa0300000c2000')+body
    return bytes.fromhex('01000ccccccc020000000001') + (bytes.fromhex('81000014') if tagged else b'') + struct.pack('!H',len(payload))+payload


class CDPTests(unittest.TestCase):
    def test_checksum_vectors(self):
        self.assertEqual(checksum(bytes.fromhex('12345678')),0x9753)
        self.assertEqual(checksum(bytes.fromhex('123456')),0xed75)
        self.assertEqual(checksum(bytes.fromhex('123480')),0xee4b)

    def test_native_and_tagged_padding(self):
        for tagged in (False,True):
            d=decode_cdp(frame(tagged=tagged)+b'padding')
            self.assertEqual(d['native_vlan'],100)
            self.assertEqual(d['port_id'],'1/1/24')
        self.assertIsNone(decode_cdp(frame(vlan=None))['native_vlan'])
        self.assertEqual(decode_cdp(frame(ttl=0))['ttl'],0)

    def test_invalid_frames(self):
        bad=bytearray(frame());bad[-1]^=1
        for raw in (bytes(bad),frame()[:-1],frame(0),frame(4095),
                    frame(extra=b'\x00'), frame(extra=bytes.fromhex('00050003')),
                    frame(extra=tlv(10,b'\x00\x01'))):
            with self.assertRaises(PacketError):decode_cdp(raw)
        bad=bytearray(frame());bad[14]=0
        self.assertIsNone(decode_cdp(bad))

    def test_capture_deadline_cdp_and_expiration(self):
        for ttl in (180,1,0):
            usb=USB();usb.frames=[frame(ttl=ttl)]
            r=e.run(usb,execute=True,vlans=True,clock=iter([0,0,10]).__next__,persist=lambda r:'test')
            self.assertEqual(r['cdp_neighbors'][0]['active'],ttl==180)
            self.assertEqual(r['status'],'cdp_captured' if ttl==180 else 'no_lldp_observed')
            self.assertEqual(r['duration_seconds'],10)
            self.assertEqual(r['elapsed_seconds'],10)
            self.assertTrue(r['configuration_restored'])

    def render(self,r):
        with contextlib.redirect_stdout(io.StringIO()) as out:print(untagged_vlan_summary(r))
        return out.getvalue()

    def test_display_matching_conflict_and_unknown(self):
        c=decode_cdp(frame());c['active']=True
        r={'status':'cdp_captured','cdp_neighbors':[c]}
        self.assertIn('100 (CDP advertised)',self.render(r))
        r['lldp']={'decoded':{'source_mac':'aa:bb:cc:dd:ee:ff','pvid':None}}
        self.assertNotIn('100 (CDP advertised)',self.render(r))
        r['lldp']['decoded']['source_mac']=c['source_mac']
        self.assertIn('100 (CDP advertised)',self.render(r))
        r['lldp']['decoded']['pvid']=200
        self.assertIn('Conflict',self.render(r))
        c['active']=False
        self.assertIn('200 (LLDP PVID)',self.render(r))

    def test_multiple_neighbors_not_guessed(self):
        c=decode_cdp(frame());c['active']=True
        r={'cdp_neighbors':[c,dict(c,source_mac='00:11:22:33:44:55')]}
        self.assertIn('Unknown',self.render(r))

    def test_withdrawal_replaces_same_neighbor(self):
        usb=USB();usb.frames=[frame(),frame(ttl=0)]
        r=e.run(usb,execute=True,vlans=True,clock=iter([0,0,1,10]).__next__,persist=lambda r:'test')
        self.assertEqual(len(r['cdp_neighbors']),1)
        self.assertFalse(r['cdp_neighbors'][0]['active'])


if __name__=='__main__':unittest.main()
