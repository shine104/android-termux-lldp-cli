"""Presentation checks using synthetic reports; no USB access."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import display
import ecm_capture as e


class DisplayTests(unittest.TestCase):
    def report(self):
        return dict(status='lldp_captured', lldp=dict(decoded=dict(
            system_name='test-switch', port_description='port 1/1/24',
            port_id={'value':'1024'}, management_addresses=[{'address':'192.0.2.1'}],
            pvid=None, voice_vlans=[])), vlan_observations=dict(
            completed=True, vlans={'100':{}, '20':{}}))

    def render(self, report):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            display.compact_summary(report)
        return out.getvalue()

    def test_compact_and_sorted(self):
        r = self.report(); before = copy.deepcopy(r)
        text = self.render(r)
        self.assertEqual(len(text.splitlines()), 6)
        self.assertIn('Ethernet:      Unknown', text)
        for value in ('test-switch', 'port 1/1/24', '192.0.2.1',
                      '20, 100 (observed)'):
            self.assertIn(value, text)
        for value in ('Voice', 'Log:', 'bindings', 'frames', 'Chassis'):
            self.assertNotIn(value, text)
        self.assertEqual(r, before)

    def test_optional_fields_and_port_fallback(self):
        r=self.report(); d=r['lldp']['decoded']
        d.update(port_description=None, management_addresses=[], pvid=200, voice_vlans=[120])
        text=self.render(r)
        self.assertIn('1024', text)
        self.assertIn('200 (LLDP PVID)', text)
        self.assertNotIn('Voice', text)
        self.assertNotIn('Switch IP', text)
        d['pvid']=0
        self.assertIn('Untagged VLAN: Unknown', self.render(r))

    def test_ethernet_speed_and_duplex_display(self):
        r = self.report()
        for speed in (10, 100, 1000):
            for duplex, label in ((True, 'full'), (False, 'half')):
                r['ethernet_link'] = dict(status='ok', link_up=True,
                    speed_mbps=speed, full_duplex=duplex)
                self.assertIn(f'{speed} Mbps, {label} duplex (before scan)', self.render(r))
        r['ethernet_link']['link_up'] = False
        self.assertIn('Link down (before scan)', self.render(r))
        r['ethernet_link'].update(link_up=True, speed_mbps=None)
        self.assertIn('Ethernet:      Unknown', self.render(r))
        r['ethernet_link'] = dict(status='unavailable', error={'message':'synthetic USB failure'})
        self.assertNotIn('synthetic USB failure', self.render(r))
        with contextlib.redirect_stdout(io.StringIO()) as out:
            display.summarize(dict(status='no_lldp_observed', ethernet_link=r['ethernet_link']))
        self.assertIn('Ethernet: Unknown', out.getvalue())
        self.assertIn('synthetic USB failure', out.getvalue())
        with contextlib.redirect_stdout(io.StringIO()) as out:
            display.summarize(dict(status='no_lldp_observed'))
        self.assertIn('Ethernet: Unknown', out.getvalue())

    def test_untagged_unknown_expired_and_cdp_conflict(self):
        r=self.report()
        self.assertIn('Untagged VLAN: Unknown', self.render(r))
        d=r['lldp']['decoded']
        d.update(source_mac='02:00:00:00:00:01', pvid=100)
        for key, value in [('lldp_active', False)]:
            r[key]=value
            self.assertIn('Untagged VLAN: Unknown', self.render(r))
        r.pop('lldp_active')
        d['shutdown']=True
        self.assertIn('Untagged VLAN: Unknown', self.render(r))
        d['shutdown']=False
        r['cdp_neighbors']=[dict(source_mac=d['source_mac'], active=True, native_vlan=200)]
        self.assertIn('Conflict - LLDP PVID 100, CDP native 200', self.render(r))
        d['pvid']=None
        self.assertIn('200 (CDP advertised)', self.render(r))
        r['cdp_neighbors'][0]['active']=False
        self.assertIn('Untagged VLAN: Unknown', self.render(r))

    def test_no_lldp_and_no_tags(self):
        r=self.report(); r.update(lldp=None, status='no_lldp_observed')
        r['vlan_observations']['vlans']={}
        text=self.render(r)
        self.assertIn('None observed', text)
        self.assertIn('No advertisement received', text)
        del r['vlan_observations']
        self.assertIn('Not scanned', self.render(r))

    def test_failures_and_withdrawal(self):
        r=self.report(); r['lldp']['decoded']['shutdown']=True
        r['vlan_observations']['completed']=False
        r.update(status='error', errors=[{'message':'Adapter unplugged'}],
                 cleanup_errors=[{'message':'Restore failed'}], configuration_restored=False)
        text=self.render(r)
        for value in ('Neighbor withdrawn', 'incomplete', 'Adapter unplugged',
                      'Restore failed', 'Unplug and reconnect'):
            self.assertIn(value, text)

    def test_driver_recovery_and_controls(self):
        r=self.report(); r['lldp']['decoded']['system_name']='bad\x1b[2J\nname'
        r.update(detached=True, configuration_restored=True,
                 baseline={'bindings':{'0':'r8152'}}, final_bindings={'0':None})
        text=self.render(r)
        self.assertNotIn('\x1b', text)
        self.assertIn(r'bad\u001b[2J\nname', text)
        self.assertIn('driver not restored', text)

    def test_default_fd_runs_full_scan_and_alias_matches(self):
        for extra in ([], ['--vlans']):
            with patch.object(sys, 'argv', ['ecm_capture.py', '--execute', '--fd', '7'] + extra), \
                    patch.object(e, 'ECMUSB'), patch.object(e, 'run', return_value=self.report()) as run, \
                    patch.object(e.d, 'save_report', return_value='synthetic'), \
                    patch.object(e.signal, 'signal'), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(e.main(), 0)
                self.assertTrue(run.call_args.kwargs['vlans'])

    def test_cli_verbose_and_logs_without_hardware(self):
        for verbose in (False, True):
            args=['ecm_capture.py','--execute'] + (['--verbose'] if verbose else [])
            responses=['["/dev/bus/usb/002/002"]','Permission granted.',json.dumps(self.report())]
            with patch.object(sys,'argv',args), patch.object(e.d,'run_command',side_effect=responses) as command, \
                    patch.object(e.d,'save_report',return_value='saved.json') as save, \
                    patch.object(e,'summarize') as detailed, \
                    contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(e.main(),0)
                save.assert_called_once()
                self.assertTrue(command.call_args.args[0][2].endswith('ecm-execute-vlans.sh'))
                self.assertEqual(detailed.called,verbose)
                self.assertEqual('Log: saved.json' in out.getvalue(),verbose)
                self.assertEqual('Tagged VLANs:' in out.getvalue(),not verbose)


if __name__ == '__main__':
    unittest.main()
