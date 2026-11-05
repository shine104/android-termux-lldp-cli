"""Compact terminal presentation; no USB operations."""
import json
from cdp import selected_cdp


def safe_text(value):
    """Escape terminal controls and switch-supplied newlines."""
    return json.dumps(str(value), ensure_ascii=True)[1:-1]


def ethernet_link_summary(report):
    link = report.get('ethernet_link') or {}
    if link.get('status') != 'ok':
        return 'Unknown'
    if link.get('link_up') is False:
        return 'Link down (before scan)'
    speed = link.get('speed_mbps')
    if link.get('link_up') is not True or speed not in (10, 100, 1000):
        return 'Unknown'
    duplex = link.get('full_duplex')
    suffix = ', full duplex' if duplex is True else ', half duplex' if duplex is False else ''
    return f'{speed} Mbps{suffix} (before scan)'


def compact_summary(report):
    decoded = (report.get('lldp') or {}).get('decoded') or {}
    expired = report.get('lldp_active') is False or decoded.get('shutdown', False)
    if expired:
        decoded = {}
    cdp = selected_cdp(report, decoded)
    observations = report.get('vlan_observations')

    def row(label, value):
        print(f'{label + ":":<15}{safe_text(value)}')

    row('Ethernet', ethernet_link_summary(report))
    row('Switch', decoded.get('system_name') or ((cdp or {}).get('device_id') if not decoded else None) or 'Unknown')
    port = decoded.get('port_description') or (decoded.get('port_id') or {}).get('value')
    row('Port', port or ((cdp or {}).get('port_id') if not decoded else None) or 'Unknown')
    addresses = [a['address'] for a in decoded.get('management_addresses', []) if a.get('address')]
    if addresses:
        row('Switch IP', ', '.join(addresses))
    row('Untagged VLAN', untagged_vlan_summary(report))
    if cdp and not decoded:
        print('Discovery: CDP')
    if observations is None:
        tagged = 'Not scanned'
    else:
        ids = sorted(observations.get('vlans', {}), key=int)
        tagged = ', '.join(ids) + ' (observed)' if ids else 'None observed'
    row('Tagged VLANs', tagged)
    status = report.get('status')
    if status == 'no_lldp_observed':
        print('LLDP: No advertisement received.')
    elif status == 'interrupted':
        print('Scan interrupted; results may be incomplete.')
    elif status == 'ready_for_authorized_experiment':
        print('Adapter ready; capture not started.')
    elif status == 'error' and not report.get('errors'):
        print('Capture failed.')
    if observations is not None and not observations.get('completed'):
        print('VLAN scan incomplete; results are partial.')
    if expired:
        print('LLDP: Neighbor withdrawn or expired; discovery is not current.')
    for error in report.get('errors', []):
        print('Error:', safe_text(error.get('message', 'Capture failed')))
    for error in report.get('cleanup_errors', []):
        print('Recovery error:', safe_text(error.get('message', 'USB recovery failed')))
    if (report.get('cleanup_errors') or report.get('configuration_restored') is False
            or report.get('unreleased_interfaces')):
        print('Unplug and reconnect the adapter to restore Android Ethernet.')
    elif report.get('configuration_restored') and report.get('detached'):
        initial = (report.get('baseline') or {}).get('bindings', {})
        final = report.get('final_bindings', {})
        if any(owner and final.get(interface) != owner for interface, owner in initial.items()):
            print('Ethernet driver not restored; unplug and reconnect the adapter.')


def untagged_vlan_summary(report):
    """Advertised untagged VLAN information for normal and verbose output."""
    decoded = (report.get('lldp') or {}).get('decoded') or {}
    if report.get('lldp_active') is False or decoded.get('shutdown'):
        decoded = {}
    cdp = selected_cdp(report, decoded)
    pvid = decoded.get('pvid')
    native = (cdp or {}).get('native_vlan')
    if pvid and native and pvid != native:
        untagged = f'Conflict - LLDP PVID {pvid}, CDP native {native}'
    elif pvid:
        untagged = f'{pvid} (LLDP PVID)'
    elif native:
        untagged = f'{native} (CDP advertised)'
    else:
        untagged = 'Unknown'
    return untagged


def summarize(report):
    print('Capture:', report['status'])
    print('Ethernet:', ethernet_link_summary(report))
    if report.get('ethernet_link'):
        print('Ethernet reading:', json.dumps(report['ethernet_link'], ensure_ascii=True))
    for reason in report.get('blockers', []):
        print('BLOCKER:', reason)
    if report.get('lldp'):
        decoded = report['lldp']['decoded']
        for label, value in [('Switch name', decoded['system_name']),
            ('Chassis ID', decoded['chassis_id']['value']), ('Port ID', decoded['port_id']['value']),
            ('Port description', decoded['port_description']), ('Advertised PVID', decoded['pvid'] or None),
            ('Advertised MED policies', decoded['med_policies']),
            ('Voice VLANs', decoded['voice_vlans']), ('Voice signalling VLANs', decoded['voice_signalling_vlans']),
            ('Management addresses', [a['address'] for a in decoded['management_addresses'] if a['address']])]:
            # JSON escapes terminal controls in untrusted switch-supplied text.
            print(label + ':', json.dumps(value if value not in (None, []) else 'unavailable', ensure_ascii=True))
        if decoded['shutdown']:
            print('TTL is zero: neighbor withdrawal, not a current discovery.')
    observations = report.get('vlan_observations')
    if observations is not None:
        print('VLAN scan:', f"completed ({observations.get('duration_seconds', 60)} seconds)" if observations['completed'] else 'incomplete')
        print('Observed tagged VLAN IDs:', ', '.join(sorted(observations['vlans'], key=int)) or 'none observed')
        for vid in sorted(observations['vlans'], key=int):
            print('VLAN ' + vid + ':', json.dumps(observations['vlans'][vid]))
        print('Frames received without tags: LLDP:', observations['untagged_lldp_frames'],
              'other:', observations['untagged_other_frames'])
        print('Untagged VLAN number: unknown from frame bytes; see advertised PVID above')
        print('Priority-only tags (VID 0):', observations['priority_tags'])
        print('Reserved tags (VID 4095):', observations['reserved_tags'])
        print(observations['interpretation'])
    if report.get('detached'):
        print(report['recovery'])
    for error in report.get('errors', []):
        print('ERROR:', error['message'])
