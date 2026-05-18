from app.snmp_helper import get_snmp_interfaces
result = get_snmp_interfaces('10.10.100.1', 'public')
for r in result:
    if r['ip'] != 'unassigned':
        print(f"  {r['intf']:20s} rel={r['reliability']:3d} tx={r['network_load']:3d} rx={r['rxload']:3d} err={r['input_errors']}")
