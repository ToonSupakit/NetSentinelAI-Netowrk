import asyncio
from pysnmp.hlapi.v3arch.asyncio import *

async def test_snmp():
    snmpEngine = SnmpEngine()
    results = {}
    
    errorIndication, errorStatus, errorIndex, varBinds = await walk_cmd(
        snmpEngine,
        CommunityData('public'),
        UdpTransportTarget(('10.10.100.1', 161), timeout=3, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.2')),
        lexicographicMode=False
    )
    
    if errorIndication:
        print(f"Error: {errorIndication}")
    elif errorStatus:
        print(f"ErrorStatus: {errorStatus.prettyPrint()}")
    else:
        # walk_cmd returns a list of varBinds
        for varBindRow in varBinds:
            for varBind in varBindRow:
                print(' = '.join([x.prettyPrint() for x in varBind]))

if __name__ == '__main__':
    asyncio.run(test_snmp())
