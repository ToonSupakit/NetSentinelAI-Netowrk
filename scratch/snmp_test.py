from pysnmp.hlapi import *

def test_snmp(host, community):
    iterator = nextCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((host, 161), timeout=2, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.2')), # ifDescr
        ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.8')), # ifOperStatus
        ObjectType(ObjectIdentity('1.3.6.1.4.1.9.2.2.1.1.93')), # locIfInLoad
        ObjectType(ObjectIdentity('1.3.6.1.4.1.9.2.2.1.1.94')), # locIfOutLoad
        ObjectType(ObjectIdentity('1.3.6.1.4.1.9.2.2.1.1.95')), # locIfReliability
        ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.14')), # ifInErrors
        lexicographicMode=False
    )
    
    for errorIndication, errorStatus, errorIndex, varBinds in iterator:
        if errorIndication:
            print(f"Error: {errorIndication}")
            break
        elif errorStatus:
            print(f"ErrorStatus: {errorStatus.prettyPrint()}")
            break
        else:
            for varBind in varBinds:
                print(' = '.join([x.prettyPrint() for x in varBind]))

if __name__ == '__main__':
    test_snmp('127.0.0.1', 'public')
