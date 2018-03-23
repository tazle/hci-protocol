from hci_protocol.hci_protocol import HciPacket, HciPacketType, HciEventType, LeMetaEventSubtype
import array

def test_parse_command_complete():
    packet = HciPacket.parse(b"\x04\x0e\x04\x01\x0c \x00")
    assert packet.type == HciPacketType.EVENT_PACKET
    event = packet.payload
    assert event.event == HciEventType.COMMAND_COMPLETE
    assert event.length == 4

def test_parse_le_advertising_report():
    data = array.array('B', [4, # HCI Event
                             0x3e, # LE meta event
                             33, # Total length
                             2, # LE Advertising report,
                             2, # 2 reports,
                             # report 1
                             3, # 1 - nonconnectable undirected advertising
                             3, # 2 - same
                             0, # 1 - public device address
                             0, # 2 - same
                             1,2,3,4,5,6, # 1 - address
                             0x11, 0x12, 0x13, 0x14, 0x15, 0x16, #2 - address
                             5, # 1 - data length
                             6, # 2 - data length
    ] + [ord(x) for x in 'Hello'] + [ # 1 - data
    ] + [ord(x) for x in 'World!'] + [ # 2 - data
        135, # 1 - RSSI
        3, # 2 - RSSI
    ]).tostring()
    packet = HciPacket.parse(data)
    assert packet.type == HciPacketType.EVENT_PACKET
    event = packet.payload
    assert event.event == HciEventType.LE_META_EVENT
    meta_event = event.payload
    assert meta_event.subevent == LeMetaEventSubtype.LE_ADVERTISING_REPORT
    report = meta_event.payload
    assert report.num_reports == 2
    assert report.datas[0] == [ord(x) for x in "Hello"]
    assert report.datas[1] == [ord(x) for x in "World!"]
