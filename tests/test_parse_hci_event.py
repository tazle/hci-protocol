from hci_protocol.hci_protocol import HciPacket

def test_parse_command_complete():
    packet = HciPacket.parse(b"\x04\x0e\x04\x01\x0c \x00")
    assert packet.type == "EVENT_PACKET"
    event = packet.payload
    assert event.event == "COMMAND_COMPLETE"
    assert event.length == 4
