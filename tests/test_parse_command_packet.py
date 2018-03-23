from hci_protocol.hci_protocol import HciPacket
import array

def test_parse_acl_data():
    data = array.array('B', [1, # Type
                             0x01, 0x04, # group 1, command 1
                             5, # length
                             0x12, 0x34, 0x56, # LAP
                             6, # inquiry length
                             0, # num responses
    ]).tostring()

    packet = HciPacket.parse(data)
    assert packet.type == "COMMAND_PACKET"
    command = packet.payload
    assert command.opcode.ogf == "LINK_CONTROL"
    assert command.opcode.ocf == 1
    assert command.length == 5
    assert command.payload == [0x12, 0x34, 0x56, 0x6, 0x0]
