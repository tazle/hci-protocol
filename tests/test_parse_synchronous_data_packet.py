from hci_protocol.hci_protocol import HciPacket
import array

def test_parse_synchronous_data():
    data = array.array('B', [3, # Type
                             0b00110000, 0b00000000, # 2_RFU, 2_packet_status_flag, 12_handle
                             5, # HCI length
                             ord('H'), ord('e'), ord('l'), ord('l'), ord('o')]).tostring()

    packet = HciPacket.parse(data)
    assert packet.type == "SYNCHRONOUS_DATA_PACKET"
    sync_data = packet.payload
    assert sync_data.handle == 0
    assert sync_data.packet_status_flag == 3
    assert sync_data.data == b"Hello"

    
