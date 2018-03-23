from hci_protocol.hci_protocol import HciPacket
import array

def test_parse_acl_data():
    data = array.array('B', [2, # Type
                             0b00101010, 0b01110000, # 2_bc, 2_pb, 12_handle (little-endian handle changes things)
                             11, 0, # HCI length
                             7, 0, # L2CAP Length
                             2, 0, # L2CAP CID - 2 = connectionless data
                             0x31, 0x10, # Random PSM
                             ord('H'), ord('e'), ord('l'), ord('l'), ord('o')]).tostring()

    packet = HciPacket.parse(data)
    assert packet.type == "ACL_DATA_PACKET"
    acl_data = packet.payload
    assert acl_data.header.handle == 0x2a
    assert acl_data.header.pb == 3
    assert acl_data.header.bc == 1
    hci_data = acl_data.payload
    assert hci_data.cid == 2
    data = hci_data.payload
    assert data.psm == 0x1031
    assert "".join(map(chr, data.data)) == "Hello"

def test_parse_l2ping_data():
    stream = (b"\x02\x29\x20\x34\x00\x30\x00\x01\x00\x08\xc8\x2c\x00\x41\x42\x43"+
              b"\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53"+
              b"\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63"+
              b"\x64\x65\x66\x67\x68\x41\x42\x43\x44")

    packet = HciPacket.parse(stream)
    assert packet.type == "ACL_DATA_PACKET"
    acl_data = packet.payload
    assert acl_data.header.handle == 0x29
    assert acl_data.header.pb == 2
    assert acl_data.header.bc == 0
    hci_data = acl_data.payload
    assert hci_data.cid == 1
    data = hci_data.payload
    assert data.code == 8
    assert data.identifier == 0xc8
    expected_data = stream[13:]
    assert "".join(chr(x) for x in data.data) == expected_data.decode("utf-8")

    
