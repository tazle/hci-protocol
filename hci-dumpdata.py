from __future__ import absolute_import, division, print_function, unicode_literals

import socket
import select
import struct
import logging
import argparse

from collections import defaultdict
from construct import RawCopy
from hci_protocol.hci_protocol import HciPacket, HciPacketType, HciEventType, LeMetaEventSubtype
import binascii

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class HciSniffer(object):
    def __init__(self, hci_device_number=0):
        self._hci_socket = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
        self._hci_socket.setsockopt(socket.SOL_HCI, socket.HCI_DATA_DIR, 1)
        self._hci_socket.setsockopt(socket.SOL_HCI, socket.HCI_TIME_STAMP, 1)
        self._hci_socket.setsockopt(
            socket.SOL_HCI, socket.HCI_FILTER, struct.pack("IIIH2x", 0xffffffff, 0xffffffff, 0xffffffff, 0)
        )
        self._hci_socket.bind((hci_device_number,))
        self._hci_device_number = hci_device_number
        log.info("Socket created and bound")

    def stream(self):
        while True:
            readable, _, _ = select.select([self._hci_socket], [], [])
            if readable is not None:
                packet = self._hci_socket.recv(4096)
                yield RawCopy(HciPacket).parse(packet)


def main():
    def counts_msg(counts):
        return ", ".join(str(k) + " " + str(counts[k]) for k in sorted(counts.keys()))
    
    logging.basicConfig(level=logging.WARNING)
    logging.basicConfig(level=logging.DEBUG)
    parser = argparse.ArgumentParser()
    parser.add_argument('--hci', type=int, default=0, help='The number of HCI device to connect to')
    args = parser.parse_args()
    hci_sniffer = HciSniffer(args.hci)

    packet_type_counts = defaultdict(lambda: 0)
    event_type_counts = defaultdict(lambda: 0)
    le_meta_event_type_counts = defaultdict(lambda: 0)
    le_advertising_mac_counts = defaultdict(lambda: 0)
    uninteresting_macs = set(["f4:f5:d8:5f:d5:e3", # Google, ehkä oma chromecast tai puhelin?, -53 dBm
                              "c2:5d:01:28:0f:61", "e5:aa:87:38:75:e3", "ed:ab:90:61:70:16", # Ruuvitagit
                              "53:18:0a:78:38:7d", # Polarin joku vehje, -99 dBm
                              "58:ab:b2:c1:d6:18", # Google, iso tyhjä vendor-specific data, -98 dBm
                              "6f:aa:38:06:94:76", # Apple, puhelin?, -102 dBm
                              "5f:3e:0e:77:de:d4", # Google, -97 dBm
                              "70:22:7b:6c:e5:39", # Apple, puhelin?, -100 dBm
                              "5c:e3:7c:c8:ba:5f", # Google, -98 dBm
                              "6f:68:4d:e6:26:65", # Apple, puhelin?, -99 dBm
                              #"c2:2c:06:04:59:f7", # iTag, -78 dBm
                              "49:db:12:c5:98:ce", # Google,
                              "52:5a:9e:f0:88:f6", # Google,
                              "d4:cd:96:c4:90:ec", # Garmin Fenix 5
                              "70:22:7b:6c:e5:39", # Apple, -102 dBm
    ])
    ruuvi_macs = {'C2:5D:01:28:0F:61': 'sauna',
                  'E5:AA:87:38:75:E3': 'makuuhuone',
                  'ED:AB:90:61:70:16': 'parveke'}
    log.info(dir(HciPacketType))
    try:
        for i, packet_and_data in enumerate(hci_sniffer.stream()):
            packet = packet_and_data.value
            if i%1000 == 0:
                log.info(counts_msg(packet_type_counts))
                log.info(counts_msg(event_type_counts))
                log.info(counts_msg(le_meta_event_type_counts))
                log.info(counts_msg(le_advertising_mac_counts))
            packet_type_counts[packet.type] += 1
            if packet.type == HciPacketType.EVENT_PACKET:
                event_type_counts[packet.payload.event] += 1
                if packet.payload.event == HciEventType.LE_META_EVENT:
                    le_meta_event_type_counts[packet.payload.payload.subevent] += 1
                    meta_event = packet.payload.payload
                    if meta_event.subevent == LeMetaEventSubtype.LE_ADVERTISING_REPORT:
                        report = meta_event.payload
                        for i in range(report.num_reports):
                            addr = report.addresses[i]
                            le_advertising_mac_counts[addr] += 1
                            count = le_advertising_mac_counts[addr]
                            rssi = report.rssis[i]
                            if count == 1:
                                data = "".join("%02x" % d for d in report.datas[i])
                                log.info("New device %s, received data: %s, rssi: %d" %(addr, data, rssi))
                            if addr not in uninteresting_macs:
                                data = "".join("%02x" % d for d in report.datas[i])
                                log.info("%s -> %s" %(addr, data))

    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
