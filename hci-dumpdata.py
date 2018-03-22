from __future__ import absolute_import, division, print_function, unicode_literals

import socket
import select
import struct
import logging
import argparse

from collections import defaultdict
from construct import RawCopy
from hci_protocol.hci_protocol import HciPacket, HciPacketType

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class HciSniffer(object):
    def __init__(self, hci_device_number=0):
        self._hci_socket = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
        self._hci_socket.setsockopt(socket.SOL_HCI, socket.HCI_DATA_DIR, 1)
        self._hci_socket.setsockopt(socket.SOL_HCI, socket.HCI_TIME_STAMP, 1)
        self._hci_socket.setsockopt(
            socket.SOL_HCI, socket.HCI_FILTER, struct.pack("IIIH2x", 0xffffffffL, 0xffffffffL, 0xffffffffL, 0)
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
    log.info(dir(HciPacketType))
    try:
        for i, packet_and_data in enumerate(hci_sniffer.stream()):
            packet = packet_and_data.value
            if i%100 == 0:
                log.info(counts_msg(packet_type_counts))
                log.info(counts_msg(event_type_counts))
            packet_type_counts[packet.type] += 1
            if packet.type == HciPacketType.EVENT_PACKET:
                event_type_counts[packet.payload.type] += 1

    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
