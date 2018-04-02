FROM resin/rpi-raspbian:stretch
RUN apt-get update && apt-get install python3
RUN apt-get install --no-install-recommends -y python3-pip
COPY requirements.txt /
RUN pip3 install --upgrade pip
RUN pip3 install setuptools
RUN pip3 install -r requirements.txt
CMD python3 hci-dumpdata.py
COPY hci_protocol /hci_protocol
COPY hci-dumpdata.py /

