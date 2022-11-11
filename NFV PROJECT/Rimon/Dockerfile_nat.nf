FROM ubuntu:trusty

RUN apt-get update && apt-get install -y iptables-persistent
RUN apt-get install -y wondershaper tcpdump
RUN mv /usr/sbin/tcpdump /usr/bin/tcpdump

RUN mkdir -p /scripts
COPY init_nat.sh /scripts
WORKDIR /scripts
RUN chmod +x init_nat.sh