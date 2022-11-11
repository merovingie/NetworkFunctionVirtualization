#!/bin/bash

# prepare environment
sudo docker build -f Dockerfile.endpoint -t endpoint:latest .
sudo docker build -f Dockerfile.nf -t nf:latest .
sudo docker stop fw
sudo docker rm fw
sudo docker stop int
sudo docker rm int
sudo docker stop ext
sudo docker rm ext
sudo ovs-vsctl del-br ovs-br1

# setting bridge
sudo ovs-vsctl add-br ovs-br1
sudo ovs-vsctl set-controller ovs-br1 tcp:127.0.0.1:6633
sudo ovs-vsctl set-fail-mode ovs-br1 secure
sudo docker run -d --privileged --name=int --net=none endpoint:latest tail -f /dev/null
sudo docker run -d --privileged --name=ext --net=none endpoint:latest tail -f /dev/null
sudo docker run -d --privileged --name=fw --net=none nf:latest tail -f /dev/null

# setup ports on bridge
sudo ovs-docker add-port ovs-br1 eth0 int --macaddress="00:00:00:00:01:01" --ipaddress="192.168.1.2/24" #1
sudo ovs-docker add-port ovs-br1 eth0 fw --macaddress="00:00:00:00:02:01" --ipaddress="192.168.1.1/24" #2
sudo ovs-docker add-port ovs-br1 eth0 ext --macaddress="00:00:00:00:01:02" --ipaddress="145.12.131.92/24" #3
sudo ovs-docker add-port ovs-br1 eth1 fw --macaddress="00:00:00:00:02:02" --ipaddress="145.12.131.74/24" #4

# show ports and dump rules
sudo ovs-ofctl show ovs-br1
sudo ovs-ofctl dump-flows ovs-br1

# add routes
sudo docker exec int route add -net 145.12.131.0/24 gw 192.168.1.1 dev eth0
sudo docker exec ext route add -net 192.168.1.0/24 gw 145.12.131.74 dev eth0

# firewall rules
sudo docker exec nat sysctl net.ipv4.ip_forward=1
sudo docker exec fw iptables -A FORWARD -i eth1 -p tcp --destination-port 22 -j DROP