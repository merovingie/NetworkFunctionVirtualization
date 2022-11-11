#!/bin/bash

# prepare environment
sudo docker build -f Dockerfile.endpoint -t endpoint:latest .
sudo docker build -f Dockerfile.nf -t nf:latest .

sudo docker ps -a -q | sudo xargs -I '{}' docker rm -f {}
sudo ovs-vsctl list-br | xargs -I '{}' sudo ovs-vsctl del-br {}

# setting bridge
sudo ovs-vsctl add-br ovs-br1
sudo ovs-vsctl set-controller ovs-br1 tcp:127.0.0.1:6633
sudo ovs-vsctl set-fail-mode ovs-br1 secure

# setting containers
sudo docker run -d --privileged --name=int --net=none endpoint:latest tail -f /dev/null
sudo docker run -d --privileged --name=ext --net=none endpoint:latest tail -f /dev/null
sudo docker run -d --privileged --name=nf1 --net=none nf:latest tail -f /dev/null
sudo docker run -d --privileged --name=nf2 --net=none nf:latest tail -f /dev/null

# setup ports on bridge
sudo ovs-docker add-port ovs-br1 eth0 int --macaddress="00:00:00:00:01:01" --ipaddress="192.168.1.2/24" #1
sudo ovs-docker add-port ovs-br1 eth0 ext --macaddress="00:00:00:00:01:02" --ipaddress="145.12.131.92/24" #2

# setup ports on bridges
sudo ovs-docker add-port ovs-br1 eth0 nf1 --macaddress="00:00:00:00:02:01"  #3
sudo ovs-docker add-port ovs-br1 eth1 nf1 --macaddress="00:00:00:00:02:02"  #4
sudo ovs-docker add-port ovs-br1 eth0 nf2 --macaddress="00:00:00:00:03:01"  #5
sudo ovs-docker add-port ovs-br1 eth1 nf2 --macaddress="00:00:00:00:03:02"  #6

# show ports and dump rules
sudo ovs-ofctl show ovs-br1
sudo ovs-ofctl dump-flows ovs-br1

# add routes on nf1
sudo docker exec nf1 ip route add 192.168.1.0/24 dev eth0
sudo docker exec nf1 ip route add 145.12.131.0/24 dev eth1

# add routes on nf2
sudo docker exec nf2 ip route add 192.168.1.0/24 dev eth0
sudo docker exec nf2 ip route add 145.12.131.0/24 dev eth1



# add routes
sudo docker exec int route add -net 145.12.131.0/24 dev eth0
sudo docker exec ext route add -net 192.168.1.0/24 dev eth0



# firewall rules
sudo docker exec nf1 sysctl net.ipv4.ip_forward=1
sudo docker exec nf2 sysctl net.ipv4.ip_forward=1

sudo docker exec nf1 iptables -A FORWARD -i eth1 -p tcp --destination-port 22 -j DROP
sudo docker exec nf2 iptables -A FORWARD -i eth1 -p tcp --destination-port 22 -j DROP
