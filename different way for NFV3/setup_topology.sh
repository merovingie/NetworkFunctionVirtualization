#!/bin/bash
# Setup the topology and endpoints here.
sudo docker build -f Dockerfile.endpoint -t endpoint:latest .
sudo docker build -f Dockerfile.nf -t nf:latest .

# Stop and remove all previously running containers
sudo docker stop $(docker ps -q)
sudo docker rm $(docker ps -a -q)

# Delete all previously running switches
for bridge in `sudo ovs-vsctl list-br`; do
    sudo ovs-vsctl del-br $bridge
done

# Add switch
sudo ovs-vsctl add-br ovs-br1
sudo ovs-vsctl set-controller ovs-br1 tcp:127.0.0.1:6633
sudo ovs-vsctl set-fail-mode ovs-br1 secure


# Create source and destination containers
sudo docker run -d --privileged --name=int --net=none endpoint:latest tail -f /dev/null
sudo docker run -d --privileged --name=ext --net=none endpoint:latest tail -f /dev/null
sudo docker run -d --privileged --name=nf1 --net=none nf:latest tail -f /dev/null
sudo docker run -d --privileged --name=nf2 --net=none nf:latest tail -f /dev/null

# Connect containers to switches
sudo ovs-docker add-port ovs-br1 eth0 int --ipaddress="192.168.1.2/24" --macaddress="00:00:00:00:01:01"
sudo ovs-docker add-port ovs-br1 eth0 ext --ipaddress="143.12.131.92/24" --macaddress="00:00:00:00:01:02"
sudo ovs-docker add-port ovs-br1 eth0 nf1 --macaddress="00:00:00:00:02:01"
sudo ovs-docker add-port ovs-br1 eth1 nf1 --macaddress="00:00:00:00:02:02"
sudo ovs-docker add-port ovs-br1 eth0 nf2 --macaddress="00:00:00:00:03:01"
sudo ovs-docker add-port ovs-br1 eth1 nf2 --macaddress="00:00:00:00:03:02"

sudo docker exec nf1 sysctl net.ipv4.ip_forward=1
sudo docker exec nf2 sysctl net.ipv4.ip_forward=1
#echo 1
sudo docker exec nf1 ip route add 192.168.1.0/24 dev eth0
sudo docker exec nf1 ip route add 143.12.131.0/24 dev eth1
sudo docker exec nf2 ip route add 192.168.1.0/24 dev eth0
sudo docker exec nf2 ip route add 143.12.131.0/24 dev eth1
#echo 2
sudo docker exec int ip route add 143.12.131.0/24 dev eth0
sudo docker exec ext ip route add 192.168.1.0/24 dev eth0

sudo docker exec nf1 iptables -A FORWARD -i eth1 -p tcp --destination-port 22 -j DROP
sudo docker exec nf2 iptables -A FORWARD -i eth1 -p tcp --destination-port 22 -j DROP