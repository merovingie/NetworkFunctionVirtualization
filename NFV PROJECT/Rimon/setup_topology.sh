#!/bin/bash
# Setup the topology and endpoints here.
sudo docker build -f Dockerfile.endpoint -t endpoint:latest .

# Stop and remove all previously running containers and BRidges
sudo docker ps -a -q | sudo xargs -I '{}' docker rm -f {}
sudo ovs-vsctl list-br | xargs -I '{}' sudo ovs-vsctl del-br {}

# Add switches 1 and 2
sudo ovs-vsctl add-br ovs-br1
sudo ovs-vsctl --columns=datapath_id list bridge ovs-br1 | grep datapath_id > switch1_id.txt
sudo ovs-vsctl set-controller ovs-br1 tcp:127.0.0.1:6633
sudo ovs-vsctl set-fail-mode ovs-br1 secure
sudo ovs-vsctl add-br ovs-br2
sudo ovs-vsctl --columns=datapath_id list bridge ovs-br2 | grep datapath_id > switch2_id.txt
sudo ovs-vsctl set-controller ovs-br2 tcp:127.0.0.1:6633
sudo ovs-vsctl set-fail-mode ovs-br2 secure

## Connect switch 1 and 2 via a patch port? This might not be needed
#sudo ovs-vsctl \
#    -- add-port ovs-br1 patch1 \
#    -- set interface patch1 type=patch options:peer=patch2 \
#    -- add-port ovs-br2 patch2 \
#    -- set interface patch2 type=patch options:peer=patch1

# Create source and destination containers
sudo docker run -d --privileged --name=src1 --net=none endpoint:latest tail -f /dev/null
sudo docker run -d --privileged --name=src2 --net=none endpoint:latest tail -f /dev/null
sudo docker run -d --privileged --name=dst1 --net=none endpoint:latest tail -f /dev/null
sudo docker run -d --privileged --name=dst2 --net=none endpoint:latest tail -f /dev/null

# Connect containers to switches
sudo ovs-docker add-port ovs-br1 eth0 src1 --ipaddress="192.168.1.2/24" --macaddress="00:00:00:00:01:01"
sudo ovs-docker add-port ovs-br1 eth0 src2 --ipaddress="192.168.1.3/24" --macaddress="00:00:00:00:01:03"
sudo ovs-docker add-port ovs-br2 eth0 dst1 --ipaddress="143.12.131.92/24" --macaddress="00:00:00:00:01:02"
sudo ovs-docker add-port ovs-br2 eth0 dst2 --ipaddress="143.12.131.93/24"  --macaddress="00:00:00:00:01:04"

sudo docker exec src1 ip route add 143.12.131.0/24 dev eth0
sudo docker exec src2 ip route add 143.12.131.0/24 dev eth0
sudo docker exec dst1 ip route add 192.168.1.0/24 dev eth0
sudo docker exec dst2 ip route add 192.168.1.0/24 dev eth0
