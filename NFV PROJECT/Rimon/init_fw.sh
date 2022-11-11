while getopts p:P:m:M:i:I:r:R: flag
do
    case "${flag}" in
        p) port1=${OPTARG};;
        P) port2=${OPTARG};;
        m) mac1=${OPTARG};;
        M) mac2=${OPTARG};;
        i) ip1=${OPTARG};;
        I) ip2=${OPTARG};;
        r) route1=${OPTARG};;
        R) route2=${OPTARG};;
    esac
done
echo "port1: $port1";
echo "port2: $port2";
echo "mac1: $mac1";
echo "mac1: $mac2";
echo "ip1: $ip1";
echo "ip2: $ip2";
echo "route1: $route1";
echo "route2: $route2";

# adding routes
ip route add $route1 dev $port1
ip route add $route2 dev $port2

# adding firewall config
sysctl net.ipv4.ip_forward=1
iptables -A FORWARD -i $port2 -p tcp --destination-port 22 -j DROP