from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet.packet import Packet
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.arp import arp
from ryu.ofproto import ether
from ryu.lib.mac import haddr_to_bin
from workshop_parent import WorkshopParent

NF_MACS = ["00:00:00:00:02:01", "00:00:00:00:02:02"]
SRC_MAC = "00:00:00:00:01:01"
DST_MAC = "00:00:00:00:01:02"

SRC_IP = "192.168.1.2"
DST_IP = "145.12.131.92"

NF_IN_PORT = 3
NF_OUT_PORT = 4
SRC_PORT = 1
DST_PORT = 2



class Workshop2(WorkshopParent):
    def __init__(self, *args, **kwargs):
        super(Workshop2, self).__init__(*args, **kwargs)

        # self.arp_table = {}
        # self.arp_ports = {}

        # #build arp table..
        # self.arp_table[SRC_IP] = NF_MACS[0]
        # self.arp_ports[SRC_IP] = NF_IN_PORT
        # self.arp_table[DST_IP] = NF_MACS[1]
        # self.arp_ports[DST_IP] = NF_OUT_PORT
        # print(self.arp_table)
        # print(self.arp_ports)


    # Function to handle packets belonging to ARP protocol
    def handle_arp(self, datapath, packet, ether_frame, in_port):
        arp_packet = packet.get_protocol(arp)

        if arp_packet.opcode == 1: # Send an ARP Response for the incoming Request
            # Determine the MAC Address for IP Address being looked up
            # Determine the out port to send the ARP Response

            ''' Your code here '''
            
            # create arp response
            print('destination IP: ', arp_packet.dst_ip)
            print('source IP: ', arp_packet.src_ip)
            arp_new_ip = arp_packet.src_ip
            print('inport ', in_port)
            # if arp_packet.dst_ip in self.arp_ports:
            #     print('+++found arp port+++')
            #     r = self.arp_table.get(arp_packet.dst_ip)
            #     out_port = self.arp_ports.get(arp_packet.dst_ip)
            #     print('Mac address for packet to forwarded to -r- ', r , ' output PORT ', out_port)
            #     src_mac = ether_frame.src
            #     dst_mac = r
            #     src_ip = arp_packet.src_ip
            #     dst_ip = arp_packet.dst_ip
            # else:
                # print('+++cant find arp port+++')
                # self.arp_ports[arp_new_ip] = in_port
                # # self.arp_ports.update(arp_new_ip= in_port)
                # print(self.arp_table)
                # print(self.arp_ports)
            if in_port == 1:
                print('---port1---')
                src_mac = ether_frame.src
                print('src_mac ', src_mac)
                src_ip = arp_packet.src_ip
                print('src_ip ', src_ip)
                dst_mac = NF_MACS[0]
                print('dst_mac ', dst_mac)
                dst_ip = arp_packet.dst_ip
                print('dst_ip ',dst_ip)
                out_port = 2
                print('out_port ', out_port)
            elif in_port == 4:
                print('---port3---')
                src_mac = ether_frame.src
                src_ip = arp_packet.src_ip
                dst_mac = NF_MACS[1]
                dst_ip = arp_packet.dst_ip
                out_port = 3
            else:
                print('holy god!!!')

            # Call helper function to create and send ARP Response
            self.send_arp_reply(datapath, src_mac, src_ip, dst_mac, dst_ip, out_port)
        else:
            # We don't expect to receive ARP replies, so do nothing
            print('***life is sooo strange***')
            pass

    # Function to handle non-ARP packets
    def handle_packet(self, msg):
        ''' Your code here '''
        #packet_in
        msg = ev.msg
        #switch
        datapath = msg.datapath
        #protocol
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #switch xID
        dpid = datapath.id
        #which PORT
        in_port = msg.match['in_port']
        
        # ip protocol handlers
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        ip_pkt_6 = pkt.get_protocol(ipv6.ipv6)

        if isinstance(ip_pkt_6, ipv6.ipv6):
            actions = []
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6)
            self.add_flow(datapath, match, actions)
            return 

        if isinstance(ip_pkt, ipv4.ipv4):
            # Send Packet to destination
            self.send_packet_out(datapath, msg.buffer_id, in_port,
                                    out_port, msg.data)

