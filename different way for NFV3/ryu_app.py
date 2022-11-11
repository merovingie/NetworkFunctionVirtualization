from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet.packet import Packet
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.tcp import tcp
from ryu.lib.packet.ipv4 import ipv4
from ryu.lib.packet.arp import arp
from ryu.ofproto import ether
from workshop_parent import WorkshopParent

# Description of traffic endpoints for the Network Function 

EXT = {
    "MAC" : "00:00:00:00:01:02",
    "PORT" : 2,
    "IP" : "143.12.131.92"
}

INT = {
    "MAC" : "00:00:00:00:01:01",
    "PORT" : 1,
    "IP" : "192.168.1.2"
}

# Description of NF instances
# NF Instance 1
NF_1 = {
    "INT_MAC" : "00:00:00:00:02:01",
    "EXT_MAC" : "00:00:00:00:02:02",
    "SWITCH_DPID" : 1,
    "INT_PORT" : 3,
    "EXT_PORT" : 4
}

# NF Instance 2
NF_2 = {
    "INT_MAC" : "00:00:00:00:03:01",
    "EXT_MAC" : "00:00:00:00:03:02",
    "SWITCH_DPID" : 1,
    "INT_PORT" : 5, 
    "EXT_PORT" : 6
}

# Pool of NF Instances
NF_POOL = [NF_1, NF_2]

class Workshop4(WorkshopParent):

    def __init__(self, *args, **kwargs):
        super(Workshop4, self).__init__(*args, **kwargs)
        print ("Initializing RYU controller app for Workshop 4")
        self.ip_to_mac = {}
        self.ip_to_mac[EXT['IP']] = EXT['MAC']
        self.ip_to_mac[INT['IP']] = INT['MAC']
        self.robin_number = 0
        self.nf_port_to_rules = {}
        self.nf_port_to_rules[3] = {
            "dst_mac": INT['MAC'],
            "out_port": INT['PORT']
        }
        self.nf_port_to_rules[4] = {
            "dst_mac": EXT['MAC'],
            "out_port": EXT['PORT']
        }
        self.nf_port_to_rules[5] = {
            "dst_mac": INT['MAC'],
            "out_port": INT['PORT']
        }
        self.nf_port_to_rules[6] = {
            "dst_mac": EXT['MAC'],
            "out_port": EXT['PORT']
        }
        self.flows_to_nf_index = {}

    # Function to handle packets belonging to ARP protocol
    def handle_arp(self, datapath, packet, ether_frame, in_port):
        arp_packet = packet.get_protocol(arp)

        if arp_packet.opcode == 1: # Send an ARP Response for the incoming Request
            # Determine the MAC Address for IP Address being looked up
            # Determine the out port to send the ARP Response 

            ''' Your code here '''
            #print(f'arp_packet: {arp_packet}')
            dst_mac = arp_packet.src_mac
            src_ip = arp_packet.dst_ip
            dst_ip = arp_packet.src_ip

            if arp_packet.dst_ip in self.ip_to_mac:
                src_mac = self.ip_to_mac[arp_packet.dst_ip]
            else:
                print('Another one!')

            #print(f'src_mac chosen: {src_mac}')
            out_port = in_port

            # Call helper function to create and send ARP Response
            self.send_arp_reply(datapath, src_mac, src_ip, dst_mac, dst_ip, out_port)
        else:
            # We don't expect to receive ARP replies, so do nothing
            pass

    # Function to handle non-ARP packets
    def handle_packet(self, msg):
        ''' Your code here '''
        #print(f'msg: {msg}')
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        #print(f'in_port in packet handler: {in_port}')
        packet = Packet(msg.data)
        #print(f'packet in packet_handler: {packet}')
        ether_frame = packet.get_protocol(ethernet)
        ip_packet = packet.get_protocol(ipv4)
        #print(f'ether_frame: {ether_frame}')
        tcp_packet = packet.get_protocol(tcp)
        #print(f'tcp packet: {tcp_packet}')

        if tcp_packet is not None:
            priority = 2  # TCP rules should take precedence over others
            flow_key = self.build_flow_key(ip_packet.src, ip_packet.dst, tcp_packet.src_port, tcp_packet.dst_port)
            match = parser.OFPMatch(eth_src=ether_frame.src, eth_dst=ether_frame.dst, ip_proto=ip_packet.proto, eth_type=ether_frame.ethertype, ipv4_src=ip_packet.src, ipv4_dst=ip_packet.dst, tcp_src=tcp_packet.src_port, tcp_dst=tcp_packet.dst_port)
        else:
            priority = 1
            flow_key = self.build_flow_key(ip_packet.src, ip_packet.dst)
            match = parser.OFPMatch(eth_src=ether_frame.src, eth_dst=ether_frame.dst, ip_proto=ip_packet.proto, eth_type=ether_frame.ethertype, ipv4_src=ip_packet.src, ipv4_dst=ip_packet.dst)

        print(f'flow_key: {flow_key}')
        if flow_key in self.flows_to_nf_index:
            print(f'Found existing flow! Using robin number: {self.flows_to_nf_index[flow_key]}')
            robin_number = self.flows_to_nf_index[flow_key]
        else:
            robin_number = self.robin_number
            self.flows_to_nf_index[flow_key] = robin_number
            self.robin_number += 1

        nf = NF_POOL[robin_number]

        if in_port == INT['PORT']:
            dst_mac = nf['INT_MAC']
            out_port = nf['INT_PORT']
        elif in_port in self.nf_port_to_rules:
            dst_mac = self.nf_port_to_rules[in_port]['dst_mac']
            out_port = self.nf_port_to_rules[in_port]['out_port']
        elif in_port == EXT['PORT']:
            dst_mac = nf['EXT_MAC']
            out_port = nf['EXT_PORT']
        else:
            print('Could not identify port!')
            pass

        if self.robin_number >= len(NF_POOL):
            self.robin_number = 0

        actions = [parser.OFPActionSetField(eth_dst=dst_mac), parser.OFPActionOutput(out_port)]
        self.add_flow(datapath, priority, match, actions)
        
        ofproto = datapath.ofproto
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port, data=msg.data, actions=actions)
        datapath.send_msg(out)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def build_flow_key(self, *args):
        flow_key = [str(a) for a in args]
        flow_key.sort()
        flow_key = ' '.join(flow_key)

        return flow_key
