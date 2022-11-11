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

import random, string

DST = {
    "IN_MAC" : "00:00:00:00:01:02",
    "IN_PORT" : 2,
    "IP" : "145.12.131.92"
}
SRC = {
    "OUT_MAC" : "00:00:00:00:01:01",
    "OUT_PORT" : 1,
    "IP" : "192.168.1.2"
}

# Description of NF instances
# NF Instance 1
NF_1 = {
    "IN_MAC" : "00:00:00:00:02:01",
    "OUT_MAC" : "00:00:00:00:02:02",
    "SWITCH_DPID" : 1,
    "IN_PORT" : 3,
    "OUT_PORT" : 4
}

# NF Instance 2
NF_2 = {
    "IN_MAC" : "00:00:00:00:03:01",
    "OUT_MAC" : "00:00:00:00:03:02",
    "SWITCH_DPID" : 1,
    "IN_PORT" : 5,
    "OUT_PORT" : 6
}

# Pool of NF Instances
NF_POOL = [NF_1, NF_2]



class Workshop2(WorkshopParent):
    def __init__(self, *args, **kwargs):
        super(Workshop2, self).__init__(*args, **kwargs)

        self.arp_table = {}
        self.mac_to_port = {}
        self.robin_number = 0

        # build arp table..
        print(SRC["OUT_MAC"])
        print(SRC["IP"])
        self.arp_table[SRC["IP"]] = SRC["OUT_MAC"]
        self.arp_table[DST["IP"]] = DST["IN_MAC"]
        


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
            print('inport ', in_port)

            r = self.arp_table.get(arp_packet.dst_ip)
            if r:
                print('Mac address for packet to forwarded to -r- ', r)
                src_mac = r
                dst_mac = ether_frame.dst
                src_ip = arp_packet.dst_ip
                dst_ip = arp_packet.src_ip
                out_port = in_port
           
                self.send_arp_reply(datapath, src_mac, src_ip, dst_mac, dst_ip, out_port)
       
        else:
            # We don't expect to receive ARP replies, so do nothing
            pass

    # Function to handle non-ARP packets
    def handle_packet(self, msg):
        ''' Your code here '''
        print('Called Packet handler')

        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']


        pkt = Packet(msg.data)
        eth = pkt.get_protocols(ethernet)[0]
        ether_frame = pkt.get_protocol(ethernet)
        ip_packet = pkt.get_protocol(ipv4)
        tcp_packet = pkt.get_protocol(tcp)

        dst = eth.dst
        src = eth.src

        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        print("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
            
        # if in_port == 1:
        #     out_port = NF_IN_PORT
        #     dst = NF_MACS[0]

        # elif in_port == 3:
        #     out_port = SRC_PORT
        #     dst = SRC_MAC

        # elif in_port == 4:
        #     out_port = DST_PORT
        #     dst = DST_MAC

        # elif in_port == 2:
        #     out_port = NF_OUT_PORT
        #     dst = NF_MACS[1]

        # else:
        #     out_port = ofproto.OFPP_FLOOD
        
        actions = [parser.OFPActionSetField(eth_dst=dst), parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(eth_src=ether_frame.src, eth_dst=ether_frame.dst)

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def build_flow_key(self):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

    def send_group_mod(self, datapath, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Hardcoding the stuff, as we already know the topology diagram.
        # Group table1
        # Receiver port3 (host connected), forward it to port1(switch) and Port2(switch)
        LB_WEIGHT1 = 50 #percentage
        LB_WEIGHT2 = 50 #percentage

        watch_port = ofproto_v1_3.OFPP_ANY
        watch_group = ofproto_v1_3.OFPQ_ALL

        if in_port == 1:
            actions1 = [parser.OFPActionOutput(2)]
            actions2 = [parser.OFPActionOutput(5)]
            buckets = [parser.OFPBucket(LB_WEIGHT1, watch_port, watch_group, actions=actions1),
                    parser.OFPBucket(LB_WEIGHT2, watch_port, watch_group, actions=actions2)]
        elif in_port == 4:
            actions1 = [parser.OFPActionOutput(3)]
            actions2 = [parser.OFPActionOutput(6)]
            buckets = [parser.OFPBucket(LB_WEIGHT1, watch_port, watch_group, actions=actions1),
                    parser.OFPBucket(LB_WEIGHT2, watch_port, watch_group, actions=actions2)]
            
            req = parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD,
                                    ofproto.OFPGT_SELECT, 50, buckets)
        datapath.send_msg(req)
