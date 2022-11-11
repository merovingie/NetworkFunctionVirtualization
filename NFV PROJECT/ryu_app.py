import copy
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
from pathlib import Path
import json

from ryu.app import simple_switch_13
from webob import Response
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import dpid as dpid_lib

app_instance_name = 'ryu_app_nfv'
register_url = '/register_sfc'
launch_url = '/launch_sfc'

# Description of traffic endpoints for the Network Function 

DST1 = {
    "MAC" : "00:00:00:00:01:02",
    "PORT" : 2,
    "IP" : "143.12.131.92"
}

DST2 = {
    "MAC" : "00:00:00:00:01:04",
    "PORT" : 3,
    "IP" : "143.12.131.93"
}

SRC1 = {
    "MAC" : "00:00:00:00:01:01",
    "PORT" : 2,
    "IP" : "192.168.1.2"
}

SRC2 = {
    "MAC" : "00:00:00:00:01:03",
    "PORT" : 3,
    "IP" : "192.168.1.3"
}

STATIC_HOSTS = [SRC1, SRC2, DST1, DST2]

PATCH_PORT = 1
# TODO Use and increment these after launching nfs and attaching them to switch ports to populate nf_port_to_rules
S1_PORT_COUNTER = 4
S2_PORT_COUNTER = 4

class Workshop4(WorkshopParent):
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(Workshop4, self).__init__(*args, **kwargs)
        print ("Initializing RYU controller app for Workshop 4")
        wsgi = kwargs['wsgi']
        wsgi.register(RestController, { app_instance_name: self })
        self.parse_switch_ids()
        self.ip_to_mac = {}
        self.ip_to_mac[DST1['IP']] = DST1['MAC']
        self.ip_to_mac[SRC1['IP']] = SRC1['MAC']
        self.ip_to_mac[DST2['IP']] = DST2['MAC']
        self.ip_to_mac[SRC2['IP']] = SRC2['MAC']
        self.nf_port_to_rules = {}
        self.registered_chains = {}
        self.ip_route_to_chain_id = {}
        self.nf_pools = {}
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
        switch_id = datapath.id
        #print(f'datapath: {datapath}')
        #print(f'switch_id: {switch_id}')
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
        chain_key = self.build_key(ip_packet.src, ip_packet.dst)
        #print(f'chain_key: {chain_key}')
        chain_id = self.ip_route_to_chain_id[chain_key] if chain_key in self.ip_route_to_chain_id else -1 
        #print(f'chain_id: {chain_id}')

        nf_pools = self.nf_pools[chain_id] if chain_id in self.nf_pools else self.build_init_nf_pools()

        if switch_id == self.s1_dpid:
            nf_pool_data = nf_pools['fw']
            nf_pool = nf_pool_data[0] # TODO make sure this nf_pool is populated by launch function
        elif switch_id == self.s2_dpid:
            nf_pool_data = nf_pools['nat']
            nf_pool = nf_pool_data[0] # TODO make sure this nf_pool is populated by launch function
        else:
            nf_pool_data = None
            nf_pool = []
            print('Could not determine nf_pool from switch_id!')

        if tcp_packet is not None:
            priority = 2  # TCP rules should take precedence over others
            flow_key = self.build_key(ip_packet.src, ip_packet.dst, tcp_packet.src_port, tcp_packet.dst_port)
            match = parser.OFPMatch(eth_src=ether_frame.src, eth_dst=ether_frame.dst, ip_proto=ip_packet.proto, eth_type=ether_frame.ethertype, ipv4_src=ip_packet.src, ipv4_dst=ip_packet.dst, tcp_src=tcp_packet.src_port, tcp_dst=tcp_packet.dst_port)
        else:
            priority = 1
            flow_key = self.build_key(ip_packet.src, ip_packet.dst)
            match = parser.OFPMatch(eth_src=ether_frame.src, eth_dst=ether_frame.dst, ip_proto=ip_packet.proto, eth_type=ether_frame.ethertype, ipv4_src=ip_packet.src, ipv4_dst=ip_packet.dst)

        #print(f'flow_key: {flow_key}')
        if flow_key in self.flows_to_nf_index:
            #print(f'Found existing flow! Using robin number: {self.flows_to_nf_index[flow_key]}')
            robin_number = self.flows_to_nf_index[flow_key]
        else:
            robin_number = nf_pool_data[1]
            self.flows_to_nf_index[flow_key] = robin_number
            nf_pool_data[1] += 1

        nf = nf_pool[robin_number] if len(nf_pool) > 0 else None

        if switch_id == self.s1_dpid and (in_port == SRC1['PORT'] or in_port == SRC2['PORT']):
            if ether_frame.dst == SRC2['MAC']: # allow src1 and src2 to communicate with no nfs
                dst_mac = ether_frame.dst
                out_port = SRC2['PORT']
            elif ether_frame.dst == SRC1['MAC']:
                dst_mac = ether_frame.dst
                out_port = SRC1['PORT']
            else:
                #print('Routing through nfs to dst')
                dst_mac = nf['INT_MAC'] if nf != None else ether_frame.dst
                out_port = nf['INT_PORT'] if nf != None else PATCH_PORT
        elif in_port == PATCH_PORT:
            # Be careful here. Make sure nf is None if no nf registered for this src/dst/switch
            if switch_id == self.s1_dpid:
                dst_mac = nf['INT_MAC'] if nf != None else ether_frame.dst
                out_port = nf['INT_PORT'] if nf != None else self.determine_host_port_from_mac(dst_mac)
            elif switch_id == self.s2_dpid:
                dst_mac = nf['EXT_MAC'] if nf != None else ether_frame.dst
                out_port = nf['EXT_PORT'] if nf != None else self.determine_host_port_from_mac(dst_mac)
            else:
                print('Could not identify switch!')
        elif in_port in self.nf_port_to_rules:
            dst_mac = self.nf_port_to_rules[in_port]['dst_mac']
            out_port = self.nf_port_to_rules[in_port]['out_port']
        elif switch_id == self.s2_dpid and (in_port == DST1['PORT'] or in_port == DST2['PORT']):
            if ether_frame.dst == DST2['MAC']: # allow dst1 and dst2 to communicate with no nfs
                dst_mac = ether_frame.dst
                out_port = DST2['PORT']
            elif ether_frame.dst == DST1['MAC']: 
                dst_mac = ether_frame.dst
                out_port = DST1['PORT']
            else:
                #print('Routing through nfs to src')
                dst_mac = nf['EXT_MAC'] if nf != None else ether_frame.dst
                out_port = nf['EXT_PORT'] if nf != None else PATCH_PORT
        else:
            print('Could not identify port/switch!')
            pass

        if nf_pool_data[1] >= len(nf_pool):
            nf_pool_data[1] = 0

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

    def build_key(self, *args):
        flow_key = [str(a) for a in args]
        flow_key.sort()
        flow_key = ' '.join(flow_key)

        return flow_key

    def parse_switch_ids(self):
        s1_file = Path('switch1_id.txt')
        s2_file = Path('switch2_id.txt')
        if not s1_file.is_file() or not s2_file.is_file():
            raise Exception('switch1_id.txt or switch2_id.txt does not exist!')
        
        # splice at end is to remove quotes
        # ovs utility reports dpid as hex
        self.s1_dpid = int(s1_file.open().read().split()[-1][1:-1], 16)
        self.s2_dpid = int(s2_file.open().read().split()[-1][1:-1], 16)

    def determine_host_port_from_mac(self, mac):
        for h in STATIC_HOSTS:
            if h['MAC'] == mac:
                return h['PORT']
        raise Exception('Could not determine host port from mac address! This should never happen')

    def register_nf_chain(self, payload):
        self.registered_chains[payload['chain_id']] = copy.deepcopy(payload)
        route_key = self.build_key(payload['SRC']['IP'], payload['DST']['IP'])
        self.ip_route_to_chain_id[route_key] = payload['chain_id']
        self.nf_pools[payload['chain_id']] = self.build_init_nf_pools()

    def build_init_nf_pools(self):
        return { 'fw': [[], 0], 'nat': [[], 0] }

    def launch_nfs(self, payload):
        chain_id = payload['chain_id']
        registration_data = self.registered_chains[chain_id]
        # TODO dynamically populate nf_port_to_rules during PUT requests (after attaching a nf function)
        # TODO utilize S1_PORT_COUNTER and S2_PORT_COUNTER here
        '''
        self.nf_port_to_rules[3] = {
            "dst_mac": SRC1['MAC'],
            "out_port": SRC1['PORT']
        }
        self.nf_port_to_rules[4] = {
            "dst_mac": DST1['MAC'],
            "out_port": DST1['PORT']
        }
        self.nf_port_to_rules[5] = {
            "dst_mac": SRC1['MAC'],
            "out_port": SRC1['PORT']
        }
        self.nf_port_to_rules[6] = {
            "dst_mac": DST1['MAC'],
            "out_port": DST1['PORT']
        }
        '''
        if 'nat' in payload:
            # TODO call nat launch script/function with info from payload and registration_data
            nfs = [] # populate this with info for each nf created
            ''' Example
            NF_2 = {
                "INT_MAC" : "00:00:00:00:03:01",
                "EXT_MAC" : "00:00:00:00:03:02",
                "SWITCH_DPID" : 1,
                "INT_PORT" : 5, 
                "EXT_PORT" : 6
            }
            '''
            self.nf_pools[chain_id]['nat'][0].extend(nfs)
            pass
        if 'fw' in payload:
            # TODO call fw launch script/function with info from payload and registration_data
            nfs = [] # populate this with info for each nf created
            self.nf_pools[chain_id]['fw'][0].extend(nfs)
            pass


class RestController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(RestController, self).__init__(req, link, data, **config)
        self.app = data[app_instance_name]

    @route('register', register_url, methods=['PUT'])
    def register(self, req, **kwargs):

        ryu_app_nfv = self.app

        try:
            new_entry = req.json if req.body else {}
        except ValueError:
            raise Response(status=400)

        try:
            #print(f'new_entry: {new_entry}')
            ryu_app_nfv.register_nf_chain(new_entry)
            
            return Response(content_type='application/json', status=201 )
        except Exception as e:
            return Response(status=500)

    @route('launch', launch_url, methods=['PUT'])
    def launch(self, req, **kwargs):

        ryu_app_nfv = self.app

        try:
            launch_payload = req.json if req.body else {}
        except ValueError:
            raise Response(status=400)

        try:
            #print(f'new_entry: {launch_payload}')
            ryu_app_nfv.launch_nfs(launch_payload)
            
            return Response(content_type='application/json', status=201 )
        except Exception as e:
            return Response(status=500)
