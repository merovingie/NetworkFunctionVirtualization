import copy
import json
import subprocess
import os
import time

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

from netaddr import *

app_instance_name = 'ryu_app_nfv'
register_url = '/register_sfc' #/{dpid}'
launch_url = '/launch_sfc' #/{dpid}'



# Description of traffic endpoints for the Network Function 

DST1 = {
    "MAC": "00:00:00:00:01:02",
    "PORT": 2,
    "IP": "143.12.131.92"
}

DST2 = {
    "MAC": "00:00:00:00:01:04",
    "PORT": 3,
    "IP": "143.12.131.93"
}

SRC1 = {
    "MAC": "00:00:00:00:01:01",
    "PORT": 2,
    "IP": "192.168.1.2"
}

SRC2 = {
    "MAC": "00:00:00:00:01:03",
    "PORT": 3,
    "IP": "192.168.1.3"
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
        print("Initializing RYU controller app for Workshop 4")
        wsgi = kwargs['wsgi']
        wsgi.register(RestController, {app_instance_name: self})

        # just in case we need switch holders for the objects from switch_handler and mac_to_port
        # self.switches = {}
        # self.mac_to_port = {}

        # switches
        self.switches_added = []

        self.parse_switch_ids()

        # arp table
        self.ip_to_mac = {}
        self.ip_to_mac[DST1['IP']] = DST1['MAC']
        self.ip_to_mac[SRC1['IP']] = SRC1['MAC']
        self.ip_to_mac[DST2['IP']] = DST2['MAC']
        self.ip_to_mac[SRC2['IP']] = SRC2['MAC']

        # structures needed for mapping
        self.nf_port_to_rules = {}
        self.registered_chains = {}
        self.ip_route_to_chain_id = {}
        self.nf_pools = {}
        self.flows_to_nf_index = {}

        # added vars
        # nf port to which switch
        self.nfv_to_switch = {}
        self.mac_to_nf = {}
        self.ip_to_nf = {}



        # mac initialization
        self.mac = EUI('00:00:00:00:00:01')
        self.current_mac = EUI('00:00:00:00:00:01')
        self.mac.dialect = mac_unix_expanded
        self.current_mac.dialect = mac_unix_expanded

        self.nfv_container_index = 1
        self.nfv_container_index_launch = 1

        self.nfv_container_id = []

        self.nf_to_script = {'fw': 'init_fw.sh', 'nat': 'init_nat.sh'}



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

        # create a specific token for each chain
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
        self.switches_added.append(self.s1_dpid)
        self.switches_added.append(self.s2_dpid)

    def determine_host_port_from_mac(self, mac):
        for h in STATIC_HOSTS:
            if h['MAC'] == mac:
                return h['PORT']
        raise Exception('Could not determine host port from mac address! This should never happen')

    def register_nf_chain(self, payload):
        self.registered_chains[payload['chain_id']] = copy.deepcopy(payload)
        print(f'registered_chains {self.registered_chains}')
        route_key = self.build_key(payload['SRC']['IP'], payload['DST']['IP'])
        print(f'route key {route_key}')
        self.ip_route_to_chain_id[route_key] = payload['chain_id']
        print(f'ip_route_to_chain_id {self.ip_route_to_chain_id}')
        self.nf_pools[payload['chain_id']] = self.build_init_nf_pools()
        print(f'nf_pools {self.nf_pools}')

        # Added Code
        print('NF_CHAIN {}'.format(payload['NF_CHAIN']))
        for nfv in payload['NF_CHAIN']:
            print(nfv)
            if nfv == 'fw':
                print(payload['fw']['image'])
                self.create_NFV(payload['chain_id'], payload['fw']['image'], payload['fw']['interfaces'])
            elif nfv == 'nat':
                print(payload['nat']['image'])
                print(payload['nat']['interfaces'])
                self.create_NFV(payload['chain_id'], payload['nat']['image'], payload['nat']['interfaces'])

        print("stop debuging")

    def create_NFV(self, chain_id, image, ports=['eth0', 'eth1']):
        self.nfv_container_index = self.nfv_container_index + 1
        print(f'nfv_container_index {self.nfv_container_index}')
        self.mac_generator(self.nfv_container_index, True)

        if image == 'fw':
            # build Conatainer
            bash_command = "docker build -f Dockerfile_fw.nf -t fw:latest ."
            print(f'bash command {bash_command}')
            self._execute_shell_command(bash_command)

            # add ports to switch
            for port in ports:
                print((str(chain_id) + '_' + image + '_' + port))
                self.mac_to_nf[(str(chain_id) + '_' + image + '_' + port)] = self.mac_generator(self.nfv_container_index, False)
                self.nfv_to_switch[(str(chain_id) + '_' + image + '_' + port)] = '1'
                print(f'mac_to_nf {self.mac_to_nf}')
                print(f'nfv_to_switch {self.nfv_to_switch}')
            self.reset_mac()

        else:
            bash_command = "docker build -f Dockerfile_nat.nf -t nat:latest ."
            print(f'bash command {bash_command}')
            self._execute_shell_command(bash_command)

            # add ports to switch
            for port in ports:
                print((str(chain_id) + '_' + image + '_' + port))
                self.mac_to_nf[(str(chain_id) + '_' + image + '_' + port)] = self.mac_generator(self.nfv_container_index, False)
                self.nfv_to_switch[(str(chain_id) + '_' + image + '_' + port)] = '2'
                print(f'mac_to_nf {self.mac_to_nf}')
                print(f'nfv_to_switch {self.nfv_to_switch}')
            self.reset_mac()



    def _execute_shell_command(self, bash_command):
        with open('output', "w") as output:
            subprocess.run(
                bash_command,
                shell=True,  # pass single string to shaddressell, let it handle.
                stdout=output,
                stderr=output
            )
        while not output.closed:
            time.sleep(0.1)
        print(f"{os.linesep} COMMAND {bash_command} LOG OUTPUT:")
        with open('output', "r") as output:
            for line in output:
                print(line)

    def reset_mac(self):
        self.current_mac.dialect = mac_unix_expanded
        self.current_mac = EUI('00:00:00:00:00:01')

    def mac_generator(self, chain_id, type=False):
        if type == True:
            multiplier = chain_id * 256
            print(f'multiplier {multiplier}')
            temp_value = self.mac.value + multiplier
            print(f'temp value {temp_value}')
            self.current_mac._set_value(temp_value)
            self.current_mac.dialect = mac_unix_expanded
            print("Current Mac At ", str(self.current_mac))
        else:
            multiplier = 1
            print(f'multiplier {multiplier}')
            temp_value = self.current_mac.value + multiplier
            print(f'temp value {temp_value}')
            self.current_mac._set_value(temp_value)
            self.current_mac.dialect = mac_unix_expanded
            print("Current Mac At ", str(self.current_mac))

        return str(self.current_mac)


    def build_init_nf_pools(self):
        return {'fw': [[], 0], 'nat': [[], 0]}

    def launch_nfs(self, payload):
        chain_id = payload['chain_id']
        # registration_data = self.registered_chains[chain_id]
        # TODO dynamically populate nf_port_to_rules during PUT requests (after attaching a nf function)
        # TODO utilize S1_PORT_COUNTER and S2_PORT_COUNTER here

        # Added Code
        if 'fw' in payload:
            for item in payload['fw']:
                print(item)
                if 'ip' in item:
                    print(item['ip'])
                    print(item['args'])
                    self.launch_NFV('fw', payload['chain_id'], item['args'], item['ip'])
                else:
                    print(item['args'])
                    self.launch_NFV('fw', payload['chain_id'], item['args'])

        if 'nat' in payload:
            for item in payload['nat']:
                print(item)
                if item['ip']:
                    print(item['ip'])
                    print(item['args'])
                    self.launch_NFV('nat', payload['chain_id'], item['args'], item['ip'])
                else:
                    print(item['args'])
                    self.launch_NFV('nat', payload['chain_id'], item['args'])

        print("stop debuging")

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
        # if 'nat' in payload:
        #     # TODO call nat launch script/function with info from payload and registration_data
        #     nfs = [] # populate this with info for each nf created
        #     ''' Example
        #     NF_2 = {
        #         "INT_MAC" : "00:00:00:00:03:01",
        #         "EXT_MAC" : "00:00:00:00:03:02",
        #         "SWITCH_DPID" : 1,
        #         "INT_PORT" : 5,
        #         "EXT_PORT" : 6
        #     }
        #     '''
        #     self.nf_pools[chain_id]['nat'][0].extend(nfs)
        #     pass
        # if 'fw' in payload:
        #     # TODO call fw launch script/function with info from payload and registration_data
        #     nfs = [] # populate this with info for each nf created
        #     self.nf_pools[chain_id]['fw'][0].extend(nfs)
        #     pass

    def launch_NFV(self, type, chain_id, args, ip={}):
        nfv_port_1 = str(chain_id) + '_' + type + '_' + 'eth0'
        nfv_port_2 = str(chain_id) + '_' + type + '_' + 'eth1'



        if len(ip) == 0:
            print(len(ip))
            print('launch with NO IP')

            route1 = args[0]
            route2 = args[1]
            print(route1, route2)

            if type == 'fw':
                print('Type FW')
                container_name = str(chain_id) + '_' + type + '_' + str(self.nfv_container_index_launch)
                self.nfv_container_id.append(container_name)
                bash_command = f'docker run -d --privileged --name={container_name} --net=none fw:latest tail -f /dev/null'
                print(f'bash command {bash_command}')
                self._execute_shell_command(bash_command)

                # attach ports
                mac_of_nf = self.mac_to_nf[nfv_port_1]
                mac1 = mac_of_nf
                print(mac_of_nf)
                bash_command = f'ovs-docker add-port ovs-br1 eth0 {container_name} --macaddress="{mac_of_nf}"'
                print(f'bash command {bash_command}')
                self._execute_shell_command(bash_command)

                mac_of_nf = self.mac_to_nf[nfv_port_2]
                mac2 = mac_of_nf
                print(mac_of_nf)
                bash_command = f'ovs-docker add-port ovs-br1 eth1 {container_name} --macaddress="{mac_of_nf}"'
                print(f'bash command {bash_command}')
                self._execute_shell_command(bash_command)

                # run script
                bash_command = f'docker exec {container_name} bash /scripts/init_fw.sh -p eth0 -P eth01 -r {route1} -R {route2}'
                print(f'bash command {bash_command}')
                self._execute_shell_command(bash_command)
                print('done')

            elif type == 'nat':
                print('Type Nat')
                container_name = str(chain_id) + '_' + type + '_' + str(self.nfv_container_index_launch)
                self.nfv_container_id.append(container_name)
                bash_command = f'docker run -d --privileged --name={container_name} --net=none nat:latest tail -f /dev/null'
                print(f'bash command {bash_command}')
                self._execute_shell_command(bash_command)

                # attach ports
                mac_of_nf = self.mac_to_nf[nfv_port_1]
                print(mac_of_nf)
                bash_command = f'ovs-docker add-port ovs-br2 eth0 {container_name} --macaddress="{mac_of_nf}"'
                print(f'bash command {bash_command}')
                self._execute_shell_command(bash_command)

                mac_of_nf = self.mac_to_nf[nfv_port_2]
                print(mac_of_nf)
                bash_command = f'ovs-docker add-port ovs-br2 eth1 {container_name} --macaddress="{mac_of_nf}"'
                print(f'bash command {bash_command}')
                self._execute_shell_command(bash_command)

                # run script
                bash_command = f'docker exec {container_name} bash /scripts/init_nat.sh -p eth0 -P eth01 -r {route1} -R {route2}'
                print(f'bash command {bash_command}')
                self._execute_shell_command(bash_command)

        else:
            print('launch with IP')

            ip1 = ip['eth0']
            ip2 = ip['eth1']
            route1 = args[0]
            route2 = args[1]
            print(ip1, ip2, route1, route2)


            self.ip_to_nf[str(chain_id) + '_' + type + '_' + 'eth0'] = ip['eth0']
            self.ip_to_nf[str(chain_id) + '_' + type + '_' + 'eth1'] = ip['eth1']
            print(f'ip_to_nf {self.ip_to_nf}')

            if type == 'fw':
                print('Type FW IP')
                container_name = str(chain_id) + '_' + type + '_' + str(self.nfv_container_index_launch)
                self.nfv_container_id.append(container_name)
                bash_command = f'docker run -d --privileged --name={container_name} --net=none fw:latest tail -f /dev/null'
                print(f'bash command {bash_command}')
                self._execute_shell_command(bash_command)

                # attach ports
                mac_of_nf = self.mac_to_nf[nfv_port_1]
                ip_to_nf = ip['eth0']
                print(ip_to_nf)
                print(mac_of_nf)
                bash_command = f'ovs-docker add-port ovs-br1 eth0 {container_name} --macaddress="{mac_of_nf}" --ipaddress="{ip_to_nf}/24"'
                print(f'bash command {bash_command}')
                self._execute_shell_command(bash_command)

                mac_of_nf = self.mac_to_nf[nfv_port_2]
                ip_to_nf = ip['eth1']
                print(ip_to_nf)
                print(mac_of_nf)
                bash_command = f'ovs-docker add-port ovs-br1 eth1 {container_name} --macaddress="{mac_of_nf}" --ipaddress="{ip_to_nf}/24"'
                print(f'bash command {bash_command}')
                self._execute_shell_command(bash_command)

                # run script
                bash_command = f'docker exec {container_name} bash /scripts/init_fw.sh -p eth0 -P eth01 -i {ip1} -I {ip2} -r {route1} -R {route2}'
                print(f'bash command {bash_command}')
                self._execute_shell_command(bash_command)

            elif type == 'nat':
                print('Type NAT IP')
                container_name = str(chain_id) + '_' + type + '_' + str(self.nfv_container_index_launch)
                self.nfv_container_id.append(container_name)
                bash_command = f'docker run -d --privileged --name={container_name} --net=none nat:latest tail -f /dev/null'
                print(f'bash command {bash_command}')
                self._execute_shell_command(bash_command)

                # attach ports
                mac_of_nf = self.mac_to_nf[nfv_port_1]
                ip_to_nf = ip['eth0']
                print(ip_to_nf)
                print(mac_of_nf)
                bash_command = f'ovs-docker add-port ovs-br2 eth0 {container_name} --macaddress="{mac_of_nf}" --ipaddress="{ip_to_nf}/24"'
                print(f'bash command {bash_command}')
                self._execute_shell_command(bash_command)

                mac_of_nf = self.mac_to_nf[nfv_port_2]
                ip_to_nf = ip['eth1']
                print(ip_to_nf)
                print(mac_of_nf)
                bash_command = f'ovs-docker add-port ovs-br2 eth1 {container_name} --macaddress="{mac_of_nf}" --ipaddress="{ip_to_nf}/24"'
                print(f'bash command {bash_command}')
                self._execute_shell_command(bash_command)

                # run script
                bash_command = f'docker exec {container_name} bash /scripts/init_nat.sh -p eth0 -P eth01 -i {ip1} -I {ip2} -r {route1} -R {route2}'
                print(f'bash command {bash_command}')
                self._execute_shell_command(bash_command)
                
            self.nfv_container_index_launch = self.nfv_container_index_launch + 1




class RestController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(RestController, self).__init__(req, link, data, **config)
        self.app = data[app_instance_name]




    @route('register', register_url, methods=['PUT']) # , requirements={'dpid': dpid_lib.DPID_PATTERN})
    def register(self, req, **kwargs):

        ryu_app_nfv = self.app

        # dpid = dpid_lib.str_to_dpid(kwargs['dpid'])

        try:
            new_entry = req.json if req.body else {}
        except ValueError:
            raise Response(status=400)

        # if dpid not in ryu_app_nfv.switches_added:
        #     print('switches array {}'.format(ryu_app_nfv.switches_added))
        #     return Response(status=404)

        try:
            print(f'new_entry: {new_entry}')
            ryu_app_nfv.register_nf_chain(new_entry)
            
            return Response(content_type='application/json', status=201)

        except Exception as e:
            print(e)
            return Response(status=500)

    @route('launch', launch_url, methods=['PUT']) #, requirements={'dpid': dpid_lib.DPID_PATTERN})
    def launch(self, req, **kwargs):

        ryu_app_nfv = self.app

        # dpid = dpid_lib.str_to_dpid(kwargs['dpid'])

        try:
            launch_payload = req.json if req.body else {}
        except ValueError:
            raise Response(status=400)

        # if dpid not in ryu_app_nfv.switches_added:
        #     print('switches array {}'.format(ryu_app_nfv.switches_added))
        #     return Response(status=404)

        try:
            print(f'new_entry: {launch_payload}')
            ryu_app_nfv.launch_nfs(launch_payload)
            
            return Response(content_type='application/json', status=201)

        except Exception as e:
            print("error with", e)
            return Response(status=500)

