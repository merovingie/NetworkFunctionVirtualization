from threading import Timer
from os import link
import logging
import sys
import subprocess
import ast
import json
import copy
import os
import time

from collections import defaultdict

ips = {
    'src1': "192.168.1.2",
    'src2': "192.168.1.3",
    'dst1': "143.12.131.92",
    'dst2': "143.12.131.93"
}

# no need for this time till cancel part just thought we might need it
class RepeatTimer(Timer):
    def run(self):
        while not self.finished.wait(self.interval):
            self.function(*self.args,**self.kwargs)
            print(' ')



class testingProfile():
    def __init__(self, file_name):
        self.profiles = {}
        self.init_Iperf = {}
        self.parse_profile_config(file_name='traffic_profile.json')
        print(self.profiles)


    def parse_profile_config(self, file_name):
        print(f'Reading {file_name} for testing data')
        file = open(file_name)
        self.profiles = json.load(file)

        for profile in self.profiles["profiles"]:
            print(profile)
            val = profile['src_container']
            profile['src_ip'] = ips[val]
            print(profile)
            for flow in profile['flows']:
                print(flow)
                duration = int(flow['end_time']) - int(flow['start_time'])
                flow['duration'] = duration
            key = str(profile['src_container']) + '_' + str(profile["dst_container"] + '_' + str(profile['dst_ip']))
            value = profile['flows']
            self.init_Iperf[key] = value
            print(self.init_Iperf)

    # start server
    def startIperfServer(self):
        for host in ips.keys():
            print(f'host to start server on {host}')
            cmd = f'docker exec {host} iperf3 -s &'
            print(cmd)
            self._execute_shell_command(cmd)
        print('All Server Started')

    # start client
    def startIperfClient(self, src, src_ip, run_time, num_flows):
        cmd = f'docker exec {src} iperf3 -c {src_ip} -t {run_time} -P {num_flows} &'
        print(cmd)
        self._execute_shell_command(cmd)

    def scheduleIperfTests(self, flows):
        print(f'starting clients with flows {flows}')
        for flow in flows.items():
            print(f'\ncurrent flow {flow}')
            src = flow[0].split('_')[1]
            src_ip = flow[0].split('_')[2]
            flow_details = flow[1]
            print(flow_details)
            t = Timer(
                    flow_details[0]['start_time'],
                    testingProfile.startIperfClient,
                    [
                        self,
                        src,
                        src_ip,
                        flow_details[0]['duration'],
                        flow_details[0]['num_flows']
                    ]
                )
            t.start()
        print('Finished scheduling all tests!')

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

def main():
    test = testingProfile('traffic_profile.json')
    test.startIperfServer()
    test.scheduleIperfTests(test.init_Iperf)

if __name__ == '__main__':
    main()


