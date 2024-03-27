import os
import json
import ipaddress
import socket
from pathlib import Path
from pprint import pprint

def get_ip_info():
    ret_val = None
    command = 'netsh interface ipv4 show addresses'
    output = os.popen(command).read()
    blocks = [b.replace('"', '') for b in output.split('Configuration for interface ')]
    adapters = []
    for block in blocks:
        if 'DHCP enabled' in block:
            lines = block.splitlines()
            adapter = {
                'name': lines[0]
            }
            for line in lines:
                if 'Subnet Prefix' in line:
                    for word in line.split():
                        if '/' in word:
                            adapter['vlsm'] = word
            if 'vlsm' in adapter:
                adapters.append(adapter)
    ret_val = adapters
    return ret_val

def build_host_list(network):
    network = ipaddress.ip_network(network, strict=False)
    hosts = []
    for host in network.hosts():
        hosts.append(str(host))
    return hosts

def check_open_ports(host):
    open_ports = []
    for port in range(10000, 40000):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((host, port))
                print(f'{host} --> {port} is open')
                open_ports.append(port)
        except:
            pass
    return open_ports

def host_is_alive(host):
    ret_val = False
    output = os.popen(f'ping -n 1 {host}').read()
    for line in output.splitlines():
        if 'TTL=' in line:
            ret_val = True
            break
    return ret_val

def main():
    adapters = get_ip_info()
    wifi_adapter = None
    for adapter in adapters:
        if adapter['name'] == 'Wi-Fi':
            wifi_adapter = adapter
    if not wifi_adapter:
        print('No wireless adapter found')
        raise SystemExit
    hosts = build_host_list(wifi_adapter['vlsm'])
    for host in hosts:
        if host_is_alive(host):
            open_ports = check_open_ports(host)
            for port in open_ports:
                print(f'{host} --> {port}')

if __name__ == '__main__':
    main()
