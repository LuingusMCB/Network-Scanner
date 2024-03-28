import os
import json
import ipaddress
import socket
import sys
from pathlib import Path
import concurrent.futures
from pprint import pprint
import time
import threading

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

def check_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((host, port))
            sys.stdout.flush()
            sys.stdout.write(f'{host} --> {port} is open' + '\n')
            sys.stdout.flush()
            return port
    except:
        return None

def check_open_ports(host):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(check_port, host, port): port for port in range(10000, 40000)}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                data = future.result()
                if data is not None:
                    open_ports.append(data)
            except Exception as exc:
                sys.stdout.flush()
                sys.stdout.write(f'Port {port} generated an exception: {exc}' + '\n')
                sys.stdout.flush()
    return open_ports

def check_open_ports_orig(host):
    open_ports = []
    for port in range(10000, 40000):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((host, port))
                sys.stdout.write(f'{host} --> {port} is open' + '\n')
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
                try:
                    socket_instance = socket.socket()
                    socket_instance.connect((host, port))
                    threading.Thread(target=handle_messages, args=[socket_instance]).start()
                    print('Connected to chat!')
                    while True:
                        msg = input()

                        if msg == 'quit':
                            break

                        if msg == 'spam':
                            while True:
                                time.sleep(1)
                                msg = 'Hello'

                        socket_instance.send(msg.encode())
                    socket_instance.close()
                except Exception as e:
                    print(f'Error connecting to server socket {e}')
                    socket_instance.close()
                    break

def handle_messages(connection: socket.socket):
    while True:
        try:
            msg = connection.recv(1024)
            if msg:
                print(msg.decode())
            else:
                connection.close()
                break
        except Exception as e:
            print(f'Error handling message from server: {e}')
            connection.close()
            break

if __name__ == '__main__':
    main()