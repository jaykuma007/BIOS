#!/usr/bin/env python
import sys
import os
import time
import argparse
import json
import requests
import pexpect
import yaml
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from logging import getLogger, StreamHandler, DEBUG, INFO, WARNING, CRITICAL, ERROR, Formatter
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

formatter = Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = getLogger(__name__)
handler = StreamHandler(sys.stdout)
handler.setLevel(DEBUG)
handler.formatter = formatter
logger.addHandler(handler)
logger.setLevel(DEBUG)

def check_credential(host, username, password):
    target_url = "https://[{0}]/redfish/v1/Systems/Self".format(host)
    response = requests.get(target_url, verify=False, auth=(username, password))
    data = response.json()
    if ('error' in data) == True:
        return False
        logger.debug(json.dumps(data, indent=4))
    else:
        return True

def get_bmc_system_info(bmchost, bmcusername, bmcpassword):
    target_url = "https://[{0}]/redfish/v1/Systems/Self".format(bmchost)
    response = requests.get(target_url, verify=False, auth=(bmcusername, bmcpassword))
    node_data = response.json()
    logger.debug(json.dumps(node_data, indent=4))
    return node_data

def get_bmc_nic_info(bmchost, bmcusername, bmcpassword):
    target_url = "https://[{0}]/redfish/v1/Managers/Self/EthernetInterfaces/eth0".format(bmchost)
    response = requests.get(target_url, verify=False, auth=(bmcusername, bmcpassword))
    node_data = response.json()
    logger.debug(json.dumps(node_data, indent=4))
    return node_data


def get_cobbler_data(host, serverusername, serverpassword, podid=""):
    server = pexpect.spawn('scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {0}@\[{1}\]:/root/openstack-configs/.cobbler_data.yaml ./cobbler_data{2}.yaml'.format(serverusername, host, podid))
    server.expect('.*ssword:*')
    server.sendline(serverpassword)
    server.expect(pexpect.EOF)
    server.terminate()

def get_node_list(bmcusername, bmcpassword, podid=""):
    fd = open("./cobbler_data{0}.yaml".format(podid))
    nodes = yaml.load(fd)
    logger.debug(nodes)
    for node in nodes:
        logger.debug("Hostname: {0}".format(node))
        if not check_credential(nodes[node]["cimc_ip"], bmcusername, bmcpassword):
            print("{0},{1},{2},{3},{4},{5}".format(node, nodes[node]["cimc_ip"], "NA", "NA", "NA", "NA"))
            continue
        bmc_system_info = get_bmc_system_info(nodes[node]["cimc_ip"], bmcusername, bmcpassword)
        bmc_nic_info = get_bmc_nic_info(nodes[node]["cimc_ip"], bmcusername, bmcpassword)
        print("{0},{1},{2},{3},{4},{5}".format(node, nodes[node]["cimc_ip"], bmc_system_info["SerialNumber"], bmc_system_info["BiosVersion"], bmc_system_info["Oem"]["Quanta_RackScale"]["FirmwareVersion"], bmc_nic_info["MACAddress"]))

def main():
    parser = argparse.ArgumentParser(description='Script to get node information including Hostname, Serial, BMC version, BIOS version')
    parser.add_argument("host", type=str, help='address for management node')
    parser.add_argument("-u", "--serverusername", dest='serverusername',type=str, default="admin", help='sername for management node')
    parser.add_argument("-p", "--serverpassword", dest='serverpassword',type=str, default="Rakuten1234!", help='password for management node')
    parser.add_argument("-U", "--bmcusername", dest='bmcusername', type=str, default="admin", help='username for BMC redfish')
    parser.add_argument("-P", "--bmcpassword", dest='bmcpassword', type=str, default="cmb9.admin", help='password for BMC redfish')
    parser.add_argument("-t", "--tag", dest='tag', type=str, default="", help='tag name for file id')
    parser.add_argument("-l", "--loglevel", dest='set_loglevel', type=str, default="INFO", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
    params = parser.parse_args()

    if params.set_loglevel == "DEBUG": logger.setLevel(DEBUG)
    elif params.set_loglevel == "INFO": logger.setLevel(INFO)
    elif params.set_loglevel == "WARNING": logger.setLevel(WARNING)
    elif params.set_loglevel == "ERROR": logger.setLevel(ERROR)
    elif params.set_loglevel == "CRITICAL": logger.setLevel(CRITICAL)
    
    get_cobbler_data(params.host, params.serverusername, params.serverpassword, params.tag)
    get_node_list(params.bmcusername, params.bmcpassword, params.tag)

if __name__ == '__main__': main()

