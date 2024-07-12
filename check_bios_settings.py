#!/usr/bin/env python
import sys
import os
import time
import argparse
import json
import requests
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

def get_bios_settings(host, username, password):
    target_url = "https://[{0}]/redfish/v1/Systems/Self/Bios".format(host)
    response = requests.get(target_url, verify=False, auth=(username, password))
    data = response.json()
    return data

def get_template_settings(filepath):
    fd = open(filepath, 'r')
    template_settings = json.load(fd)
    return template_settings

def check_bios_settings(host, username, password, filepath):
    if check_credential(host, username, password) == False:
        logger.info("Username or password might be wrong.")
        return False
    bios_settings = get_bios_settings(host, username, password)
    template_settings = get_template_settings(filepath)
    for key in template_settings['Attributes'].keys():
        if not key in bios_settings['Attributes'].keys():
            logger.info("{0} is not in actual settings".format(key))
        elif not template_settings['Attributes'][key] == bios_settings['Attributes'][key]:
            logger.info("Key({0}) Template({1}) Actual({2})".format(key, template_settings['Attributes'][key], bios_settings['Attributes'][key]))

    for key in bios_settings['Attributes'].keys():
        if not key in template_settings['Attributes'].keys():
            logger.info("{0} is not in template settings".format(key))

def main():
    parser = argparse.ArgumentParser(description='This script compares actual bios settings and expected one which we got from Altiostar testbed.')
    parser.add_argument("host", type=str, help='target BMC ipv6 address or hostname.')
    parser.add_argument("-u", "--username", dest='username', type=str, default="admin", help='username to log into target.')
    parser.add_argument("-p", "--password", dest='password', type=str, default="cmb9.admin", help='password to log into target.')
    parser.add_argument("-f", "--filepath", dest='filepath', type=str, default="./template.json", help='path for json file including expected bios settings.')
    parser.add_argument("-l", "--loglevel", dest='set_loglevel', type=str, default="INFO", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
    params = parser.parse_args()

    if params.set_loglevel == "DEBUG": logger.setLevel(DEBUG)
    elif params.set_loglevel == "INFO": logger.setLevel(INFO)
    elif params.set_loglevel == "WARNING": logger.setLevel(WARNING)
    elif params.set_loglevel == "ERROR": logger.setLevel(ERROR)
    elif params.set_loglevel == "CRITICAL": logger.setLevel(CRITICAL)
    
    check_bios_settings(params.host, params.username, params.password, params.filepath)

if __name__ == '__main__': main()
