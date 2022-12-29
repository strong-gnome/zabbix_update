"""
Script gathers hosts filtered by specific group from Zabbix server.
Then it collects attached templates and macros, define providers and CE ip.
Finally, it updates hosts on Zabbix with required templates and macros.
"""

import time
import argparse
import re
import logging
from requests import post
from requests import exceptions
from sys import exit
from json import dump
from json import dumps
from getpass import getpass
from netmiko import ConnectHandler
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from urllib3 import exceptions as urllib_exceptions


# Wrapper to check performance time.
def duration(func):
    def wrapper():
        tic = time.perf_counter()
        func()
        print(time.perf_counter() - tic)

    return wrapper


# Parsing incoming options.
parser = argparse.ArgumentParser()
parser.add_argument('-s', '--username-ssh', type=str, help="provide login for ssh authentication")
parser.add_argument('-z', '--username-zabbix', type=str, help="provide login for zabbix authentication")
parser.add_argument('-r', '--results', type=str, default='logs', help='specify name of file with logs')
ssh_password = getpass('Password for SSH authentication:')
zabbix_password = getpass('Password for Zabbix authentication:')
options = parser.parse_args()
if not options.username_ssh:
    exit('No username for ssh provided')
elif not ssh_password:
    exit('No password for ssh provided')
elif not options.username_zabbix:
    exit('No username for zabbix provided')
elif not zabbix_password:
    exit('No password for zabbix provided')
if options.results:
    if re.search('.*.txt&', options.results):
        log_name = options.results
    else:
        log_name = f'{options.results}.txt'

m = '13532'
# Define file handler to place logs in external file
fh = logging.FileHandler(log_name, mode='w')
log_format = logging.Formatter(fmt='{name} - {levelname} - {message}', style='{')
fh.setFormatter(log_format)


# Class to interact with Zabbix API
class zabbix_api:
    HEADERS = {'Content-Type': 'application/json-rpc'}
    hosts_dict = {}
    hosts_list = []
    logger = logging.getLogger('Zabbix api')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(fh)
    payload = {
        "jsonrpc": "2.0",
        "method": '',
        "params": {},
        "id": 1,
        "auth": None
    }
    BLACKBOX_TEMPLATES = {
        'PROVIDER1': {
            'host': 'Blackbox PROVIDER1 ICMP',
            'templateid': '11111',
        },
        'PROVIDER2': {
            'host': 'Blackbox PROVIDER2 ICMP',
            'templateid': '11112',
        },
        'PROVIDER3': {
            'host': 'Blackbox PROVIDER3 ICMP',
            'templateid': '11113',
        },
        'PROVIDER4': {
            'host': 'Blackbox PROVIDER4 ICMP',
            'templateid': '11114',
        },
        'PROVIDER5': {
            'host': 'Blackbox PROVIDER5 ICMP',
            'templateid': '11115',
        },
        'PROVIDER6': {
            'host': 'Blackbox PROVIDER6 ICMP',
            'templateid': '11116',
        },
        'PROVIDER7': {
            'host': 'Blackbox PROVIDER7 ICMP',
            'templateid': '11117',
        },
    }

    # Just at the initialization of a class the script will authorizes with provided user/passwd and get auth token
    # for future operations with API
    def __init__(self, url, username, password, fh):
        self.ZBX_URL = url.rstrip('/') + '/api_jsonrpc.php'
        self.username = username
        self.passwd = password
        self.fh = fh
        self.get_oauth()

    def post_request(self, url, headers, payload):
        try:
            #self.logger.debug(msg=f'Provided payload: {payload}')
            r = post(url, headers=headers, data=dumps(payload), verify=False)
            if 'error' in list(r.json().keys()):
                self.logger.error(msg=f'Server couldnt handle request and replied with error: {r.json()["error"]["message"]}, reason: {r.json()["error"]["data"]}')
                return ConnectionError
            else:
                #self.logger.debug(msg=f'Resulted json: {r.json()}')
                return r.json()
        except exceptions.Timeout as err:
            self.logger.error(msg=f'Timeout exceeded:\n{err}')
        except exceptions.ConnectionError as err:
            self.logger.error(msg=f'Error raised during connection:\n{err}')
        except exceptions.RequestsWarning as warn:
            self.logger.warning(msg=f'Warning raised during connection:\n{warn}')

    # Authorize and get auth token
    def get_oauth(self):
        self.payload['method'], self.payload['params'] = 'user.login', {'user': self.username, 'password': self.passwd}
        #self.logger.debug(msg=f'API method {self.payload["method"]}, API parameters {self.payload["params"]}')
        #self.logger.debug(msg=f'Payload {self.payload}')
        try:
            r = self.post_request(self.ZBX_URL, self.HEADERS, self.payload)
            if r == ConnectionError:
                raise ConnectionError
            self.payload['auth'] = r['result']
            self.logger.info(msg='OAuth token gathered')
        except ConnectionError:
            exit('An error occurred while authorization process. Check logs')

    def get_host_ids(self):
        Routers_group_id = '140'
        self.payload['method'], self.payload['params'] = 'host.get', {'groupids': Routers_group_id}
        try:
            # Request all hosts from the group-id 140 (routers group)
            r = self.post_request(self.ZBX_URL, self.HEADERS, self.payload)
            if r == ConnectionError:
                raise ConnectionError
            self.logger.info(msg='Hosts gathered')
            # Move through gathered hosts and form a dict for each one
            for host in r['result']:
                self.hosts_list.append(host['hostid'])
                self.hosts_dict.update({host['hostid']: {
                    'hostname': host['host'],
                    'ip': None,
                    'templates': [],
                    'macros': [],
                    'providers': [],
                }})
        except ConnectionError:
            exit('An error occurred while hosts had been gathered. Check logs')

    def get_host_ips(self):
        self.payload['method'], self.payload['params'] = 'hostinterface.get', {'hostids': self.hosts_list}
        try:
            # Request all host interfaces for the gathered host-ids
            r = self.post_request(self.ZBX_URL, self.HEADERS, self.payload)
            if r == ConnectionError:
                raise ConnectionError
            self.logger.info(msg='IPs gathered')
            # Move through the host interfaces and bind host-id with referred ip
            for interface in r['result']:
                self.hosts_dict[interface['hostid']].update({'ip': interface['ip']})
        except ConnectionError:
            exit('An error occurred while hosts ips had been gathered. Check logs')

    def get_host_templates(self):
        self.payload['method'], self.payload['params'] = 'template.get', {'hostids': self.hosts_list}
        try:
            # Request all possible templates for gathered host-ids
            r = self.post_request(self.ZBX_URL, self.HEADERS, self.payload)
            if r == ConnectionError:
                raise ConnectionError
            self.logger.info(msg='Templates gathered')
            # Move through the templates and form the list
            template_list = []
            for template in r['result']:
                template_list.append(template['templateid'])
            # After the list of templates is made, we are able to move through them
            # and bind iterated templates with respective hosts
            self.payload['method'] = 'host.get'
            for template_id in template_list:
                self.payload['params'] = {'templateids': template_id}
                r = self.post_request(self.ZBX_URL, self.HEADERS, self.payload)
                for i in r['result']:
                    self.hosts_dict[i['hostid']]['templates'].append({'templateid': template_id})
                self.logger.info(msg=f'Template {template_id} has been checked')
        except ConnectionError:
            exit('An error occurred while templates had been gathered. Check logs')

    def get_host_macros(self):
        self.payload['method'] = 'usermacro.get'
        try:
            for i in self.hosts_list:
                self.payload['params'] = {'hostids': i}
                r = self.post_request(self.ZBX_URL, self.HEADERS, self.payload)
                if r == ConnectionError:
                    raise ConnectionError
                self.logger.info(msg=f'Macros for {self.hosts_dict[i]["ip"]} have been gathered')
                macro_list = []
                for x in r['result']:
                    macro_list.append({'macro': x['macro'], 'value': x['value']})
                if self.hosts_dict[i]['providers']:
                    for x in self.hosts_dict[i]['providers']:
                        macro_list.append({'macro': f'{{${x["provider"]}_IP}}', 'value': x['ip']})
                self.hosts_dict[i].update({'macros': macro_list})
        except ConnectionError:
            exit('An error occurred while macros had been gathered. Check logs')

    def update_hosts(self):
        self.payload['method'] = 'host.update'
        try:
            for i in self.hosts_list:
                self.payload['params'] = {
                    'hostid': i,
                    'templates': self.hosts_dict[i]['templates'],
                    'macros': self.hosts_dict[i]['macros'],
                }
                r = self.post_request(self.ZBX_URL, self.HEADERS, self.payload)
                if r == ConnectionError:
                    raise ConnectionError
            self.logger.info(msg='All hosts have been updated')
        except ConnectionError:
            exit('An error occurred while hosts had been updated. Check logs')


class router:
    ips_list = []
    locker = Lock()
    logger = logging.getLogger('Router')
    logger.setLevel(logging.INFO)
    logger.addHandler(fh)
    VPLS_PROVIDERS = {
        "172.16.21.": "PROVIDER1",
        "172.16.22.": "PROVIDER2",
        "172.16.23.": "PROVIDER3",
        "172.16.24.": "PROVIDER4",
        "172.16.25.": "PROVIDER5",
        "172.16.26.": "PROVIDER6",
        "172.16.27.": "PROVIDER7",
    }
    IPVPN_PROVIDERS = {
        "12341": "PROVIDER1",
        "12342": "PROVIDER2",
        "12343": "PROVIDER3",
        "12346": "PROVIDER6",
    }

    def __init__(self, username: str, password: str, routers_dict, fh):
        self.password = password
        self.username = username
        self.routers = routers_dict
        self.fh = fh

    def collect_ips(self):
        self.logger.debug(msg=f'Routers provided: {list(self.routers.keys())}')
        for i in list(self.routers.keys()):
            self.ips_list.append({self.routers[i]['ip']: i})
        self.logger.info(msg='IPs collected to the list')

    def connect_router(self, address):
        router = {
            'device_type': 'cisco_ios',
            'host': address,
            'username': self.username,
            'password': self.password
        }
        try:
            device = ConnectHandler(**router)
            return device
        except Exception as err:
            self.logger.error(msg=f'Error occurred: {err}')

    def collect_info(self, host):
        host_ip = list(host.keys())[0]
        host_id = host[host_ip]
        logger_device = logging.getLogger(f'Router.{host_ip}')
        logger_device.setLevel(logging.DEBUG)
        bgp_neighbor = re.compile('(?P<neighbor>\d+\.\d+\.\d+\.)\d+\s+4\s+(?P<bgp_as>\d{4,5}).*')
        interface_analyze = re.compile('\d+\.\d+\.\d+\.\d+')
        device_providers = []
        try:
            device = self.connect_router(host_ip)
            logger_device.info(msg=f'connection established')

            # Collecting data from router, so we can extract required info from outputs.
            show_interfaces = device.send_command('sh ip int br')
            show_bgp = device.send_command('sh ip bgp sum | begin Neighbor')
            logger_device.info(msg=f'data collected')

            # Checking bgp output, if there are any IPVPN neighbors.
            # Then add CE of IPVPN to the list.
            if show_bgp:
                for match in bgp_neighbor.finditer(show_bgp):
                    if match.group('bgp_as') in list(self.IPVPN_PROVIDERS.keys()):
                        device_providers.append({
                            'provider': self.IPVPN_PROVIDERS[match.group('bgp_as')],
                            'ip': re.search(match.group('neighbor') + '\d+', show_interfaces).group()
                        })
            else:
                logger_device.info(msg='no bgp found')
            logger_device.info(msg='IPVPN checked')

            # Checking the interfaces, if there are any of federal VPLS channels and what are the addresses for ipvpn
            if show_interfaces:
                for match in interface_analyze.finditer(show_interfaces):
                    shorten_ip = re.search('\d+\.\d+\.\d+\.', match.group()).group()
                    if shorten_ip in list(self.VPLS_PROVIDERS.keys()):
                        device_providers.append({
                            'provider': self.VPLS_PROVIDERS[shorten_ip],
                            'ip': match.group()
                        })
                        logger_device.info(msg='VPLS provider added')
            logger_device.info(msg=f'VPLS checked')

            # Adding collected data to common dict
            self.locker.acquire()
            logger_device.debug(msg=f'Providers: {device_providers}')
            self.routers[host_id].update({'providers': device_providers})
            logger_device.info(msg='Providers uploaded for specific host')
            self.locker.release()

        except (Exception, ValueError, EOFError, ConnectionError) as exc:
            self.logger.error(msg=f'some error on connection to device occurred: {exc}')


@duration
def some_func():
    logger = logging.getLogger('Main function')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(fh)
    try:
        connect_zbx = zabbix_api('https://zbxusi.localserver.company-domain.net/', options.username_zabbix, zabbix_password, logger)
        connect_zbx.get_host_ids()
        connect_zbx.get_host_ips()
        connect_zbx.get_host_templates()
        check_devices = router(options.username_ssh, ssh_password, connect_zbx.hosts_dict, logger)
        check_devices.collect_ips()
        logger.debug(msg=f'Collected IPs: {check_devices.ips_list}')

        with ThreadPoolExecutor(max_workers=30) as executor:
            for i in check_devices.ips_list:
                executor.submit(check_devices.collect_info, i)

        connect_zbx.get_host_macros()
        connect_zbx.update_hosts()

        with open('json_result.txt', mode='w') as textfile:
            dump(connect_zbx.hosts_dict, textfile, indent=4)
    except Exception or EOFError as err:
        logger.error(msg=f'Some error in main program occurred: {err}')


if __name__ == '__main__':
    some_func()
