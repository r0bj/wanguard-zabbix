#!/usr/bin/python

# Copyright (c) 2012-2014 Robert Jerzak
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import requests
import json
import sys
import subprocess
import re
import time
import logging
import signal

zbx_api_host = '10.2.201.6'
zbx_api_url = 'http://%s/api_jsonrpc.php' % zbx_api_host
zbx_api_user = 'wanguard'
zbx_api_pass = '6MGHFxe5TJEbVvF2'

wg_host = 'wanguard' # host used in zabbix
wg_app = 'wanguard' # application used in zabbix
zbx_item_name = 'anomaly' # item pattern used in zabbix
zbx_item_key = 'anomaly' # item key pattern used in zabbix

logfile = '/var/log/wanguard-notify.log'
connection_timeout = 5

class ZabbixAPIError(Exception):
    pass

class Alarm(Exception):
    pass

def alarm_handler(signum, frame):
	raise Alarm

class ZabbixConnection:
	__api_url = None
	__api_user = None
	__api_pass = None
	__api_token = None

	def __init__(self, url, user, passwd):
		self.__api_url = url
		self.__api_user = user
		self.__api_pass = passwd
		self.__api_token = self.__auth()

	def __callAPI(self, json_data):
		headers = {
			'Content-Type': 'application/json-rpc',
			'User-Agent': 'ZabbixAPI Client',
		}

		signal.signal(signal.SIGALRM, alarm_handler)
		signal.alarm(connection_timeout)
		try:
			r = requests.post(self.__api_url, data=json_data, headers=headers, timeout=connection_timeout)
			signal.alarm(0)
		except requests.exceptions.ConnectionError:
			raise ZabbixAPIError('HTTP connection error')
		except Alarm:
			raise ZabbixAPIError('HTTP connection timeout')

		if r.status_code == 200 and r.content != '':
			c = json.loads(r.content)
			if 'error' in c:
				raise ZabbixAPIError('API error: code: %s message: %s data: %s'
					%(str(c['error']['code']), str(c['error']['message']), str(c['error']['data'])))
			elif 'result' in c:
				return c['result']
			else:
				raise ZabbixAPIError('Wrong API result')
		else:
			raise ZabbixAPIError('Wrong API response content: HTTP code %s' % r.status_code)

	def __auth(self):
		req = {
			'jsonrpc': '2.0',
			'method': 'user.login',
			'params': {
				'user': self.__api_user,
				'password': self.__api_pass,
			},
			'id': '0',
		}

		token = self.__callAPI(json.dumps(req))
		if token != '':
			return token
		else:
			raise ZabbixAPIError('Wrong API auth token')

	def send(self, data):
		data['auth'] = self.__api_token
		data['jsonrpc'] = '2.0'
		data['id'] = '0'
		return self.__callAPI(json.dumps(data))

class ZabbixAPI:
	__zconn = None

	def __init__(self, url, user, passwd):
		self.__zconn = ZabbixConnection(url, user, passwd)

	def __find_hostid(self, hostname):
		req = {
			'method': 'host.get',
			'params': {
				'output': ['hostid'],
				'filter': {
					'host': [hostname],
				},
			},
		}

		result = self.__zconn.send(req)
		try:
			return result[0]['hostid']
		except (KeyError, IndexError):
			raise ZabbixAPIError('Error: cannot find hostid for hostname %s' % hostname)

	def __find_hostinterfaceid_by_hostid(self, hostid):
		req = {
			'method': 'hostinterface.get',
			'params': {
				'output': ['interfaceid'],
				'hostids': hostid,
			},
		}

		result = self.__zconn.send(req)
		try:
			return result[0]['interfaceid']
		except (KeyError, IndexError):
			raise ZabbixAPIError('Error: cannot find hostinterfaceid for hostid ' % hostid)

	def __find_applicationid_by_hostid(self, name, hostid):
		req = {
			'method': 'application.get',
			'params': {
				'output': ['applicationid'],
				'hostids': hostid,
				'filter': {
					'name': name,
				},
			},
		}		

		result = self.__zconn.send(req)
		try:
			return result[0]['applicationid']
		except (KeyError, IndexError):
			return self.__create_application_by_hostid(name, hostid)

	def __create_application_by_hostid(self, name, hostid):
		req = {
			'method': 'application.create',
			'params': {
				'name': name,
				'hostid': hostid,
			},
		}

		result = self.__zconn.send(req)
		try:
			return result['applicationids'][0]
		except (KeyError, IndexError):
			raise ZabbixAPIError('Error: cannot create application %s on hostid %s' %(name, hostid))

	def create_item(self, hostname, app, item_name, item_key):
		hostid = self.__find_hostid(hostname)
		hostinterfaceid = self.__find_hostinterfaceid_by_hostid(hostid)
		appid = self.__find_applicationid_by_hostid(app, hostid)

		req = {
			'method': 'item.create',
			'params': {
				'name': item_name,
				'key_': item_key,
				'hostid': hostid,
				'type': '2',
				'value_type': '4',
				'interfaceid': hostinterfaceid,
				'applications': [appid],
				'delay': '60',
				'history': '0',
			},
		}

		result = self.__zconn.send(req)
		try:
			return result['itemids'][0]
		except (KeyError, IndexError):
			raise ZabbixAPIError('Error: cannot create item %s on host %s' %(item_name, hostname))

	def exists_item(self, hostname, item_key):
		req = {
			'method': 'item.exists',
			'params': {
				'host': hostname,
				'key_': item_key,
			},
		}

		result = self.__zconn.send(req)
		if result:
			return True
		else:
			return False

	def __prepare_trigger(self, anomaly, hostname, item_key):
		m = re.match(r'\S+\s+\[(.*)\]', anomaly['sensor'])
		if m:
			anomaly['sensor'] = m.group(1)

		perc = int(round(float(anomaly['severity']) * 100))
		if perc <= 110:
			severity = 2
		elif perc > 110 and perc <= 150:
			severity = 3
		elif perc > 150:
			severity = 4

		if anomaly['direction'] == 'incoming':
			direction = '->'
		elif anomaly['direction'] == 'outgoing':
			direction = '<-'

		name = '#%s %s %s%s [%s %s] = %s%%' %(
			anomaly['id'],
			anomaly['sensor'],
			direction, anomaly['ip'],
			anomaly['decoder'],
			anomaly['unit'],
			perc
		)

		expression = self.__prepare_trigger_expression(hostname, item_key)

		return (name, severity, expression)

	def __prepare_trigger_expression(self, hostname, item_key):
		expression = '{%s:%s.now()}>0' %(hostname, item_key)
		return expression

	def create_trigger(self, hostname, item_key, anomaly):
		name, severity, expression = self.__prepare_trigger(anomaly, hostname, item_key)

		req = {
			'method': 'trigger.create',
			'params': {
				'description': name,
				'expression': expression,
				'priority': severity,
			},
		}

		result = self.__zconn.send(req)
		try:
			return result['triggerids'][0]
		except (KeyError, IndexError):
			raise ZabbixAPIError('Error: cannot create trigger on item key %s on host %s' %(item_key, hostname))

	def exists_trigger(self, hostname, item_key):
		expression = self.__prepare_trigger_expression(hostname, item_key)
		req = {
			'method': 'trigger.exists',
			'params': {
				'expression': expression,
				'host': hostname,
			},
		}

		result = self.__zconn.send(req)
		if result:
			return True
		else:
			return False

	def __find_itemid(self, hostname, item_key):
		req = {
			'method': 'item.get',
			'params': {
				'output': ['itemid'],
				'host': hostname,
				'search': {
					'key_': item_key,
				},
			},
		}		

		result = self.__zconn.send(req)
		try:
			return result[0]['itemid']
		except (KeyError, IndexError):
			raise ZabbixAPIError('Error: cannot find itemid for item key %s on host %s' %(item_key, hostname))

	def del_item(self, hostname, item_key):
		itemid = self.__find_itemid(hostname, item_key)
		req = {
			'method': 'item.delete',
			'params': [itemid],
		}		

		result = self.__zconn.send(req)
		try:
			return result['itemids'][0]
		except (KeyError, IndexError):
			raise ZabbixAPIError('Error: cannot delete item %s on host %s' %(name, hostname))

## MAIN

requests_log = logging.getLogger('requests')
requests_log.setLevel(logging.WARNING)
logging.basicConfig(format='%(asctime)s %(levelname)s:%(message)s', filename=logfile, level=logging.DEBUG)

if len(sys.argv) != 3 and len(sys.argv) != 9:
	logging.error('Wrong program execution parameters: ' + ' '.join(sys.argv))
	sys.exit('Usage: %s [add|del] {anomaly_id} {sensor} {direction} {ip} {decoder} {unit} {severity}' % sys.argv[0])

logging.info('Program execution: ' + ' '.join(sys.argv))
try:
	za = ZabbixAPI(zbx_api_url, zbx_api_user, zbx_api_pass)
except ZabbixAPIError as e:
	logging.error(e.message)
	sys.exit(1)

action = sys.argv[1]
if action == 'add':
	anomaly = {
		'id': sys.argv[2],
		'sensor': sys.argv[3],
		'direction': sys.argv[4],
		'ip': sys.argv[5],
		'decoder': sys.argv[6],
		'unit': sys.argv[7],
		'severity': sys.argv[8],
	}

	item_name = '%s %s' %(zbx_item_name, anomaly['id'])
	item_key = '%s.%s' %(zbx_item_key, anomaly['id'])

	logging.debug('API invocation: create item: %s, item key %s on %s' %(item_name, item_key, wg_host))
	try:
		za.create_item(wg_host, wg_app, item_name, item_key)
	except ZabbixAPIError as e:
		logging.warning(e.message)
		if not za.exists_item(wg_host, item_key):
			logging.error('No item %s, exiting' % item_key)
			sys.exit(1)

	logging.debug('API invocation: create trigger on item key: %s on %s' %(item_key, wg_host))
	try:
		za.create_trigger(wg_host, item_key, anomaly)
	except ZabbixAPIError as e:
		logging.warning(e.message)
		if not za.exists_trigger(wg_host, item_key):
			logging.error('No trigger for item %s, exiting' % item_key)
			sys.exit(1)

elif action == 'del':
	anomaly = {'id': sys.argv[2]}

	item_key = '%s.%s' %(zbx_item_key, anomaly['id'])

	logging.info('API invocation: del item key %s on %s (%s)' %(item_key, wg_host, wg_app))
	try:
		za.del_item(wg_host, item_key)
	except ZabbixAPIError as e:
		logging.error(e.message)
