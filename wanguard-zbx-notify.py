#!/usr/bin/python

# Copyright (c) 2013-2014 Robert Jerzak
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
import ConfigParser
import os
import pickle

zbx_trigger_warning_ceil = 150 # percent above thhreshold
zbx_trigger_average_ceil = 250 # percent above thhreshold

wg_host = 'wanguard' # host used in zabbix
wg_app = 'wanguard' # application used in zabbix
zbx_item_name = 'anomaly' # item pattern used in zabbix
zbx_item_key = 'anomaly' # item key pattern used in zabbix

logfile = '/var/log/wanguard-notify.log'
conf_file = '/etc/wanguard-zbx-notify.conf'
statefile = '/tmp/wanguard-notify'
connection_timeout = 5

class ZabbixAPIError(Exception):
    pass

class Alarm(Exception):
    pass

def alarm_handler(signum, frame):
	raise Alarm

class ZabbixConnection:
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
			raise ZabbixAPIError('HTTP connection error, json: %s' % self.remove_password(json_data))
		except Alarm:
			raise ZabbixAPIError('HTTP connection timeout, json: %s' % self.remove_password(json_data))

		if r.status_code == 200 and r.content != '':
			c = json.loads(r.content)
			if 'error' in c:
				raise ZabbixAPIError('API error: code: %s message: %s data: %s'
					%(str(c['error']['code']), str(c['error']['message']), str(c['error']['data'])))
			elif 'result' in c:
				return c['result']
			else:
				raise ZabbixAPIError('Wrong API result, json: %s' % self.remove_password(json_data))
		else:
			raise ZabbixAPIError('Wrong API response content: HTTP code %s, json: %s' %(r.status_code, self.remove_password(json_data)))

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

	def remove_password(self, json_data):
		dict = json.loads(json_data)
		if 'params' in dict and 'password' in dict['params']:
			dict['params']['password'] = 'XXX'
		return json.dumps(dict)

	def send(self, data):
		data['auth'] = self.__api_token
		data['jsonrpc'] = '2.0'
		data['id'] = '0'
		return self.__callAPI(json.dumps(data))

class ZabbixAPI:
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

	def __create_item(self, hostname, app, item_name, item_key):
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

	def create_item(self, hostname, app, item_name, item_key):
		logging.debug('API invocation: create item: %s, item key %s on %s' %(item_name, item_key, hostname))
		try:
			self.__create_item(hostname, app, item_name, item_key)
			return True
		except ZabbixAPIError as e:
			logging.warning(e.message)

			try:
				if self.__exists_item(hostname, item_key):
					return True
				else:
					logging.error('No item %s' % item_key)
					return None
			except ZabbixAPIError as e:
				logging.error('Cannot check if item exists')
				return None

	def del_item(self, hostname, item_key):
		logging.info('API invocation: del item key %s on %s' %(item_key, hostname))
		try:
			self.__del_item(hostname, item_key)
			return True
		except ZabbixAPIError as e:
			logging.warning(e.message)

			try:
				if self.__exists_item(hostname, item_key):
					logging.error('Cannot delete item %s' % item_key)
					return None
				else:
					return True
			except ZabbixAPIError as e:
				logging.error('Cannot check if item exists')
				return None

	def __exists_item(self, hostname, item_key):
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
		if perc <= zbx_trigger_warning_ceil:
			severity = 2 # warning
		elif perc > zbx_trigger_warning_ceil and perc <= zbx_trigger_average_ceil:
			severity = 3 # average
		elif perc > zbx_trigger_average_ceil:
			severity = 4 # high

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

	def __create_trigger(self, hostname, item_key, anomaly):
		name, severity, expression = self.__prepare_trigger(anomaly, hostname, item_key)

		req = {
			'method': 'trigger.create',
			'params': {
				'description': name,
				'expression': expression,
				'priority': severity,
				#'status': 1,
			},
		}

		logging.debug('API invocation: create trigger on item key: %s: %s' %(item_key, name))
		result = self.__zconn.send(req)
		try:
			return result['triggerids'][0]
		except (KeyError, IndexError):
			raise ZabbixAPIError('Error: cannot create trigger on item key %s on host %s' %(item_key, hostname))

	def create_trigger(self, hostname, item_key, anomaly):
		try:
			self.__create_trigger(hostname, item_key, anomaly)
			return True
		except ZabbixAPIError as e:
			logging.warning(e.message)

			try:
				if self.__exists_trigger(hostname, item_key):
					return True
				else:
					logging.error('No trigger for item %s' % item_key)
					return None
			except ZabbixAPIError as e:
				logging.error('Cannot check if trigger exists')
				return None

	def __exists_trigger(self, hostname, item_key):
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

	def __del_item(self, hostname, item_key):
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

class Notification:
	def __init__(self, pd, url, user, passwd):
		self.__pd = pd
		self.__load_data()
		try:
			self.__zbx = ZabbixAPI(url, user, passwd)
		except ZabbixAPIError as e:
			logging.error('%s, program execution: %s' %(e.message, ' '.join(sys.argv)))
			raise ZabbixAPIError

	def __load_data(self):
		self.__zbx_item_name = zbx_item_name
		self.__zbx_item_key = zbx_item_key
		self.__wg_host = wg_host
		self.__wg_app = wg_app

	def __gen_item_key(self, anomaly_id):
		return '%s.%s' %(self.__zbx_item_key, anomaly_id)

	def add_notification(self, anomaly):
		item_name = '%s %s' %(self.__zbx_item_name, anomaly['id'])
		item_key = self.__gen_item_key(anomaly['id'])

		if not self.__zbx.create_item(self.__wg_host, self.__wg_app, item_name, item_key):
			return None

		if not self.__zbx.create_trigger(self.__wg_host, item_key, anomaly):
			return None

		return True

	def del_notification(self, anomaly):
		item_key = self.__gen_item_key(anomaly['id'])

		if self.__zbx.del_item(self.__wg_host, item_key):
			return True
		else:
			return None

	def clean_notification(self):
		self.__pd.priority_anomalies()
		for a in self.__pd.get_anomalies():
			if a['action'] == 'add':
				if self.add_notification(a):
					self.__pd.del_anomaly(a['id'])
			elif a['action'] == 'del':
				if self.del_notification(a):
					self.__pd.del_anomaly(a['id'])

		self.__pd.save_anomalies()

class PersistData:
	def __init__(self):
		self.__statefile = statefile
		self.__data_changed = None
		self.__anomalies = self.__load_anomalies()

	def get_anomalies(self):
		return self.__anomalies

	def save_anomalies(self):
		if not self.__data_changed:
			return

		if self.__anomalies:
			logging.debug('Saving faulty anomalies: %s' % self.__flatten_anomalies(self.__anomalies))

		self.__save_anomalies(self.__anomalies)

	def __save_anomalies(self, anomalies):
		tmpfile = self.__statefile + '-' + str(os.getpid())

		try:
			file = open(tmpfile, 'w')
		except IOError:
			logging.error('Cannot open file %s for writing' % tmpfile)
			return

		try:
			pickle.dump(anomalies, file)
		except IOError:
			logging.error('Cannot write file %s' % tmpfile)
		except pickle.PicklingError:
			logging.error('Pickling error')
		else:
			# attempt to emulate atomic write
			file.flush()
			os.fsync(file)
			file.close()
			os.rename(tmpfile, self.__statefile)
		finally:
			file.close()

	def __load_anomalies(self):
		try:
			file = open(self.__statefile, 'r')
		except IOError:
			logging.debug('Cannot open file %s for reading' % self.__statefile)
			return []

		try:
			a = pickle.load(file)
		except (pickle.UnpicklingError, AttributeError, EOFError, ImportError, IndexError):
			logging.error('Unpickling error')
			file.close()
			self.__save_anomalies([])
			return []
		finally:
			file.close()

		if a:
			logging.debug('Loaded faulty anomalies: %s' % self.__flatten_anomalies(a))
			return a
		else:
			return []

	def __flatten_anomalies(self, anomalies):
		f = []
		for a in anomalies:
			f.append('%s %s' %(a['id'], a['action']))
		return ', '.join(f)

	def add_anomaly(self, anomaly):
		exists = None
		for a in self.__anomalies:
			if anomaly['id'] == a['id'] and (anomaly['action'] == a['action'] or a['action'] == 'del'):
				exists = True
				break

		if not exists:
			self.__anomalies.append(anomaly)
			self.__data_changed = True

	def priority_anomalies(self):
		dups = {}
		for a in self.__anomalies:
			if a['id'] in dups:
				dups[a['id']] += 1
			else:
				dups[a['id']] = 1

		for key, value in dups.iteritems():
			if value > 1:
				self.__del_dup_anomalies(key)

	def __del_dup_anomalies(self, id):
		anomalies_new = []
		for a in self.__anomalies:
			if a['id'] != id or (a['id'] == id and a['action'] != 'add'):
				anomalies_new.append(a)

		if len(self.__anomalies) != len(anomalies_new):
			self.__anomalies = anomalies_new
			self.__data_changed = True

	def del_anomaly(self, id):
		anomalies_new = []
		for a in self.__anomalies:
			if a['id'] != id:
				anomalies_new.append(a)

		if len(self.__anomalies) != len(anomalies_new):
			self.__anomalies = anomalies_new
			self.__data_changed = True

## MAIN

def usage():
	sys.exit('Usage: %s [add|del|clean] {anomaly_id} {sensor} {direction} {ip} {decoder} {unit} {severity}' % sys.argv[0])

def parse_config(file):
	if os.path.exists(file):
		config = ConfigParser.ConfigParser()
		config.read(file)
		return dict(config.items('zabbix'))
	else:
		return None

requests_log = logging.getLogger('requests')
requests_log.setLevel(logging.WARNING)
logging.basicConfig(format='%(asctime)s %(levelname)s:%(message)s', filename=logfile, level=logging.DEBUG)

logging.info('Program execution: ' + ' '.join(sys.argv))
conf = parse_config(conf_file)

if not isinstance(conf, dict) or 'zabbix_api_host' not in conf or 'zabbix_api_user' not in conf or 'zabbix_api_pass' not in conf:
	logging.error('Could not get data from config file %s' % conf_file)
	sys.exit(1)

conf['zabbix_api_url'] = 'http://%s/api_jsonrpc.php' % conf['zabbix_api_host']

if len(sys.argv) != 2 and len(sys.argv) != 3 and len(sys.argv) != 9:
	logging.error('Wrong program execution parameters: %s' % ' '.join(sys.argv))
	usage()

action = sys.argv[1]
if action == 'add':
	anomaly = {
		'action': sys.argv[1],
		'id': sys.argv[2],
		'sensor': sys.argv[3],
		'direction': sys.argv[4],
		'ip': sys.argv[5],
		'decoder': sys.argv[6],
		'unit': sys.argv[7],
		'severity': sys.argv[8],
	}
elif action == 'del':
	anomaly = {
		'action': sys.argv[1],
		'id': sys.argv[2],
	}
elif action == 'clean':
	pass
else:
	usage()

pd = PersistData()
try:
	n = Notification(pd, conf['zabbix_api_url'], conf['zabbix_api_user'], conf['zabbix_api_pass'])
except ZabbixAPIError:
	pd.add_anomaly(anomaly)
	pd.save_anomalies()
	sys.exit(1)

if action == 'add':
	if not n.add_notification(anomaly):
		pd.add_anomaly(anomaly)
elif action == 'del':
	if not n.del_notification(anomaly):
		pd.add_anomaly(anomaly)

n.clean_notification()
