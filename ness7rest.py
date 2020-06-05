#!/usr/bin/python 
#coding=utf-8

"""
reference:
	https://github.com/lukaszbanasiak/python-nessus-client
	https://you-domain:8834/api#/overview
"""
import json
from requests import request, Session, codes

class Resource(object):
	def __init__(self, uri, api):
		self.uri = uri
		self.api = api

	@staticmethod
	def _nessus_dict2dict(self, data, key=0):
		""" Convert from {key: key, value: value} to {key: value} dict
		:param data: nessus dict response
		:param key: which value should be key, first or second
		"""
		new = {}
		k, v = 0, 1
		if key == 1:
			v, k = 0, 1
		for r in data:
			new[r.values()[k]] = r.values()[v]
		return new

class Scans(Resource):
	
	def new(self, target, scan_name, uuid = None, **settings):
			"""
			Example::
				>>> from ness7rest import Nessus
				>>> nessus = Nessus('https://127.0.0.1:8834', username='user', password='pass')
				>>> target = ['localhost', 'example.com']
				>>> nessus.scans.new('127.0.0.1', 'test', launch_now = "true")
			"""
			payload ={
						"uuid" : uuid,
						"settings": {
							"name": scan_name,
							#"description": "test",
							#"emails": {string},
							#"launch": {string},
							#"folder_id": {integer},
							#"policy_id": {integer},
							#"scanner_id": {integer},
							"text_targets": target,
							#"launch_now": "true"
						}
					}
			
			
			if payload['uuid'] is None:
				#Default Basic Network Scan
				payload['uuid'] = '731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65'
			if settings:
				payload['settings'].update(settings)
			if isinstance(target, (list, tuple)):
				payload['target'] = ','.join(target)
			return self.api.post(self.uri, json = payload)

	def stop(self, scan_uuid):
		"""Stop an existing scan job.
		:param scan_uuid: UUID of scan job to stop
		Permissions:
		* authenticated: Yes
		* administrator: No
		"""
		return self.api.post(self.uri + '/%d/stop'%scan_uuid)

	def pause(self, scan_uuid):
		"""Pause an existing scan job, allowing it to be resumed at a later time.
		:param scan_uuid: UUID of scan job to pause
		Permissions:
		* authenticated: Yes
		* administrator: No
		"""
		return self.api.post(self.uri + '/%d/pause'%scan_uuid)

	def resume(self, scan_uuid):
		"""Resume a previously paused scan job.
		:param scan_uuid: UUID of scan job to resume
		Permissions:
		* authenticated: Yes
		* administrator: No
		"""
		return self.api.post(self.uri + '/%d/resume'%scan_uuid)

	def list(self):
		"""List all current scan jobs.
		Permissions:
		* authenticated: Yes
		* administrator: No
		Example::
			>>> from ness7rest import Nessus
			>>> nessus = Nessus('https://127.0.0.1:8834', username='user', password='pass')
			>>> print nessus.scan.list()
			{
			  "templates": {},
			  "policies": {
				"policies": {
				  "policy": [
					{
					  "user_permissions": 128,
					  "policyName": "Internal Network Scan",
					  "policyOwner": "test",
					  "policyID": -1,
					  "visibility": "shared"
					},
					(...)
				  ]
				}
			  },
			  "scans": {
				"scanList": {
				  "scan": []
				}
			  }
			}
		"""
		return self.api.get(self.uri)

	def template_new(self):
		"""
		:raise NotImplementedError:
		.. todo:: ``/scan/template/new``
		"""
		# TODO: /scan/template/new
		raise NotImplementedError

	def template_edit(self):
		"""
		:raise NotImplementedError:
		.. todo:: ``/scan/template/edit``
		"""
		# TODO: /scan/template/edit
		raise NotImplementedError

	def template_delete(self):
		"""
		:raise NotImplementedError:
		.. todo:: ``/scan/template/delete``
		"""
		# TODO: /scan/template/delete
		raise NotImplementedError

	def template_launch(self):
		"""
		:raise NotImplementedError:
		.. todo:: ``/scan/template/launch``
		"""
		# TODO: /scan/template/launch
		raise NotImplementedError

class Nessus(object):
	
	def __init__(self, base_url, accessKey = '', secretKey = '', username = '', password='', login = False, debug=False):
			if debug:
				import logging
				try:
					import http.client as http_client
				except ImportError:
					# Python 2
					import httplib as http_client
				http_client.HTTPConnection.debuglevel = 1
				logging.basicConfig(level=0)
			super(Nessus, self).__init__()
			self.base_url = base_url + '/' if not base_url.endswith('/') else base_url
			self.username = username
			self.payload = {}  # set return type to JSON
			self.session = {}

			if login:
				token = self.login(self.username, password)
				self.session = {'X-Cookie': 'token=%s'%token}
			else:
				self.session = {'X-ApiKeys': 'accessKey={accessKey};secretKey={secretKey};'.format(accessKey = accessKey, secretKey = secretKey)}
			self.scans = Scans('scans', api = self)
			"""self.server = Server('server', api=self)
			self.users = Users('users', api=self)
			self.plugins = Plugins('plugins', api=self)
			self.preferences = Preferences('preferences', api=self)
			self.policy = Policy('policy', api=self)
			self.report = Report('report', api=self)
			self.file = File('file', api=self)"""
	
	def get(self, name, **payload):
		return self.__request('GET', name, **payload)

	def post(self, name, **payload):
		return self.__request('POST', name, **payload)

	def __request(self, method, name, **payload):
		response = request(method, self.base_url + name, **payload, headers = self.session, verify = False)
		print(self.base_url + name, method)
		if response.status_code == codes.ok:
			try:
				print(response.json())
				return response.json()
			except json.decoder.JSONDecodeError as e:
				'TODO: check response'
				print('Warning: %s Response length:%d'%(str(e), len(response.text)))
				pass
	
	def login(self, username, password):
		"""Authenticates a user.
		Permissions:
		* authenticated: No
		* administrator: No
		:param login: user login
		:param password: user password
		Example::
			>>> from ness7rest import Nessus
			>>> nessus = Nessus('https://127.0.0.1:8834', login=False)
			>>> nessus.login('user', 'pass')
		"""
		
		return self.post('session', json = {'username': username, 'password': password})['token']
