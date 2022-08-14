#! /usr/bin/python3
import sys
import socket
import json
from time import sleep
import xml.etree.ElementTree as ET
import netifaces
import struct

def buildGETRequest(ip, port, url, keepalive=False):

	ip_b = str.encode(ip)
	port_b = str.encode(str(port))
	url_b = str.encode(url)

	connection = b'close'
	if keepalive:
		connection = b'keep-alive'
	
	HTTP_GET_Packet = \
			b'GET ' + url_b + b' HTTP/1.1\r\n' +\
			b'Host: ' + ip_b + b':' + port_b + b'\r\n' +\
			b'Connection: ' + connection + b'\r\n' +\
			b'UserAgent: UPnP Searcher/1.0 Windows\r\n' +\
			b'Accept-Encoding: gzip, deflate\r\n\r\n'
	
	return HTTP_GET_Packet

def getHTTPResponse(packet, ip, destPort, s=None, keepalive=False):
	if s is None:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(1.0)
		success = False
		attempts = 0

		while success is False:
			try:
				s.connect((ip, destPort))
				success = True
			except:
				success = False
				print("Failed connect: {}:{}".format(ip, destPort))
				attempts += 1
				if attempts > 10:
					break
				sleep(0.1)
		
		if not success:
			print("Giving up attempting to connect")
			s.close()
			return ("", None)

	try:
		s.send(packet)
	except:
		print("Failed to send somehow?")
		s.close()
		return ("", None)

	size = -1
	try:
		response = s.recv(8192)
	except socket.timeout:
		print("No resonse")
		s.close()
		return ("", None)
	response = str(response.decode("utf-8"))

	for header in response.split("\r\n"):
		if header.lower().startswith("content-length:"):
			size = int(header.split(": ")[1])
			break;
	if size < 0:
		print("Failed to get Content-Length field")
		s.close()
		return ("", None)

	data = str(response).split("\r\n\r\n", 1)
	message = ""
	if len(data) > 1:
		if len(data[1]) == size:
			if not keepalive:
				s.close()
				s = None
			return (str(data[1]), s)
		else:
			message = str(data[1])
	
	while len(message) < size:
		try:
			data = s.recv(8192)
			message += data.decode("utf-8")
		except socket.timeout:
			print("No response 2")
			s.close()
			return ("", None)

	if not keepalive:
		s.close()
		s = None
	return (message, s)

def getNodeText(parentNode, childNodeName, ns=None, bail=False):
	childNode = None
	if ns:
		childNode = parentNode.find(childNodeName, ns)
	else:
		childNode = parentNode.find(childNodeName)

	if childNode is not None:
		return childNode.text
	else:
		if bail:
			print("Failed to get text for {}".format(childNodeName))
			sys.exit(1)
		else:
			return ""

def buildSOAPRequest(ip, port, url, serviceType, actionName, args={}):
	
	ip_b = str.encode(ip)
	port_b = str.encode(str(port))
	#if '?' in url:
	#	url_b = str.encode(url.split('?')[0])
	#	params = url.split('?')[1].split('&')
	#else:
	#	url_b = str.encode(url)
	url_b = str.encode(url)
	actionName_b = str.encode(actionName)
	serviceType_b = str.encode(serviceType)


	SOAPHeader = \
		b'POST ' + url_b + b' HTTP/1.1\r\n' +\
		b'Host: '+ ip_b + b':' + port_b + b'\r\n' +\
		b'Content-Type: text/xml; charset="utf-8"\r\n'

	#for param in params:
	#	key_b = str.encode(param.split('=')[0])
	#	value_b = str.encode(param.split('=')[1])
	#	SOAPHeader = SOAPHeader +\
	#		key_b + b': ' + value_b + b'\r\n'
	

	SOAPBody1 = \
		b'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"' +\
		b' s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' +\
		b'<s:Body>' +\
		b'<u:' + actionName_b + b' xmlns:u="' + serviceType_b + b'">'

	SOAPArguments = b''
	for arg,value in args:
		arg_b = str.encode(arg)
		value_b = str.encode(value)

		SOAPArguments = SOAPArguments + \
			b'<' + arg_b + b'>' + value_b + b'</' + arg_b + b'>'

	SOAPBody2 = \
		b'</u:' + actionName_b + b'>' + \
		b'</s:Body>' +\
		b'</s:Envelope>'
	
	SOAPBody = SOAPBody1 + SOAPArguments + SOAPBody2

	SOAPHeader = SOAPHeader +\
		b'Content-Length: ' + str.encode(str(len(SOAPBody))) + b'\r\n' +\
		b'SOAPACTION: "' + serviceType_b + b'#' + actionName_b + b'"\r\n\r\n'

	SOAPRequest = SOAPHeader + SOAPBody
	return SOAPRequest

#request = buildSOAPRequest("192.168.1.1", 49469, "/ctl/BMS", "urn:schema-upnp-org:service:BasicManagement:2", "GetDeviceStatus")
#
#print(request)
#sys.exit()

HOST = ""
ifaces = netifaces.interfaces()
for interface in ifaces:
	ifaceInfo = netifaces.ifaddresses(interface)
	if netifaces.AF_INET in ifaceInfo:
		address = ifaceInfo[netifaces.AF_INET][0]["addr"]
		if address != "127.0.0.1":
			HOST = address
			break

if HOST == "":
	print("Failed to find appropriate network interface")
	sys.exit(1)

PORT = 50450
print("Binding on udp://{}:{}".format(HOST, PORT))

SSDP_Packet = \
	b'M-SEARCH * HTTP/1.1\r\n' + \
	b'HOST: 239.255.255.250:1900\r\n' + \
	b'MAN: "ssdp:discover"\r\n' + \
	b'MX: 1\r\n' + \
	b'ST: ssdp:all\r\n' + \
	b'\UserAgent: UPnP Searcher/1.0 Windows\r\n\r\n'

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

s.bind((HOST, PORT))

s.settimeout(0.5)
ttl = struct.pack('b', 1)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
s.sendto(SSDP_Packet, ('239.255.255.250', 1900))

run = True

response = 0
addr = 0
responses = []
addresses = []
while run:
	try:
		data,addr = s.recvfrom(PORT)
		responses.append(data)
		addresses.append(addr)
	except socket.timeout:
		run = False

s.close()

locations = []
sts = []
for response in responses:
	spaced = str(response).split("\\r\\n")
	for line in spaced:
		if line.lower().startswith("st:"):
			st = line.split(" ")[1]
			sts.append(st)
		elif line.lower().startswith("location:"):
			location = line.split(" ")[1]
			if location not in locations:
				locations.append(location)

devices = []

sockets = {}
keepalive = False
for location in locations:
	url = location
	if not url.split("http://")[1][0].isnumeric():
		continue
	ip = url.split("http://")[1].split(":")[0]
	port = url.split("http://")[1].split(":")[1].split("/")[0]
	httpURL = url.split("http://")[1].split(port)[1]

	port = int(port)

	packet = buildGETRequest(ip, port, httpURL, keepalive=keepalive)
	(responseXML, usedSocket) = getHTTPResponse(packet, ip, port, keepalive=keepalive)
	if len(responseXML) == 0:
		continue
	if keepalive:
		sockets[location] = usedSocket

	responseXML = responseXML.replace("\\r\\n","")

	ns = {'x'  : 'urn:schemas-upnp-org:device-1-0',
		  'df' : 'http://schemas.microsoft.com/windows/2008/09/devicefoundation',
		  's'  : 'urn:schemas-upnp-org:service-1-0'}

	root = ET.fromstring(responseXML)

	deviceNode = root.find('x:device', ns)
	while deviceNode is not None:
		device = {'location' : url,
		          'ip' : ip,
				  'port' : port}

		device['deviceType'] = getNodeText(deviceNode, 'x:deviceType', ns=ns, bail=True)
		device['UDN'] = getNodeText(deviceNode, 'x:UDN', ns=ns, bail=True)
		device['friendlyName'] = getNodeText(deviceNode, 'x:friendlyName', ns=ns, bail=True)

		serviceListNode = deviceNode.find('x:serviceList', ns)
		if serviceListNode is None:
			print("Failed to find serviceList element")
			sys.exit(1)

		device['services'] = []
		for serviceNode in serviceListNode.findall('x:service', ns):

			service = {}
			service['serviceType'] = getNodeText(serviceNode, 'x:serviceType', ns=ns, bail=True)
			service['serviceId'] = getNodeText(serviceNode, 'x:serviceId', ns=ns, bail=True)
			service['SCPDURL'] = getNodeText(serviceNode, 'x:SCPDURL', ns=ns, bail=True)
			service['controlURL'] = getNodeText(serviceNode, 'x:controlURL', ns=ns, bail=True)
			service['eventSubURL'] = getNodeText(serviceNode, 'x:eventSubURL', ns=ns, bail=True)
			device['services'].append(service)

		devices.append(device)
		deviceListNode = deviceNode.find('x:deviceList', ns)
		if deviceListNode is None:
			break

		deviceNode = deviceListNode.find('x:device', ns)

#print(json.dumps(devices, sort_keys=True, indent=4))

#sys.exit(0)

for device in devices:
	for service in device['services']:
		gotSocket = False
		if keepalive and device['location'] in sockets.keys():
			print("have socket")
			prevSocket = sockets[device['location']]
			gotSocket = True

		if keepalive and gotSocket:
			print("using old socket")
			packet = buildGETRequest(device['ip'], device['port'], service['SCPDURL'], keeepalive=keepalive)
			(responseXML, s) = getHTTPResponse(packet, device['ip'], device['port'], s=prevSocket, keepalive=keepalive)
		else:
			packet = buildGETRequest(device['ip'], device['port'], service['SCPDURL'], keepalive=keepalive)
			(responseXML, s) = getHTTPResponse(packet, device['ip'], device['port'], keepalive=keepalive)
		if len(responseXML) == 0:
			if s is not None:
				s.close()
				del sockets[device['location']]
			continue

		responseXML = responseXML.replace("\\r\\n","")

		scpd = ET.fromstring(responseXML)

		service['actions'] = []
		service['stateVariables'] = []
		actionListNode = scpd.find('s:actionList', ns)
		serviceStateTableNode = scpd.find('s:serviceStateTable', ns)
		if actionListNode is not None:
			for actionNode in actionListNode.findall('s:action', ns):
				action = {'name' : getNodeText(actionNode, 's:name', ns=ns, bail=True)}
				argumentListNode = actionNode.find('s:argumentList', ns)
				if argumentListNode is None:
					continue

				action['arguments'] = []
				for argumentNode in argumentListNode.findall('s:argument', ns):
					argument = {'name' : getNodeText(argumentNode, 's:name', ns=ns, bail=True),
								'direction' : getNodeText(argumentNode, 's:direction', ns=ns, bail=True),
								'relatedStateVariable' : getNodeText(argumentNode, 's:relatedStateVariable', ns=ns, bail=True)}
					action['arguments'].append(argument)
				service['actions'].append(action)
		else:
			print('cannot find actionList in {} -> {}'.format(device['friendlyName'], service['serviceType']))

		if serviceStateTableNode is not None:
			for stateVariableNode in serviceStateTableNode.findall('s:stateVariable', ns):
				stateVariable = {}
				sendEvents = stateVariableNode.attrib['sendEvents']
				if sendEvents.lower() == "yes":
					stateVariable['sendEvents'] = True
				else:
					stateVariable['sendEvents'] = False
				
				stateVariable['name'] = getNodeText(stateVariableNode, 's:name', ns=ns, bail=True)
				stateVariable['dataType'] = getNodeText(stateVariableNode, 's:dataType', ns=ns, bail=True)
				stateVariable['default'] = getNodeText(stateVariableNode, 's:default', ns=ns, bail=False)
				allowedValueRangeNode = stateVariableNode.find('s:allowedValueRange', ns)
				if allowedValueRangeNode is not None:
					stateVariable['allowedValueRange'] = \
						{'minimum' : getNodeText(allowedValueRangeNode, 's:minimum', ns=ns, bail=False),
						 'maximum' : getNodeText(allowedValueRangeNode, 's:maximum', ns=ns, bail=False),
						 'step' :    getNodeText(allowedValueRangeNode, 's:step', ns=ns, bail=False)}
				allowedValueListNode = stateVariableNode.find('s:allowedValueList', ns)
				if allowedValueListNode is not None:
					stateVariable['allowedValues'] = []
					for allowedValueNode in allowedValueListNode.findall('s:allowedValue', ns):
						stateVariable['allowedValues'].append(allowedValueNode.text)

				service['stateVariables'].append(stateVariable)
		else:
			print('cannot find actionList in {} -> {}'.format(device['friendlyName'], service['serviceType']))

#print(json.dumps(devices, sort_keys=True, indent=4))

for device in devices:
	#if device['UDN'] != 'uuid:fbd66701-23d0-4d28-af06-086ea66c0a12':
	#	continue

	for service in device['services']:
		#if service['serviceId'] != 'urn:upnp-org:serviceId:WANIPConn1':
		#	continue

		for action in service['actions']:
			if not action['name'].startswith("Get"):
				continue
			skip = False
			for argument in action['arguments']:
				if argument['direction'] == 'in':
					skip = True
					break
			if skip:
				continue

			print("{}:{}{} {} -> {}".format(device['ip'], device['port'], service['controlURL'], service['serviceType'], action['name']))
			packet = buildSOAPRequest(device['ip'], device['port'], service['controlURL'], service['serviceType'], action['name'])
			print(packet)
			(response, s) = getHTTPResponse(packet, device['ip'], device['port'])
			print(response)

sys.exit(0)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.0)

#s.bind((HOST, PORT))
s.connect((addr[0], 10247))
for app in apps:
	HTTP_GET_Packet2 = \
		b'GET /apps/' + str.encode(app) + b' HTTP/1.1\r\n' +\
		b'Host: b' + str.encode(addr[0]) + b':' + str.encode(urlport) + b'\r\n' + \
		b'Connection: keep-alive\r\n' + \
		b'UserAgent: UPnP Searcher/1.0 Windows\r\n\r\n'

	s.send(HTTP_GET_Packet2)
	try:
		data = s.recv(8192)
		if "200" in str(data):
			print(app + ": Yes")
		elif "400" in str(data):
			print(app + ": Bad Request")
			sleep(1)
		elif "500" in str(data):
			print(app + ": ISR")
		else:
			print(data)
			print(app + ": No")
	except socket.timeout:
		print("Timeout")
		
	sleep(0.1)

