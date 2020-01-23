#! /usr/bin/env python
# -*- coding: utf-8 -*-
####################

import base64
import logging
import json
import ssl
import os.path
import hashlib
import time
import threading

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from urlparse import urlparse, parse_qs
import urllib2

import indigo

REALM = "HTTPd Plugin"

########################################

class MyHTTPServer(HTTPServer):

    def set_auth_params(self, httpUser, httpPassword, digestRequired):
        self.logger = logging.getLogger("Plugin.MyHTTPServer")
        self.httpUser = httpUser
        self.httpPassword = httpPassword
        self.digestRequired = bool(digestRequired)
        self.logger.debug("MyHTTPServer, username = {}, password = {}, digest = {}".format(self.httpUser, self.httpPassword, self.digestRequired))
        
    def set_dev_id(self, devID):
        self.devID = devID
        self.logger.debug("MyHTTPServer, devID = {}".format(self.devID))
        
    def set_state_list(self, state_list):
        self.state_list = state_list
    
class MyRequestHandler(BaseHTTPRequestHandler):

    def send_reply(self, code):

        nonce = hashlib.md5("{}:{}".format(time.time(), REALM)).hexdigest() 
        if self.server.digestRequired:
            authHeader = 'Digest realm="{}", nonce="{}", algorithm="MD5", qop="auth"'.format(REALM, nonce)
        else:
            authHeader = 'Digest realm="{}", nonce="{}", algorithm="MD5", qop="auth" Basic realm="{}"'.format(REALM, nonce, REALM)
            
        self.send_response(code)
        self.send_header('WWW-Authenticate', authHeader)
        self.send_header("Content-type", "text/html")
        self.end_headers()
    
    def is_authorized(self, method):

        if len(self.server.httpPassword) == 0:    # no authentication needed
            self.logger.debug("MyRequestHandler: No password specified in device configuration, skipping authentication")
            return True
            
        auth_header = self.headers.getheader('Authorization')        
        if auth_header == None:
            self.logger.debug("MyRequestHandler: Request has no Authorization header")
            headers = {key:value for (key,value) in self.headers.items()}
            self.logger.debug("{}".format(headers))
            return False

        auth_scheme, auth_params  = auth_header.split(" ", 1)
        auth_scheme = auth_scheme.lower()
        
        if auth_scheme == 'basic':
            username, password = base64.decodestring(auth_params).split (":", 1)
            auth_map = {"username": username, "password": password}
            
        elif auth_scheme == 'digest':                       # Convert the auth params to a dict
            items = urllib2.parse_http_list(auth_params)
            auth_map = urllib2.parse_keqv_list(items)
            
        else:
            self.logger.debug(u"MyRequestHandler: Invalid authentication scheme: {}".format(auth_scheme))
            return False
                
        self.logger.debug("MyRequestHandler: auth_map = {}".format(auth_map))
            
        # check username
        if auth_map["username"] != self.server.httpUser:
            self.logger.debug("MyRequestHandler: Username mismatch")
            return False
                
        if auth_scheme == "basic":
            if self.server.digestRequired:
                self.logger.debug(u"MyRequestHandler: {} Authorization not allowed".format(auth_scheme).capitalize())
                return False
                
            if auth_map["password"] == self.server.httpPassword:
                self.logger.debug(u"MyRequestHandler: {} Authorization valid".format(auth_scheme).capitalize())
                return True
            else:
                self.logger.debug(u"MyRequestHandler: {} Authorization failed".format(auth_scheme).capitalize())
                return False
 
        elif auth_scheme == "digest":

            h1 = hashlib.md5(self.server.httpUser + ":" + REALM + ":" + self.server.httpPassword).hexdigest()
            h2 = hashlib.md5(method + ":" + auth_map["uri"]).hexdigest()
            rs = h1 + ":" + auth_map["nonce"] + ":" + auth_map["nc"] + ":" + auth_map["cnonce"] + ":" + auth_map["qop"] + ":" + h2
            if hashlib.md5(rs).hexdigest() == auth_map["response"]:
                self.logger.debug(u"MyRequestHandler: {} Authorization valid".format(auth_scheme).capitalize())
                return True
            else:
                self.logger.debug(u"MyRequestHandler: {} Authorization failed".format(auth_scheme).capitalize())
                return False

        else:
            self.logger.debug(u"MyRequestHandler: {} Authorization invalid".format(auth_scheme).capitalize())
            return False

    def do_setvar(self, request):      
        query = parse_qs(request.query)
        state_list = []
        for key in query:
            value = query[key][0]
            self.logger.debug(u"MyRequestHandler: setting state {} to '{}'".format(key, value))
            state_list.append({'key': unicode(key), 'value': value})
                    
        device = indigo.devices[self.server.devID]
        self.logger.debug(u"MyRequestHandler: updating device {} (port {})".format(device.name, device.address))

        self.server.set_state_list(state_list)
        device.stateListOrDisplayStateIdChanged()
        device.updateStatesOnServer(state_list)

    def do_POST(self):
        self.logger = logging.getLogger("Plugin.MyRequestHandler")
        client_host, client_port = self.client_address
        port = self.server.socket.getsockname()[1]
        self.logger.debug("MyRequestHandler: POST to port {} from {}:{} for {}".format(port, client_host, client_port, self.path))
        
        if not self.is_authorized("POST"):
            self.send_reply(401)
            return
                       
        request = urlparse(self.path)

        if request.path == "/setvar":
            self.do_setvar(request)

        elif request.path == "/broadcast":

            broadcastDict = {}
            query = parse_qs(request.query)
            for key in query:
                value = query[key][0]
                broadcastDict[key] = value
            
            # might not have any content
            try:
                payload = self.rfile.read(int(self.headers['Content-Length']))
                broadcastDict["payload"] = payload
            except:
                pass

            self.logger.debug("POST Broadcast = {}".format(broadcastDict, indent=4, sort_keys=True))
            indigo.server.broadcastToSubscribers(u"httpd_post_broadcast", broadcastDict)
        
        elif request.path.startswith("/webhook"):

            broadcastDict = {}
            varsDict = {}
            query = parse_qs(request.query)
            for key in query:
                value = query[key][0]
                varsDict[key] = value
            broadcastDict["vars"] = varsDict

            broadcastDict["request"] = {"path" : request.path, "command" : self.command, "client" : client_host}
            broadcastDict["request"]["headers"] = {key:value for (key,value) in self.headers.items()}
            
            # might not have any content
            try:
                payload = self.rfile.read(int(self.headers['Content-Length']))
                if self.headers['Content-Type'] == 'application/json':
                    broadcastDict["payload"] = json.loads(payload)
                else:
                    broadcastDict["payload"] = payload
            except:
                pass
                
            broadcast = u"httpd_" + request.path[1:]
            self.logger.debug("POST Webhook to {} = {}".format(broadcast, broadcastDict, indent=4, sort_keys=True))
            indigo.server.broadcastToSubscribers(broadcast, broadcastDict)
        
        else:
            self.logger.debug(u"MyRequestHandler: Unknown POST request: {}".format(request.path))

        self.send_reply(200)



    def do_GET(self):
        self.logger = logging.getLogger("Plugin.MyRequestHandler")
        client_host, client_port = self.client_address
        port = self.server.socket.getsockname()[1]
        self.logger.debug("MyRequestHandler: GET to port {} from {}:{} for {}".format(port, client_host, client_port, self.path))

        if not self.is_authorized("GET"):
            self.send_reply(401)
            return

        request = urlparse(self.path)

        if request.path == "/setvar":
            self.do_setvar(request)

        elif request.path.startswith("/webhook"):

            broadcastDict = {}
            varsDict = {}
            query = parse_qs(request.query)
            for key in query:
                value = query[key][0]
                varsDict[key] = value
            broadcastDict["vars"] = varsDict

            broadcastDict["request"] = {"path" : request.path, "command" : self.command, "client" : client_host}
            broadcastDict["request"]["headers"] = {key:value for (key,value) in self.headers.items()}
                            
            broadcast = u"httpd_" + request.path[1:]
            self.logger.debug("GET Webhook to {} = {}".format(broadcast, broadcastDict, indent=4, sort_keys=True))
            indigo.server.broadcastToSubscribers(broadcast, broadcastDict)
        
        else:
            self.logger.debug(u"MyRequestHandler: Unknown GET request: {}".format(request.path))

        self.send_reply(200)


class Plugin(indigo.PluginBase):

    ########################################
    # Main Plugin methods
    ########################################
    def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
        indigo.PluginBase.__init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs)

        pfmt = logging.Formatter('%(asctime)s.%(msecs)03d\t[%(levelname)8s] %(name)20s.%(funcName)-25s%(msg)s', datefmt='%Y-%m-%d %H:%M:%S')
        self.plugin_file_handler.setFormatter(pfmt)
        
        try:
            self.logLevel = int(self.pluginPrefs[u"logLevel"])
        except:
            self.logLevel = logging.INFO
        self.indigo_log_handler.setLevel(self.logLevel)
        self.logger.debug(u"logLevel = {}".format(self.logLevel))


    def startup(self):
        indigo.server.log(u"Starting HTTPd")

        self.servers = {}
        self.triggers = {}
        self.proxy_data = {}
        
        indigo.server.subscribeToBroadcast("com.flyingdiver.indigoplugin.httpd", u"httpd_webhook-httpd", "webHook")       

    def webHook(self, hookData):
        self.logger.debug(u"webHook received:\n{}".format(hookData))

    def shutdown(self):
        indigo.server.log(u"Shutting down HTTPd")


    def start_server(self, port, https=False, certfileName=None, keyfileName=None):
    
        if port == 0:
            return None

        if not https:
            try:
                server = MyHTTPServer(("", port), MyRequestHandler)
                server.timeout = 1.0
                self.logger.debug(u"Started HTTP server on port {}".format(port))
                return server
                
            except:
                self.logger.error(u"Unable to open port {} for HTTP Server".format(port))
                return None
        
        else:

            certfile = indigo.server.getInstallFolderPath() + '/' + certfileName
            if not os.path.isfile(certfile):
                self.logger.error(u"Certificate file missing, unable to start HTTPS server on port {}".format(port))
                return None

            try:
                server = MyHTTPServer(("", port), MyRequestHandler)
                server.timeout = 1.0
            except:
                self.logger.error(u"Unable to open port {} for HTTPS Server".format(port))
                return None

            if not keyfileName:
                keyfile = None
            else:
                keyfile = indigo.server.getInstallFolderPath() + '/' + keyfileName
                if not os.path.isfile(keyfile):
                    self.logger.error(u"Key file missing, unable to start HTTPS server on port {}".format(port))
                    return None
            
            server.socket = ssl.wrap_socket(server.socket, keyfile=keyfile, certfile=certfile, server_side=True)
            self.logger.debug(u"Started HTTPS server on port {}".format(port))
            return server


    def runConcurrentThread(self):

        try:
            while True:

                for server in self.servers.values():
                    server.handle_request()

                self.sleep(0.1)

        except self.StopThread:
            pass


    ####################

    def triggerStartProcessing(self, trigger):
        self.logger.debug("Adding Trigger {} ({})".format(trigger.name, trigger.id))
        assert trigger.id not in self.triggers
        self.triggers[trigger.id] = trigger

    def triggerStopProcessing(self, trigger):
        self.logger.debug("Removing Trigger {} ({})".format(trigger.name, trigger.id))
        assert trigger.id in self.triggers
        del self.triggers[trigger.id]


    ####################
    def validatePrefsConfigUi(self, valuesDict):
        errorDict = indigo.Dict()
        if len(errorDict) > 0:
            return (False, valuesDict, errorDict)
        return (True, valuesDict)

    ########################################
    def closedPrefsConfigUi(self, valuesDict, userCancelled):
        if not userCancelled:
            try:
                self.logLevel = int(valuesDict[u"logLevel"])
            except:
                self.logLevel = logging.INFO
            self.indigo_log_handler.setLevel(self.logLevel)
            self.logger.debug(u"logLevel = {}".format(self.logLevel))
            
    ########################################
    def validateDeviceConfigUi(self, valuesDict, typeId, devId):
        errorsDict = indigo.Dict()

        if typeId == 'serverDevice':
            try:
                port = int(valuesDict.get('address', '0'))
            except:
                errorsDict['address'] = u"HTTP Port Number invalid"
            else:
                if port < 1024:
                    errorsDict['address'] = u"HTTP Port Number invalid"
                    
            if valuesDict.get('protocol', 'http') == 'https':
                certfile = indigo.server.getInstallFolderPath() + '/' + valuesDict.get('certfileName', "")
                if not os.path.isfile(certfile):
                    errorsDict['certfileName'] = u"Certificate file required for HTTPS protocol"

        if len(errorsDict) > 0:
            return (False, valuesDict, errorsDict)
        return (True, valuesDict)


    def deviceStartComm(self, dev):
        self.logger.info(u"{}: Starting {} Device {}".format(dev.name, dev.deviceTypeId, dev.id))
                    
        if dev.deviceTypeId == 'serverDevice':
            port = int(dev.address)
            https = dev.pluginProps.get('protocol', 'http') == 'https'
            certfile = dev.pluginProps.get('certfileName', None)
            keyfile = dev.pluginProps.get('keyfileName', None)
            
            server = self.start_server(port, https=https, certfileName=certfile, keyfileName=keyfile)
            if server:
                digestRequired = dev.pluginProps.get('digestRequired', False)
                httpUser = dev.pluginProps.get('httpUser', None)
                httpPassword = dev.pluginProps.get('httpPassword', None)
                server.set_auth_params(httpUser, httpPassword, digestRequired)
                server.set_dev_id(dev.id)
                self.servers[dev.id] =  server
            
        elif dev.deviceTypeId == 'proxyDevice':

            webhook_info = self.getWebhookInfo(str(dev.id))
            stateList = [
                            {'key': 'http',      'value': webhook_info.get("http",None)},
                            {'key': 'https',     'value': webhook_info.get("https",None)} 
                        ]
            dev.updateStatesOnServer(stateList)

            indigo.server.subscribeToBroadcast("com.flyingdiver.indigoplugin.httpd", webhook_info["hook_name"], "webhook_proxy")

        dev.stateListOrDisplayStateIdChanged()


    def deviceStopComm(self, dev):
        self.logger.info(u"{}: Stopping {} Device {}".format( dev.name, dev.deviceTypeId, dev.id))

        if dev.deviceTypeId == 'serverDevice':
            server = self.servers[dev.id]
            del self.servers[dev.id]
            assassin = threading.Thread(target=server.server_close)
            assassin.daemon = True
            assassin.start()            
            
        elif dev.deviceTypeId == 'proxyDevice':

            webhook_info = self.getWebhookInfo(str(dev.id))
            indigo.server.subscribeToBroadcast("com.flyingdiver.indigoplugin.httpd", webhook_info["hook_name"], "CallbackNOP")
           

    ########################################
    #
    # callback for state list changes, called from stateListOrDisplayStateIdChanged()
    #
    ########################################
    def getDeviceStateList(self, device):
        state_list = indigo.PluginBase.getDeviceStateList(self, device)
        self.logger.threaddebug(u"{}: getDeviceStateList, base state_list = {}".format(device.name, state_list))
        
        if device.id in self.servers:

            try:
                device_states = self.servers[device.id].state_list
                if device_states and len(device_states) > 0:
                    for item in device_states:
                        key = item['key']
                        value = item['value']
                        new_state = self.getDeviceStateDictForStringType(unicode(key), unicode(key), unicode(key))
                        self.logger.threaddebug(u"{}: getDeviceStateList, adding String state {}, value {}".format(device.name, key, value))
                        state_list.append(new_state)
            except:
                pass
                
        self.logger.threaddebug(u"{}: getDeviceStateList, final state_list = {}".format(device.name, state_list))
        return state_list


    def webhook_proxy(self, hook_data):

        proxy_dev = indigo.devices[int(hook_data["request"]["path"][9:])]
        self.logger.debug(u"webhook_proxy saving hook data for {} ({})".format(proxy_dev.name, proxy_dev.id))
        self.proxy_data[proxy_dev.id] = hook_data

        for triggerId, trigger in sorted(self.triggers.iteritems()):
            self.logger.debug("Checking Trigger %s (%s)" % (trigger.name, trigger.id))
            if trigger.pluginProps["proxyDevice"] == str(proxy_dev.id):
                self.logger.debug("Executing Trigger %s (%s)" % (trigger.name, trigger.id))
                indigo.trigger.execute(trigger)

    def CallbackNOP(self, hook_data):
        pass


    ########################################
    # Actions
    ########################################

    def getWebhookDataAction(self, pluginAction, device, callerWaitingForResult = True):

        try:
            hook_data = self.proxy_data[device.id]
            return hook_data
        except:
            return None


    def getWebhookInfoAction(self, pluginAction, device, callerWaitingForResult = True):

        return self.getWebhookInfo(pluginAction.props.get(u"name", None))
        

    def getWebhookInfo(self, callerName):

        if not callerName:
            self.logger.debug(u"getWebhookInfo failed, caller name not provided")
            return None
            
        info = {u"hook_name" : u"httpd_webhook-" + callerName}
        
        ddnsName = self.pluginPrefs.get('ddnsName', None)
        if not ddnsName:
            return None
        
        if len(self.pluginPrefs.get('httpPassword', None)) != 0:
            auth = "{}:{}@".format(self.pluginPrefs.get('httpUser', ''), self.pluginPrefs.get('httpPassword', ''))
        else:
            auth = ''
                    
        port = int(self.pluginPrefs.get('httpPort', 0))
        if port:
            info[u"http"] = "http://{}{}:{}/webhook-{}".format(auth, ddnsName, port, callerName)
            
        port = int(self.pluginPrefs.get('httpsPort', 0))
        if port:
            info[u"https"] = "https://{}{}:{}/webhook-{}".format(auth, ddnsName, port, callerName)

        self.logger.debug(u"getWebhookInfo, info = {}".format(info))

        return info
