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

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from urlparse import urlparse, parse_qs
import urllib2

REALM = "HTTPd Plugin"

########################################

def updateVar(name, value, folder):
    if name not in indigo.variables:
        indigo.variable.create(name, value=value, folder=folder)
    else:
        indigo.variable.updateValue(name, value)

class RequestHandler(BaseHTTPRequestHandler):

    def send_reply(self, code):

        nonce = hashlib.md5("{}:{}".format(time.time(), REALM)).hexdigest() 
        if indigo.activePlugin.pluginPrefs.get('digestRequired', None):
            authHeader = 'Digest realm="{}", nonce="{}", algorithm="MD5", qop="auth"'.format(REALM, nonce)
        else:
            authHeader = 'Digest realm="{}", nonce="{}", algorithm="MD5", qop="auth" Basic realm="{}"'.format(REALM, nonce, REALM)
            
        self.send_response(code)
        self.send_header('WWW-Authenticate', authHeader)
        self.send_header("Content-type", "text/html")
        self.end_headers()
    
    def authorized(self, method):

        if len(indigo.activePlugin.pluginPrefs.get('httpPassword', None)) == 0:    # no authentication needed
            self.logger.debug("RequestHandler: No password specified in plugin preferences, skipping authentication")
            return True
            
        auth_header = self.headers.getheader('Authorization')        
        if auth_header == None:
            self.logger.debug("RequestHandler: Request has no Authorization header")
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
            self.logger.debug(u"RequestHandler: Invalid authentication scheme: {}".format(auth_scheme))
            return False
                
        self.logger.debug("RequestHandler: auth_map = {}".format(auth_map))
            
        # check username
        if auth_map["username"] != indigo.activePlugin.pluginPrefs.get('httpUser', None):
            self.logger.debug("RequestHandler: Username mismatch")
            return False
                
        if auth_scheme == "basic":
            if indigo.activePlugin.pluginPrefs.get('digestRequired', None):
                self.logger.debug(u"RequestHandler: {} Authorization not allowed".format(auth_scheme).capitalize())
                return False
                
            if auth_map["password"] == indigo.activePlugin.pluginPrefs.get('httpPassword', None):
                self.logger.debug(u"RequestHandler: {} Authorization valid".format(auth_scheme).capitalize())
                return True
            else:
                self.logger.debug(u"RequestHandler: {} Authorization failed".format(auth_scheme).capitalize())
                return False
 
        elif auth_scheme == "digest":

            h1 = hashlib.md5(indigo.activePlugin.pluginPrefs.get('httpUser', None) + ":" + REALM + ":" + indigo.activePlugin.pluginPrefs.get('httpPassword', None)).hexdigest()
            h2 = hashlib.md5(method + ":" + auth_map["uri"]).hexdigest()
            rs = h1 + ":" + auth_map["nonce"] + ":" + auth_map["nc"] + ":" + auth_map["cnonce"] + ":" + auth_map["qop"] + ":" + h2
            if hashlib.md5(rs).hexdigest() == auth_map["response"]:
                self.logger.debug(u"RequestHandler: {} Authorization valid".format(auth_scheme).capitalize())
                return True
            else:
                self.logger.debug(u"RequestHandler: {} Authorization failed".format(auth_scheme).capitalize())
                return False

        else:
            self.logger.debug(u"RequestHandler: {} Authorization invalid".format(auth_scheme).capitalize())
            return False


    def do_POST(self):
        self.logger = logging.getLogger("Plugin.RequestHandler")
        client_host, client_port = self.client_address
        self.logger.debug("RequestHandler: POST from %s:%s to %s" % (str(client_host), str(client_port), self.path))
        
        if not self.authorized("POST"):
            self.send_reply(401)
            return
                       
        request = urlparse(self.path)

        if request.path == "/setvar":
            query = parse_qs(request.query)
            for key in query:
                value = query[key][0]
                self.logger.debug(u"RequestHandler: setting variable httpd_%s to '%s'" % (key, value))
                updateVar("httpd_"+key, value, indigo.activePlugin.pluginPrefs["folderId"])

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
            self.logger.debug(u"RequestHandler: Unknown request: %s" % request.path)

        self.send_reply(200)



    def do_GET(self):
        self.logger = logging.getLogger("Plugin.RequestHandler")
        client_host, client_port = self.client_address
        self.logger.debug("RequestHandler: GET from %s:%s for %s" % (str(client_host), str(client_port), self.path))

        if not self.authorized("GET"):
            self.send_reply(401)
            return

        request = urlparse(self.path)

        if request.path == "/setvar":
            query = parse_qs(request.query)
            for key in query:
                value = query[key][0]
                newvar = "httpd_"+key
                self.logger.debug(u"RequestHandler: setting variable {} to '{}'".format(newvar, value))
                updateVar(newvar, value, indigo.activePlugin.pluginPrefs["folderId"])

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
            self.logger.debug(u"RequestHandler: Unknown request: %s" % request.path)

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
        self.logger.debug(u"logLevel = " + str(self.logLevel))


    def startup(self):
        indigo.server.log(u"Starting HTTPd")

        self.httpPort = int(self.pluginPrefs.get('httpPort', 0))
        self.httpsPort = int(self.pluginPrefs.get('httpsPort', 0))

        if "HTTPd" in indigo.variables.folders:
            myFolder = indigo.variables.folders["HTTPd"]
        else:
            myFolder = indigo.variables.folder.create("HTTPd")
        self.pluginPrefs["folderId"] = myFolder.id

        self.triggers = {}
        self.proxy_data = {}
        
        self.httpd  = self.start_server(self.httpPort)
        self.httpsd = self.start_server(self.httpsPort, https=True)
        
        indigo.server.subscribeToBroadcast("com.flyingdiver.indigoplugin.httpd", u"httpd_webhook-httpd", "webHook")       

    def webHook(self, hookData):
        self.logger.debug(u"webHook received:\n{}".format(hookData))

    def shutdown(self):
        indigo.server.log(u"Shutting down HTTPd")


    def start_server(self, port, https=False):
    
        if port == 0:
            return None

        if not https:
            try:
                server = HTTPServer(("", port), RequestHandler)
                server.timeout = 1.0
                self.logger.debug(u"Started HTTP server on port %d" % port)
                return server
                
            except:
                self.logger.error(u"Unable to open port %d for HTTP Server" % port)
                return None
        
        else:

            certfile = indigo.server.getInstallFolderPath() + '/' + self.pluginPrefs.get('certfileName', '')
            if not os.path.isfile(certfile):
                self.logger.error(u"Certificate file missing, unable to start HTTPS server")
                return None

            try:
                server = HTTPServer(("", port), RequestHandler)
                server.timeout = 1.0
            except:
                self.logger.error(u"Unable to open port %d for HTTP Server" % port)
                return None

            keyfileName = self.pluginPrefs.get('keyfileName', None)
            if not keyfileName:
                keyfile = None
            else:
                keyfile = indigo.server.getInstallFolderPath() + '/' + keyfileName
                if not os.path.isfile(keyfile):
                    self.logger.error(u"Key file missing, unable to start HTTPS server")
                    return None
            
            server.socket = ssl.wrap_socket(server.socket, keyfile=keyfile, certfile=certfile, server_side=True)
            self.logger.debug(u"Started HTTPS server on port %d" % port)
            return server


    def runConcurrentThread(self):

        try:
            while True:

                if self.httpd:
                    self.httpd.handle_request()
                if self.httpsd:
                    self.httpsd.handle_request()

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

        try:
            port = int(valuesDict.get('httpPort', '0'))
        except:
            errorDict['httpPort'] = u"HTTP Port Number invalid"
        else:
            if 0 < port < 1024:
                errorDict['httpPort'] = u"HTTP Port Number invalid"

        try:
            port = int(valuesDict.get('httpsPort', 0))
        except:
            errorDict['httpsPort'] = u"HTTPS Port Number invalid"
        else:
            if 0 < port < 1024:
                errorDict['httpsPort'] = u"HTTPS Port Number invalid"

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
            self.logger.debug(u"logLevel = " + str(self.logLevel))
            
            port = int(valuesDict.get('httpPort', 0))
            if not port:
                self.httpd = None
                self.httpPort = 0
            elif port != self.httpPort:
                self.httpPort = port
                self.httpd = self.start_server(self.httpPort)
            
            port = int(valuesDict.get('httpsPort', 0))
            if not port:
                self.httpd = None
                self.httpPort = 0
            elif port != self.httpsPort:
                self.httpsPort = port
                self.httpsd = self.start_server(self.httpsPort, https=True)


    def deviceStartComm(self, dev):
        self.logger.info(u"{}: Starting {} Device {}".format(dev.name, dev.deviceTypeId, dev.id))
                    
        if dev.deviceTypeId == 'proxyDevice':

            webhook_info = self.getWebhookInfo(str(dev.id))
            stateList = [
                            {'key': 'http',      'value': webhook_info.get("http",None)},
                            {'key': 'https',     'value': webhook_info.get("https",None)} 
                        ]
            dev.updateStatesOnServer(stateList)

            indigo.server.subscribeToBroadcast("com.flyingdiver.indigoplugin.httpd", webhook_info["hook_name"], "webhook_proxy")
           

    def deviceStopComm(self, dev):
        self.logger.info(u"{}: Stopping {} Device {}".format( dev.name, dev.deviceTypeId, dev.id))

    def webhook_proxy(self, hook_data):

        proxy_dev = indigo.devices[int(hook_data["request"]["path"][9:])]
        self.logger.debug(u"webhook_proxy saving hook data for {} ({})".format(proxy_dev.name, proxy_dev.id))
        self.proxy_data[proxy_dev.id] = hook_data

        for triggerId, trigger in sorted(self.triggers.iteritems()):
            self.logger.debug("Checking Trigger %s (%s)" % (trigger.name, trigger.id))
            if trigger.pluginProps["proxyDevice"] == str(proxy_dev.id):
                self.logger.debug("Executing Trigger %s (%s)" % (trigger.name, trigger.id))
                indigo.trigger.execute(trigger)




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
