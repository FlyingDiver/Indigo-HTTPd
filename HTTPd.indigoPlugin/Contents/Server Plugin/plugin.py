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

########################################
class MyHTTPServer(HTTPServer):

    def setUser(self, user):
        self.user = user

    def setPassword(self, password):
        self.password = password

    def setDigestRequired(self, digestRequired):
        self.digestRequired = digestRequired


class RequestHandler(BaseHTTPRequestHandler):

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
    
    def authorized(self, auth_header, method):

        auth_scheme, auth_params  = auth_header.split(" ", 1)
        auth_scheme = auth_scheme.lower()
        if auth_scheme == 'basic':
            username, password = base64.decodestring(auth_params).split (":", 1)
            auth_map = {"username": username, "password": password}
        elif auth_scheme == 'digest':
            # Convert the auth params to a dict
            items = urllib2.parse_http_list(auth_params)
            auth_map = urllib2.parse_keqv_list(items)
        else:
            self.logger.debug(u"RequestHandler: Invalid authentication scheme")
            return False
                
        self.logger.debug("RequestHandler: auth_map = {}".format(auth_map))
            
        # check username
        if auth_map["username"] != self.server.user:
            self.logger.debug("RequestHandler: Username mismatch")
            return False
                
        if auth_scheme == "basic":
            if self.server.digestRequired:
                self.logger.debug(u"RequestHandler: {} Authorization not allowed".format(auth_scheme).capitalize())
                return False
                
            if auth_map["password"] == self.server.password:
                self.logger.debug(u"RequestHandler: {} Authorization valid".format(auth_scheme).capitalize())
                return True
            else:
                self.logger.debug(u"RequestHandler: {} Authorization failed".format(auth_scheme).capitalize())
                return False
 
        elif auth_scheme == "digest":

            h1 = hashlib.md5(self.server.user + ":" + REALM + ":" + self.server.password).hexdigest()
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
        
        auth_header = self.headers.getheader('Authorization')        
        if auth_header == None:
            self.logger.debug("RequestHandler: Request has no Authorization header")
            self.send_reply(401)
            return
                            
        if not self.authorized(auth_header, "POST"):
            self.logger.debug(u"RequestHandler: Request failed {} Authorization".format(auth_scheme).capitalize())
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
                
            self.logger.debug("POST Broadcast = {}".format(broadcastDict, indent=4, sort_keys=True))
            indigo.server.broadcastToSubscribers(u"httpd_"+request.path[1:], broadcastDict)
        
        else:
            self.logger.debug(u"RequestHandler: Unknown request: %s" % request.path)

        self.send_reply(200)

        indigo.activePlugin.triggerCheck()



    def do_GET(self):
        self.logger = logging.getLogger("Plugin.RequestHandler")
        client_host, client_port = self.client_address
        self.logger.debug("RequestHandler: GET from %s:%s for %s" % (str(client_host), str(client_port), self.path))

        auth_header = self.headers.getheader('Authorization')

        if auth_header == None:
            self.logger.debug("RequestHandler: Request has no Authorization header")
            self.send_reply(401)

        if not self.authorized(auth_header, "GET"):
            self.logger.debug(u"RequestHandler: Request failed {} Authorization".format(auth_scheme).capitalize())
            self.send_reply(401)
            return

        request = urlparse(self.path)

        if request.path == "/setvar":
            query = parse_qs(request.query)
            for key in query:
                value = query[key][0]
                self.logger.debug(u"RequestHandler: setting variable httpd_%s to '%s'" % (key, value))
                updateVar("httpd_"+key, value, indigo.activePlugin.pluginPrefs["folderId"])

        else:
            self.logger.debug(u"RequestHandler: Unknown request: %s" % request.path)

        self.send_reply(200)

        indigo.activePlugin.triggerCheck()


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

        self.httpPort = int(self.pluginPrefs.get('httpPort', '5555'))
        self.httpsPort = int(self.pluginPrefs.get('httpsPort', '0'))

        if "HTTPd" in indigo.variables.folders:
            myFolder = indigo.variables.folders["HTTPd"]
        else:
            myFolder = indigo.variables.folder.create("HTTPd")
        self.pluginPrefs["folderId"] = myFolder.id

        self.triggers = {}

        self.httpd  = self.start_server(self.httpPort)
        self.httpsd = self.start_server(self.httpsPort, https=True)
        
        
    def shutdown(self):
        indigo.server.log(u"Shutting down HTTPd")


    def start_server(self, port, https=False):
    
        server = None

        if https:        
            certfile = indigo.server.getInstallFolderPath() + '/httpd_server.pem'
            if not os.path.isfile(certfile):
                self.logger.error(u"Certificate file missing, unable to start HTTPS server")
                return None
           
        if port > 0:
            try:
                server = MyHTTPServer(("", port), RequestHandler)
            except:
                self.logger.error(u"Unable to open port %d for HTTP Server" % port)
                return None
            
            server.timeout = 1.0
            server.setUser(self.pluginPrefs.get('httpUser', 'username'))
            server.setPassword(self.pluginPrefs.get('httpPassword', 'password'))
            server.setDigestRequired(self.pluginPrefs.get('digestRequired', False))
        else:
            return None
            
        if https:
            server.socket = ssl.wrap_socket(server.socket, certfile=certfile, server_side=True)
            self.logger.debug(u"Started HTTPS server on port %d" % port)
       
        else:
            self.logger.debug(u"Started HTTP server on port %d" % port)
            
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
        self.logger.debug("Adding Trigger %s (%d) - %s" % (trigger.name, trigger.id, trigger.pluginTypeId))
        assert trigger.id not in self.triggers
        self.triggers[trigger.id] = trigger

    def triggerStopProcessing(self, trigger):
        self.logger.debug("Removing Trigger %s (%d)" % (trigger.name, trigger.id))
        assert trigger.id in self.triggers
        del self.triggers[trigger.id]

    def triggerCheck(self):
        for triggerId, trigger in sorted(self.triggers.iteritems()):
            self.logger.debug("Checking Trigger %s (%s), Type: %s" % (trigger.name, trigger.id, trigger.pluginTypeId))
            if trigger.pluginTypeId == 'requestReceived':
                indigo.trigger.execute(trigger)


    ####################
    def validatePrefsConfigUi(self, valuesDict):
        self.logger.debug(u"validatePrefsConfigUi called")
        errorDict = indigo.Dict()

        try:
            port = int(valuesDict['httpPort'])
        except:
            errorDict['httpPort'] = u"HTTP Port Number invalid"
        else:
            if 0 < port < 1024:
                errorDict['httpPort'] = u"HTTP Port Number invalid"

        try:
            port = int(valuesDict['httpsPort'])
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
            
            if valuesDict['httpPort'] == '0':
                self.httpd = None
                self.httpPort = 0
            elif int(valuesDict['httpPort']) != self.httpPort:
                self.httpPort = int(valuesDict['httpPort'])
                self.httpd = self.start_server(self.httpPort)
            
            if valuesDict['httpsPort'] == '0':
                self.httpsd = None
                self.httpsPort = 0
            elif int(valuesDict['httpsPort']) != self.httpsPort:
                self.httpsPort = int(valuesDict['httpsPort'])
                self.httpsd = self.start_server(self.httpsPort, https=True)


    ########################################
    # Menu Methods
    ########################################

