#! /usr/bin/env python
# -*- coding: utf-8 -*-
####################

import base64
import logging
import json

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from urlparse import urlparse, parse_qs
import ssl
import os.path

########################################

def updateVar(name, value, folder):
    if name not in indigo.variables:
        indigo.variable.create(name, value=value, folder=folder)
    else:
        indigo.variable.updateValue(name, value)

########################################
class MyHTTPServer(HTTPServer):

    def setKey(self, authKey):
        self.authKey = authKey


class RequestHandler(BaseHTTPRequestHandler):

    def send_reply(self, code, msgs):
        self.send_response(code)
        self.send_header('WWW-Authenticate', 'Basic realm="My Realm"')
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write("<html>\n<head><title>Indigo HTTPd Plugin</title></head>\n<body>")
        if len(msgs) > 0:
            for m in msgs:
                self.wfile.write("\n<p>{}</p>".format(m))
        else:
            self.wfile.write("\n<p></p>".format(m))        
        self.wfile.write("\n</body>\n</html>\n")
    
    
    def do_POST(self):
        self.logger = logging.getLogger("Plugin.RequestHandler")
        client_host, client_port = self.client_address
        self.logger.debug("RequestHandler: POST from %s:%s to %s" % (str(client_host), str(client_port), self.path))

        auth_header = self.headers.getheader('Authorization')

        if auth_header == None:
            self.logger.debug("RequestHandler: Request has no Authorization header")
            self.send_reply(401, ["Basic Authentication Required"])

        elif auth_header == ('Basic ' + self.server.authKey):
            self.logger.debug(u"RequestHandler: Request has correct Authorization header")

            msgs = []           
            request = urlparse(self.path)

            if request.path == "/setvar":
                query = parse_qs(request.query)
                for key in query:
                    value = query[key][0]
                    self.logger.debug(u"RequestHandler: setting variable httpd_%s to '%s'" % (key, value))
                    updateVar("httpd_"+key, value, indigo.activePlugin.pluginPrefs["folderId"])
                    msgs.append("Updated variable httpd_{} to '{}'".format(key, value))

            elif request.path == "/broadcast":
                self.logger.debug(u"RequestHandler: received broadcast request")
                msgs.append("Handling broadcast request")

                broadcastDict = {}
                query = parse_qs(request.query)
                for key in query:
                    value = query[key][0]
                    broadcastDict[key] = value
                    msgs.append("Setting broadcastDict entry '{}' to '{}'".format(key, value))
                
                payload = self.rfile.read(int(self.headers['Content-Length']))
                broadcastDict["payload"] = payload
                msgs.append("Setting dict entry 'payload' to '{}'".format(payload))
                self.logger.debug("POST Broadcast = {}".format(broadcastDict, indent=4, sort_keys=True))
                indigo.server.broadcastToSubscribers(u"httpd_post_broadcast", broadcastDict)
            
            elif request.path.startswith("/webhook"):
                self.logger.debug(u"RequestHandler: received webook request")
                msgs.append("Handling webhook request")

                broadcastDict = {}
                varsDict = {}
                query = parse_qs(request.query)
                for key in query:
                    value = query[key][0]
                    varsDict[key] = value
                    msgs.append("Setting varsDict entry '{}' to '{}'".format(key, value))
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
                    msgs.append("Setting dict entry 'payload' to '{}'".format(payload))
                except:
                    pass
                    
                self.logger.debug("POST Broadcast = {}".format(broadcastDict, indent=4, sort_keys=True))
                indigo.server.broadcastToSubscribers(u"httpd_"+request.path[1:], broadcastDict)
            
            else:
                self.logger.debug(u"RequestHandler: Unknown request: %s" % request.path)
                msgs = ["Unknown request: {}".format(request.path)]

            self.send_reply(200, msgs)

            indigo.activePlugin.triggerCheck()

        else:
            self.logger.debug(u"RequestHandler: Request with invalid Authorization header")
            self.logger.debug(u"Theirs: '%s' -> '%s'" % (auth_header, base64.b64decode(auth_header[6:])))
            self.logger.debug(u"Ours:   '%s' -> '%s'" % ('Basic ' + self.server.authKey, base64.b64decode(self.server.authKey)))
            self.send_reply(401, ["Invalid Authentication"])


    def do_GET(self):
        self.logger = logging.getLogger("Plugin.RequestHandler")
        client_host, client_port = self.client_address
        self.logger.debug("RequestHandler: GET from %s:%s for %s" % (str(client_host), str(client_port), self.path))

        auth_header = self.headers.getheader('Authorization')

        if auth_header == None:
            self.logger.debug("RequestHandler: Request has no Authorization header")
            self.send_reply(401, ["Basic Authentication Required"])

        elif auth_header == ('Basic ' + self.server.authKey):
            self.logger.debug(u"RequestHandler: Request has correct Authorization header")

            msgs = []           
            request = urlparse(self.path)

            if request.path == "/setvar":
                query = parse_qs(request.query)
                for key in query:
                    value = query[key][0]
                    self.logger.debug(u"RequestHandler: setting variable httpd_%s to '%s'" % (key, value))
                    updateVar("httpd_"+key, value, indigo.activePlugin.pluginPrefs["folderId"])
                    msgs.append("Updated variable httpd_{} to '{}'".format(key, value))

            else:
                self.logger.debug(u"RequestHandler: Unknown request: %s" % request.path)
                msgs = ["Unknown request: {}".format(request.path)]

            self.send_reply(200, msgs)

            indigo.activePlugin.triggerCheck()

        else:
            self.logger.debug(u"RequestHandler: Request with invalid Authorization header")
            self.logger.debug(u"Theirs: '%s' -> '%s'" % (auth_header, base64.b64decode(auth_header[6:])))
            self.logger.debug(u"Ours:   '%s' -> '%s'" % ('Basic ' + self.server.authKey, base64.b64decode(self.server.authKey)))
            self.send_reply(401, ["Invalid Authentication"])


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

        user = self.pluginPrefs.get('httpUser', 'username')
        password = self.pluginPrefs.get('httpPassword', 'password')
        self.authKey = base64.b64encode(user + ":" + password)
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
        
        indigo.server.subscribeToBroadcast("com.flyingdiver.indigoplugin.httpd", u"httpd_webhook", "webHook")
        indigo.server.subscribeToBroadcast("com.flyingdiver.indigoplugin.httpd", u"httpd_webhook/httpd", "webHook")

    def shutdown(self):
        indigo.server.log(u"Shutting down HTTPd")

    def webHook(self, hookData):
        self.logger.debug(u"webHook: hookData:\n{}".format(hookData))

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
            server.setKey(self.authKey)
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

            self.authKey = base64.b64encode(valuesDict[u"httpUser"] + ":" + valuesDict[u"httpPassword"])
            
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

