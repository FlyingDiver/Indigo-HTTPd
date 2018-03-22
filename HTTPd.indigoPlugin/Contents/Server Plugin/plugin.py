#! /usr/bin/env python
# -*- coding: utf-8 -*-
####################

import sys
import time
import os
import base64
import logging

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from urlparse import urlparse, parse_qs


# taken from http://www.piware.de/2011/01/creating-an-https-server-in-python/
# generate server.xml with the following command:
#    openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
# run as follows:
#    python simple-https-server.py
# then in your browser, visit:
#    https://localhost:4443
#import BaseHTTPServer, SimpleHTTPServer
#import ssl
#httpd = BaseHTTPServer.HTTPServer(('localhost', 4443), SimpleHTTPServer.SimpleHTTPRequestHandler)
#httpd.socket = ssl.wrap_socket (httpd.socket, certfile='./server.pem', server_side=True)
#httpd.serve_forever()



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


class AuthHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        self.logger = logging.getLogger("Plugin.AuthHandler")
        client_host, client_port = self.client_address
        self.logger.debug("AuthHandler: POST from %s:%s to %s" % (str(client_host), str(client_port), self.path))

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()


    def do_GET(self):
        self.logger = logging.getLogger("Plugin.AuthHandler")
        client_host, client_port = self.client_address
        self.logger.debug("AuthHandler: GET from %s:%s for %s" % (str(client_host), str(client_port), self.path))

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        auth_header = self.headers.getheader('Authorization')

        if auth_header == None:
            self.logger.debug("AuthHandler: Request has no Authorization header")
            self.wfile.write("<html>\n<head><title>Indigo HTTPd Plugin</title></head>\n<body>")
            self.wfile.write("\n<p>Basic Authentication Required</p>")
            self.wfile.write("\n</body>\n</html>\n")

        elif auth_header == ('Basic ' + self.server.authKey):
            self.logger.debug(u"AuthHandler: Request has correct Authorization header")
            self.wfile.write("<html>\n<head><title>Indigo HTTPd Plugin</title></head>\n<body>")
            request = urlparse(self.path)

            if request.path == "/setvar":
                query = parse_qs(request.query)
                for key in query:
                    value = query[key][0]
                    self.logger.debug(u"AuthHandler: setting variable httpd_%s to '%s'" % (key, value))
                    updateVar("httpd_"+key, value, indigo.activePlugin.pluginPrefs["folderId"])
                    self.wfile.write("\n<p>Updated variable httpd_%s to '%s'</p>" % (key, value))

                indigo.activePlugin.triggerCheck()

            elif request.path == "/stripvar":
                query = parse_qs(request.query)
                for key in query:
                    value = query[key][0].strip()
                    self.logger.debug(u"AuthHandler: setting variable httpd_%s to '%s'" % (key, value))
                    updateVar("httpd_"+key, value, indigo.activePlugin.pluginPrefs["folderId"])
                    self.wfile.write("\n<p>Updated variable httpd_%s to '%s'</p>" % (key, value))

                indigo.activePlugin.triggerCheck()

            else:
                self.logger.debug(u"AuthHandler: Unknown request: %s" % self.request)

            self.wfile.write("\n</body>\n</html>\n")

        else:
            self.logger.debug(u"AuthHandler: Request with invalid Authorization header")
            self.logger.debug(u"Theirs: '%s' -> '%s'" % (auth_header, base64.b64decode(auth_header[6:])))
            self.logger.debug(u"Ours:   '%s' -> '%s'" % ('Basic ' + self.server.authKey, base64.b64decode(self.server.authKey)))
            self.wfile.write("<html>\n<head><title>Indigo HTTPd Plugin</title></head>\n<body>")
            self.wfile.write("\n<p>Invalid Authentication</p>")
            self.wfile.write("\n</body>\n</html>\n")



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

        self.port = int(self.pluginPrefs.get('httpPort', '5555'))

        if "HTTPd" in indigo.variables.folders:
            myFolder = indigo.variables.folders["HTTPd"]
        else:
            myFolder = indigo.variables.folder.create("HTTPd")
        self.pluginPrefs["folderId"] = myFolder.id

        self.triggers = {}

        self.logger.debug(u"Starting HTTP server on port %d" % self.port)
        try:
            self.httpd = MyHTTPServer(("", self.port), AuthHandler)
        except:
            self.logger.error(u"Unable to open port %d for HHTTP Server" % self.port)
            self.httpd = None
        else:
            self.httpd.timeout = 1.0
            self.httpd.setKey(self.authKey)



    def shutdown(self):
        indigo.server.log(u"Shutting down HTTPd")


    def runConcurrentThread(self):

        try:
            while True:

                self.httpd.handle_request()

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

        httpPort = int(valuesDict['httpPort'])
        if httpPort < 1024:
            errorDict['httpPort'] = u"HTTP Port Number invalid"

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
            self.httpd.setKey(self.authKey)


    ########################################
    # Menu Methods
    ########################################

