# HTTPd

Plugin for the Indigo Home Automation system.

Runs an HTTP server inside Indigo.

Configure port number, username, and password in the plugin configuration dialog.  You'll need to set up port forwarding on your router to the specified port.  Only ports > 1024 can be used.

Example URL to activate the plugin:

    http://username:password@my.domain.org:5566/setvar?foo=bar&zig=zag
    
The first "action" the plugin supports is "/setvar". This will set the specified variables to the values given. For protection, the variables have "httpd_" prepended to the names provided. In this case, the Indigo variable "httpd_foo" would be set to "bar", and the Indigo variable "httpd_zig" would be set to "zag". If they don't exist, the variables are created in an "HTTPd" variable folder. "/setvar" is available with either GET or POST http methods.

The next action is "/webhook" which is available using http POST only. The syntax is similar:

    http://username:password@my.domain.org:5566/webhook?name=test

In this case, the plugin will do a broadcastToSubscribers call:

    indigo.server.broadcastToSubscribers(u"httpd_webhook", broadcastDict)

and the contents of broadcastDict would be:

	{
    'request': {
     	...<the Headers from the HTTP POST request>...
    }, 
    'payload': {
     	... <the POST payload>...
    }, 
    'vars': {
        'name': 'test', 
    }
}

For more details on the URL path and payload options see the Wiki.
 
The last action is "/broadcast" which is available using http POST only.  The syntax is the same:

    http://username:password@my.domain.org:5566/broadcast?name=test

And the broadcastToSubscribers call looks like:

    indigo.server.broadcastToSubscribers(u"httpd_post_broadcast", broadcastDict)

and the contents of broadcastDict would be:

	{'name': 'test', 'payload': '<the POST payload>}

Multiple name/value pairs can be specified in the URL, similar to '/setvar'.  The "/broadcast" action has been superceded by the "/webhook" action, and is only maintained for backward compatability.

