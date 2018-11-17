# HTTPd

Plugin for the Indigo Home Automation system.

Runs an HTTP server inside Indigo.

Configure port number, username, and password in the plugin configuration dialog.  You'll need to set up port forwarding on your router to the specified port.  Only ports > 1024 can be used.

Example URL to activate the plugin:
    http://username:password@my.domain.org:5566/setvar?foo=bar&zig=zag
    
At this time, the only "action" the plugin will do is "/setvar". This will set the specified variables to the values given. For protection, the variables have "httpd_" prepended to the names provided. In this case, the Indigo variable "httpd_foo" would be set to "bar", and the Indigo variable "httpd_zig" would be set to "zag". If they don't exist, the variables are created in an "HTTPd" variable folder.
