# HTTPd

Plugin for the Indigo Home Automation system.

Runs an SMTP server inside Indigo.

The Python Twisted module is required.  Current versions of Twisted do not run on Python 2.6 (which Indigo uses), so a specific version must be installed:

`sudo pip install twisted==15.4.0`

If you don't have pip2.6 installed:

`sudo easy_install-2.6 pip`
