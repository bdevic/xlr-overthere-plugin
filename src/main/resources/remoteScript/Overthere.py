#
# THIS CODE AND INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
# FOR A PARTICULAR PURPOSE. THIS CODE AND INFORMATION ARE NOT SUPPORTED BY XEBIALABS.
#

import sys
from com.xebialabs.xlrelease.plugin.overthere import OverthereSession


def apply_task_options():
    if username:
        host.setProperty('username', username)
        host.setProperty('password', password)
    if privateKeyFile:
        host.setProperty('privateKeyFile', privateKeyFile)
        host.setProperty('passphrase', passphrase)
    host_options = host.getProperty("connectionOptions")
    for key, value in connectionOptions.iteritems():
        host_options.put(key, value)


host = task.pythonScript.getProperty("host")
apply_task_options()
session = OverthereSession(host)
response = session.execute(script, remotePath)

# set variables
output = response.stdout
error = response.stderr

if response.rc == 0:
    print output
else:
    print "Exit code "
    print response.rc
    print
    print "#### Output:"
    print output

    print "#### Error stream:"
    print error
    print
    print "----"

    sys.exit(response.rc)
