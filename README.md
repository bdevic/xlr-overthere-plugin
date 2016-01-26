# XL Release Overthere plugin

## Build Status

[![Build Status](https://travis-ci.org/xebialabs-community/xlr-overthere-plugin.svg?branch=master)](https://travis-ci.org/xebialabs-community/xlr-overthere-plugin)

## Preface

This document describes the functionality provided by the xlr-overthere-plugin.

See the XL Release Reference Manual for background information on XL Release and release concepts.

## Overview

The Overthere plugin is an XL Release plugin that allows XL Release to manipulate files and execute commands on remote hosts. It does so by using the **Overthere** framework. Overthere is a Java library to manipulate files and execute processes on remote hosts, i.e. do stuff "over there". See the [Overthere Github repository](https://github.com/xebialabs/overthere) for more information.

### Features ###

* Supports SSH for connectivity to Unix, Windows and z/OS hosts.
* Supports CIFS, Telnet and WinRM for connectivity to Windows hosts.
* Allows SSH jumpstations to be used to access hosts to which a direct network connection is not possible.
	* **Note:** Not only SSH connection can be tunneled through an SSH jumpstation, CIFS, Telnet and WinRM can be tunneled too!
* All connection methods are implemented internally in XL Release itself, so no external dependencies are required.
	* An exception is the `WINRM_NATIVE` connection type which uses the Windows `winrs` command, but a _winrs proxy_ can be used to use this connection type when XL Release runs on a Unix host.

## Installation

Copy the plugin JAR file into the `SERVER_HOME/plugins` directory of XL Release.

Update the JVM security policy at `SERVER_HOME/conf/script.policy` to contain the following entry:

    permission java.net.SocketPermission "localhost:1024-65535", "connect, listen, accept, resolve";

## Supported Tasks

The Overthere plugin defines one generic task type - **remoteScript.Overthere** which, depending on the chosen host, executes a shell or a batch script.

Input Properties:

* `Host` is the remote host where the script executes.
* `Username` is the login ID of the user on your host.
* `Password` is the password of your user on your host.
* `Private Key File` is the private key file to use for authentication (**SSH host only**)
* `Passphrase` is the passphrase for the private key in the private key file (**SSH host only**)
* `Connection Options` are additional options passed to the Overthere connection. See the [Overthere documentation](https://github.com/xebialabs/overthere#common_connection_options) for a comprehensive list of available options.
* `Remote Path` is the path on the remote host where you script will be executed.
* `Script` is the script to execute on your remote host.

Output Properties:

* `Output` is the variable in which the standard output will be stored.
* `Error` is the variable in which the error output will be stored.

### Host types ###

The Overthere plugin defines two CI types that define the protocol that is used to access the target host:

* `remoteScript.SshHost` - connects to a Unix, Windows or z/OS host using the [SSH protocol](http://en.wikipedia.org/wiki/Secure_Shell). For Windows, OpenSSH on [Cygwin](http://www.cygwin.com) (i.e. [Copssh](https://www.itefix.no/i2/copssh)) and [WinSSHD](http://www.bitvise.com/winsshd) are supported.
* `remoteScript.CifsHost` - connects to a Windows host using the [CIFS protocol](http://en.wikipedia.org/wiki/Server_Message_Block), also known as SMB, for file manipulation and, depending on the settings, using either [WinRM](http://en.wikipedia.org/wiki/WS-Management) or [Telnet](http://en.wikipedia.org/wiki/Telnet) for process execution. This protocol is not supported for Unix or z/OS hosts.

For further details on the available options as well as usage and troubleshooting scenarios, please see the [Overthere documentation](https://github.com/xebialabs/overthere#table-of-contents).

## Advanced configuration

### Connecting through an SSH jumpstation

When XL Release cannot reach a remote host directly, but that host can be reached by setting up one (or more) SSH tunnels, configure one (or more) **remoteScript.SshJumpstation** CIs as follows:

1. Create an **remoteScript.SshJumpStation** CI that represents a host to which XL Release can connect directly.
1. For each remote host that cannot be reached directly by XL Release, create an **remoteScript.Host** as usual, but set the **jumpstation** property to refer to the **remoteScript.SshJumpStation** CI created in step 1.

When XL Release creates a connection to the remote host and determines that it needs to connect through a jumpstation, and will first open a connection to that jumpstation and then setup a SSH tunnel ("local port forward") to the remote host.

**Note:** Jumpstations can also refer to other jumpstations for even more complex network setups, but cycles are not allowed.

### Additional Overthere properties in XL Release

Additional Overthere connection properties defined in the [Overthere documentation](https://github.com/xebialabs/overthere/blob/master/README.md) can be provided by using the **connectionOptions** key-value map.
This map is available on the **remoteScript.Host** configuration and the **remoteScript.Overthere** task. When the same property is defined on both place, the task value overrides the host defined value.

If you need to provide a different default value, or wish to provide an additional property to the end user, you can also create a `type-modification` in the `ext/synthetic.xml` file like this:

	<type-modification type="remoteScript.SshHost">
		<property name="listFilesCommand" hidden="true" default="/bin/ls -a1 {0}" />
		<property name="getFileInfoCommand" hidden="true" default="/bin/ls -ld {0}" />
		<property name="connectionTimeoutMillis" category="Advanced" kind="integer" default="1800000" description="Number of milliseconds Overthere waits for a connection to a remote host to be established"/>
	</type-modification>
