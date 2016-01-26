## Overthere Plugin

This document describes the functionality provided by the XL Release Overthere plugin.

## Overview ##




## Connection types ##

The **remoteScript.SshHost** and **remoteScript.CifsHost** types each have a **connectionType** property that defines more precisely how to connect to the remote host.

### SSH connection types ###

The **connectionType** property of an **remoteScript.SshHost** defines how files are transferred and how commands are executed on the remote host. Possible values are:

* **SFTP** - uses [SFTP](http://en.wikipedia.org/wiki/SSH_File_Transfer_Protocol) to transfer files to a Unix host or a z/OS host. Requires the SFTP subsystem to be enabled, which is the default for most SSH servers.  
This is the only connection type available for z/OS hosts.
* **SFTP_CYGWIN** - uses SFTP to transfer files to a Windows host running OpenSSH on Cygwin.  
This connection type can only be used for Windows hosts.
* **SFTP_WINSSHD** - uses SFTP to transfer files to a Windows host running WinSSHD.  
This connection type can only be used for Windows hosts.
* **SCP** - uses SCP to transfer files to a Unix host. The is the fastest connection type available for Unix hosts.
* **SUDO** - like the **SCP** connection type, but uses the [sudo](http://en.wikipedia.org/wiki/Sudo) command to execute commands and to copy files from and to their actual locations. Requires all commands to be executed to have been configured with `NOPASSWD` in the `/etc/sudoers` configuration file.  
If this connection type is selected, the **sudoUsername** property should be set to specify the user that _does_ have the necessary permissions.
* **INTERACTIVE_SUDO** - like the **SUDO** connection type, but does not require the `NOPASSWD` option to have been configured for all commands.  It enables detection of the password prompt that is shown by the `sudo` command when the login user (**username**) tries to execute a commands as the privileged user (**sudoUsername**) when that command has not been configured with `NOPASSWD`, and causes the password of **username** to be sent in reply.  
**Note:** Because the password of the login user (**username**) is needed to answer this prompt, this connection type is incompatible with the **privateKeyFile** property that can be used to authenticate with a private key file.

For more details on how to configure the remote hosts and your XL Release server for SSH, see [the section on SSH of this document](#ssh). Troubleshooting tips are included too.

### CIFS connection types (includes WinRM and Telnet) ###

The **connectionType** property of an **remoteScript.CifsHost** defines how commands are executed on the remote host. Files are always transferred using CIFS. Possibles values are:

* **WINRM_INTERNAL** - uses WinRM over HTTP(S) to execute remote commands. The **port** property specifies the Telnet port to connect to. The default value is `5985` for HTTP and `5986` for HTTPS.  
A Java implementation of WinRM internal to XL Release is used.
* **WINRM_NATIVE** - like **WINRM_INTERNAL** but uses the native Windows implementation of WinRM, i.e. the `winrs` command.  
If the XL Release server is not running on a Windows host, a [winrs proxy](#winrs_proxy) must be configured.
* **TELNET** - uses Telnet to execute remote commands. The **port** property specifies the Telnet port to connect to. The default value is `23`.

All CIFS connection types can only be used for Windows hosts. For more details on how to configure the remote hosts and your XL Release server for CIFS, WinRM and Telnet, see [the relevant section of this document](#cifs). Troubleshooting tips are included too.

### Which host type and connection type to choose? ###

To determine what kind of host to create and what connection type to choose, please follow these guidelines.

* Is the remote host the XL Release server itself?
	* Yes -> Create an **overthere.LocalHost** CI. Done.
* Is the remote host a Unix host?
	* Yes -> Create an **overthere.SshHost** CI, set the **os** to `UNIX`, and answer the questions below:
	* Can you connect to the target system with the user that has the privileges to manipulate the files and execute the commands required?
		* Yes -> Use the **SCP** connection type. Done.
	* Do you need to log in as one user and then use `sudo` (or a similar command like `sx` but not `su`) to execute commands and manipulate files as a different user?
		* Yes -> Answer the questions below:
		* Are the commands you need configured with `NOPASSWD` in the `/etc/sudoers` configuration file? In other words, are you not prompted for a password when executing `sudo COMMAND`?
			* Yes -> Use the **SUDO** connection type. Done.
			* No -> Use the **INTERACTIVE_SUDO** connection type. Done.
	* Do you need to log in as one user and then use `su` to execute commands and manipulate files as a different user?
		* Yes -> Use the **SU** connection type. Done.
* Is the remote host a Windows host?
	* Yes -> Answer the questions below.
	* Have you configured WinRM on the remote host?
		* Yes -> Create an **overthere.CifsHost** CI and answer the questions below:
			* Is the XL Release server running on a Windows host?
				* Yes -> Use the **WINRM_NATIVE** connection type. Done.
				* No -> Use the **WINRM_INTERNAL** connection type. Done.
	* Have you installed WinSSHD on the remote host?
		* Yes -> Create an **overthere.SshHost** CI, set the **os** to `WINDOWS`, and use the **SFTP_WINSSHD** connection type. Done.
	* Have you installed OpenSSH (e.g. Cygwin or Copssh) on the remote host?
		* Yes -> Create an **overthere.SshHost** CI, set the **os** to `WINDOWS`, and use the **SFTP_CYGWIN** connection type. Done.
	* Have you configured Telnet on the remote host?
		* Yes -> Create an **overthere.CifsHost** CI and use the **TELNET** connection type. Done.
	* If you have not yet configured either WinRM, SSH or Telnet, please configure WinRM and start from the top.
* Is the remote host a z/OS host?
	* Yes -> Create an **overthere.SshHost** CI, set the **os** to `ZOS`, and use the **SFTP** connection type. Done.

<a name="ssh"></a>
## SSH ##

The SSH protocol support of XL Release uses the [SSH](http://en.wikipedia.org/wiki/Secure_Shell) protocol to connect to remote hosts to manipulate files and execute commands. Most Unix systems already have an SSH server installed and configured and a number of different SSH implementations are available for Windows although not all of them are supported by XL Release.

### Compatibility

XL Release uses the [sshj](https://github.com/shikhar/sshj) library for SSH and supports all algorithms and formats supported by that library:

* Ciphers: ``aes{128,192,256}-{cbc,ctr}``, ``blowfish-cbc``, ``3des-cbc``
* Key Exchange methods: ``diffie-hellman-group1-sha1``, ``diffie-hellman-group14-sha1``
* Signature formats: ``ssh-rsa``, ``ssh-dss``
* MAC algorithms: ``hmac-md5``, ``hmac-md5-96``, ``hmac-sha1``, ``hmac-sha1-96``
* Compression algorithms: ``zlib`` and ``zlib@openssh.com`` (delayed zlib)
* Private Key file formats: ``pkcs8`` encoded (the format used by [OpenSSH](http://www.openssh.com/))

<a name="ssh_host_setup"></a>
### Host setup for SSH

<a name="ssh_host_setup_ssh"></a>
#### SSH
To connect to a remote host using the SSH protocol, you will need to install an SSH server on that remote host. For Unix platforms, we recommend [OpenSSH](http://www.openssh.com/). It is included in all Linux distributions and most other Unix flavours. For Windows platforms two SSH servers are supported:

* OpenSSH on [Cygwin](http://www.cygwin.com/). We recommend [Copssh](http://www.itefix.no/i2/copssh) as a convenient packaging of OpenSSH and Cygwin. It is a free source download but since 22/11/2011 the binary installers are a paid solution.
* [WinSSHD](http://www.bitvise.com/winsshd) is a commercial SSH server that has many configuration options.

**Note:** The **SFTP**, **SCP**, **SUDO** and **INTERACTIVE_SUDO** connection types are only available for Unix hosts. To use SSH with z/OS hosts, use the **SFTP** connection type. To use SSH with Windows hosts, choose either the **SFTP_CYGWIN** or the **SFTP_WINSSHD** connection type.

<a name="ssh_host_setup_sftp"></a>
#### SFTP

To use the **SFTP** connection type, make sure SFTP is enabled in the SSH server. This is enabled by default in most SSH servers.

<a name="ssh_host_setup_sftp_cygwin"></a>
#### SFTP_CYGWIN

To use the **SFTP_CYGWIN** connection type, install [Copssh](http://www.itefix.no/i2/copssh) on your Windows host. In the Copssh control panel, add the users as which you want to connect and select _Linux shell and Sftp_ in the _shell_ dropdown box. Check _Password authentication_ and/or _Public key authentication_ depending on the authentication method you want to use.

**Note:** XL Release will take care of the translation from Windows style paths, e.g. `C:\Program Files\IBM\WebSphere\AppServer`, to Cygwin-style paths, e.g. `/cygdrive/C/Program Files/IBM/WebSphere/AppServer`, so that your code can use Windows style paths.

<a name="ssh_host_setup_sftp_winsshd"></a>
#### SFTP_WINSSHD

To use the **SFTP_WINSSHD** connection type, install [WinSSHD](http://www.bitvise.com/winsshd) on your Windows host. In the Easy WinSSHD Settings control panel, add the users as which you want to connect, check the _Login allowed_ checkbox and select _Allow full access_ in the _Virtual filesystem layout_ dropdown box. Alternatively you can check the _Allow login to any Windows account_ to allow access to all Windows accounts.

**Note:** XL Release will take care of the translation from Windows style paths, e.g. `C:\Program Files\IBM\WebSphere\AppServer`, to WinSSHD-style paths, e.g. `/C/Program Files/IBM/WebSphere/AppServer`, so that your code can use Windows style paths.
 
<a name="ssh_host_setup_sudo"></a>
<a name="ssh_host_setup_interactive_sudo"></a>
#### SUDO and INTERACTIVE_SUDO

To use the **SUDO** connection type, the `/etc/sudoers` configuration will have to be set up in such a way that the user configured with the **username** property can execute the commands below as the user configured with the **sudoUsername** property. The arguments passed to these commands depend on the exact usage of the XL Release connection. Check the `INFO` messages on the `com.xebialabs.overthere.ssh.SshConnection` category to see what commands get executed.

* `chmod`
* `cp`
* `ls`
* `mkdir`
* `mv`
* `rm`
* `rmdir`
* `tar`
* Any other command that might be invoked by the middleware plugins, e.g. `wsadmin.sh` or `wlst.sh`.
    
The commands mentioned above must be configured with the **NOPASSWD** setting in the `/etc/sudoers` file. Otherwise you will have to use the **INTERACTIVE_SUDO** connection type. When the **INTERACTIVE_SUDO** connection type is used, every line of the output will be matched against the regular expression configured with the **sudoPasswordPromptRegex** property. If a match is found, the value of the **password** property is sent.

<a name="ssh_troubleshooting"></a>
### Troubleshooting SSH

This section lists a number of common configuration errors that can occur when using XL Release with SSH.

#### Cannot start a process on an SSH server because the server disconnects immediately

If the terminal type requested using the **allocatePty** property or the **allocateDefaultPty** property is not recognized by the SSH server, the connection will be dropped. Specifically, the `dummy` terminal type configured by **allocateDefaultPty** property, will cause OpenSSH on AIX and WinSSHD to drop the connection. Try a safe terminal type such as `vt220` instead.

To verify the behavior of your SSH server with respect to pty allocation, you can manually execute the <code>ssh</code> command with the `-T` (disable pty allocation) or `-t` (force pty allocation) flags.

#### Command executed using SUDO or INTERACTIVE_SUDO fails with the message `sudo: sorry, you must have a tty to run sudo`

The `sudo` command requires a `tty` to run. Set the **allocatePty** property or the **allocateDefaultPty** property to ask the SSH server allocate a pty.

#### Command executed using SUDO or INTERACTIVE_SUDO appears to hang

This may be caused by the `sudo` command waiting for the user to enter his password to confirm his identity. There are two ways to solve this:

1. Use the [`NOPASSWD`](http://www.gratisoft.us/sudo/sudoers.man.html#nopasswd_and_passwd) tag in your `/etc/sudoers` file.
2. Use the INTERACTIVE_SUDO**] connection type instead of the **SUDO** connection type.
3. If you are already using the **INTERACTIVE_SUDO** connection type and you still get this error, please verify that you have correctly configured the **sudoPasswordPromptRegex** property. If you have trouble determining the proper value for the **sudoPasswordPromptRegex** property, set the log level for the `com.xebialabs.overthere.ssh.SshInteractiveSudoPasswordHandlingStream` category to `TRACE` and examine the output.

<a name="cifs"></a>
## CIFS, WinRM and Telnet

The CIFS protocol implementation of XL Release uses the [CIFS protocol](http://en.wikipedia.org/wiki/Server_Message_Block), also known as SMB, for file manipulation and, depending on the settings, uses either [WinRM](http://en.wikipedia.org/wiki/WS-Management) or [Telnet](http://en.wikipedia.org/wiki/Telnet) for process execution. You will most likely not need to install new software although you might need to enable and configure some services:

* The built-in file sharing capabilities of Windows are based on CIFS and are therefore available and enabled by default.
* WinRM is available on Windows Server 2008 and up. XL Release supports basic authentication for local accounts and Kerberos authentication for domain accounts. _Overthere_ has a built-in WinRM library that can be used from all operating systems by setting the **connectionType** property to **WINRM_INTERNAL**. When connecting from a host that runs Windows, or when using a _winrs proxy_ that runs Windows, the native WinRM capabilities of Windows, i.e. the `winrs` command, can be used by setting the **connectionType** property to **WINRM_NATIVE**.
* A Telnet Server is available on all Windows Server versions although it might not be enabled.

### Password limitations

Due to a limitation of the `winrs` command, passwords containing a single quote (`'`) or a double quote (`"`) cannot be used when using the **WINRM_NATIVE** connection type.

### Domain accounts

Windows domain accounts are supported by the **WINRM_INTERNAL**, **WINRM_NATIVE** and **TELNET** connection types, but the syntax of the username is different:

* For the **WINRM_INTERNAL** connection type, domain accounts must be specified using the new-style domain syntax, e.g. `USER@FULL.DOMAIN`.
* For the **TELNET** connection type, domain accounts must be specified using the old-style domain syntax, e.g `DOMAIN\USER`.
* For the **WINRM_NATIVE** connection type, domain accounts may be specified using either the new-style (`USER@FULL.DOMAIN`) or old-style (`DOMAIN\USER`) domain syntax.
* For all three connection types, local accounts must be specified without an at-sign (`@`) or a backslash (`\`).

**Note:** When using domain accounts with the **WINRM_INTERNAL** connection type, the Kerberos subsystem of the Java Virtual Machine must be configured correctly. Please read the section on how to set up Kerberos [for the source host](#cifs_host_setup_krb5) and [the remote hosts](#cifs_host_setup_spn).

### Administrative shares

By default XL Release will access the [administrative shares](http://en.wikipedia.org/wiki/Administrative_share) on the remote host. These shares are only accessible for users that are part of the **Administrators** on the remote host. If you want to access the remote host using a regular account, use the **pathShareMapping** property to configure the shares to use for the paths XL Release will be connecting to. Of course, the user configured with the **username** property should have access to those shares and the underlying directories and files.

**Note:** XL Release will take care of the translation from Windows paths, e.g. `C:\Program Files\IBM\WebSphere\AppServer`, to SMB URLs that use the administrative shares, e.g. `smb://username:password@hostname/C$/Program%20Files/IBM/WebSphere/AppServer` (which corresponds to the UNC path `\\hostname\C$\Program Files\IBM\WebSphere\AppServer`), so that your code can use Windows style paths.

<a name="cifs_host_setup"></a>
### Host setup for CIFS, WinRM and Telnet

<a name="cifs_host_setup_cifs"></a>
#### CIFS
To connect to a remote host using the **CIFS** protocol, ensure the host is reachable on port 445.

If you will be connecting as an administrative user, ensure the administrative shares are configured. Otherwise, ensure that the user you will be using to connect has access to shares that correspond to the directory you want to access and that the **pathShareMappings** property is configured accordingly.

<a name="cifs_host_setup_telnet"></a>
#### Telnet

To use the **TELNET** connection type, you'll need to enable and configure the Telnet Server according to these instructions:

1. (Optional) If the Telnet Server is not already installed on the remote host, add it using the **Add Features Wizard** in the **Server Manager** console.

1. (Optional) If the remote host is running Windows Server 2003 SP1 or an x64-based version of Windows Server 2003, install the Telnet server according to [these instructions from the Microsoft Support site](http://support.microsoft.com/kb/899260). 

1. Enable the Telnet Server Service on the remote host according to <a href="http://technet.microsoft.com/en-us/library/cc732046(WS.10).aspx">these instructions on the Microsoft Technet site</a>. 

1. After you have started the Telnet Server, open a command prompt as the **Administrator** user on the remote host and enter the command `tlntadmn config mode=stream` to enable stream mode.

When the Telnet server is enabled any user that is in the **Administrators** group or that is in the **TelnetClients** group and that has the **Allow logon locally** privilege can log in using Telnet. See the Microsoft Technet to learn <a href="http://technet.microsoft.com/en-us/library/ee957044(WS.10).aspx">how to grant a user or group the right to logon locally</a> on Windows Server 2008 R2.

<a name="cifs_host_setup_winrm"></a>
<a name="cifs_host_setup_winrm_internal"></a>
<a name="cifs_host_setup_winrm_native"></a>
#### WinRM

To use the **WINRM_INTERNAL** or the **WINRM_NATIVE** connection type, you'll need to setup WinRM on the remote host by following these instructions:

1. If the remote host is running Windows Server 2003 SP1 or SP2, or Windows XP SP2, install the [WS-Management v.1.1 package](http://support.microsoft.com/default.aspx?scid=kb;EN-US;936059&wa=wsignin1.0).

1. If the remote host is running Windows Server 2003 R2, go to the **Add/Remove System Components** feature in the **Control Panel** and add WinRM under the section **Management and Monitoring Tools**. Afterwards install the [WS-Management v.1.1 package](http://support.microsoft.com/default.aspx?scid=kb;EN-US;936059&wa=wsignin1.0) to upgrade the WinRM installation.

1. If the remote host is running Windows Vista or Windows 7, the **Windows Remote Management (WS-Management)** service is not started by default. Start the service and change its Startup type to **Automatic (Delayed Start)** before proceeding with the next steps.

1. On the remote host, open a Command Prompt (not a PowerShell prompt!) using the **Run as Administrator** option and paste in the following lines when using the **WINRM_INTERNAL** connection type:

		winrm quickconfig
		y
		winrm set winrm/config/service/Auth @{Basic="true"}
		winrm set winrm/config/service @{AllowUnencrypted="true"}
		winrm set winrm/config/winrs @{MaxMemoryPerShellMB="1024"}

	Or the following lines when using the **WINRM_NATIVE** connection type:

		winrm quickconfig
		y
		winrm set winrm/config/service/Auth @{Basic="true"}
		winrm set winrm/config/winrs @{MaxMemoryPerShellMB="1024"}

	Or keep reading for more detailed instructions.

1. Run the quick config of WinRM to start the Windows Remote Management service, configure an HTTP listener and create exceptions in the Windows Firewall for the Windows Remote Management service:

		winrm quickconfig

	**Note:** The Windows Firewall needs to be running to run this command. See [Microsoft Knowledge Base article #2004640](http://support.microsoft.com/kb/2004640).

1. (Optional) By default basic authentication is disabled in WinRM. Enable it if you are going to use local accounts to access the remote host:

		winrm set winrm/config/service/Auth @{Basic="true"}

1. (Optional) By default Kerberos authentication is enabled in WinRM. Disable it if you are **not** going to use domain accounts to access the remote host:

		winrm set winrm/config/service/Auth @{Kerberos="false"}

	**Note:** Do not disable Negotiate authentication as the `winrm` command itself uses that to configure the WinRM subsystem!
	
1. (Only required for **WINRM_INTERNAL** or when the property **winrsUnencrypted** is set to `true`) Configure WinRM to allow unencrypted SOAP messages:

		winrm set winrm/config/service @{AllowUnencrypted="true"}

1. Configure WinRM to provide enough memory to the commands that you are going to run, e.g. 1024 MB:

		winrm set winrm/config/winrs @{MaxMemoryPerShellMB="1024"}

	**Note:** This is not supported by WinRM 3.0, included with the Windows Management Framework 3.0. This update [has been temporarily removed from Windows Update](http://blogs.msdn.com/b/powershell/archive/2012/12/20/windows-management-framework-3-0-compatibility-update.aspx) because of numerous incompatibility issues with other Microsoft products. However, if you have already installed WMF 3.0 and cannot downgrade, [Microsoft Knowledge Base article #2842230](http://support.microsoft.com/kb/2842230) describes a hotfix that can be installed to re-enable the `MaxMemoryPerShellMB` setting.

1. To use the **WINRM_INTERNAL** or **WINRM_NATIVE** connection type with HTTPS, i.e. **winrmEnableHttps** set to `true`, follow the steps below:

	(Optional) Create a self signed certificate for the remote host by installing `selfssl.exe` from [the IIS 6 resource kit](http://www.microsoft.com/download/en/details.aspx?displaylang=en&id=17275) and running the command below or by following the instructions [in this blog by Hans Olav](http://www.hansolav.net/blog/SelfsignedSSLCertificatesOnIIS7AndCommonNames.aspx):

        	C:\Program Files\IIS Resources\SelfSSL>selfssl.exe /T /N:cn=HOSTNAME /V:3650
        	Microsoft (R) SelfSSL Version 1.0
        	Copyright (C) 2003 Microsoft Corporation. All rights reserved.

        	Do you want to replace the SSL settings for site 1 (Y/N)?Y
        	The self signed certificate was successfully assigned to site 1.

	Open a PowerShell window and enter the command below to find the thumbprint for the certificate for the remote host:

			PS C:\Windows\system32> Get-childItem cert:\LocalMachine\Root\ | Select-String -pattern HOSTNAME

			[Subject]
			  CN=HOSTNAME

			[Issuer]
			  CN=HOSTNAME

			[Serial Number]
			  527E7AF9142D96AD49A10469A264E766

			[Not Before]
			  5/23/2011 10:23:33 AM

			[Not After]
			  5/20/2021 10:23:33 AM

			[Thumbprint]
			  5C36B638BC31F505EF7F693D9A60C01551DD486F

	Create an HTTPS WinRM listener for the remote host with the thumbprint you've just found:

			winrm create winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname="HOSTNAME"; CertificateThumbprint="THUMBPRINT"}


For more information on WinRM, please refer to <a href="http://msdn.microsoft.com/en-us/library/windows/desktop/aa384426(v=vs.85).aspx">the online documentation at Microsoft's DevCenter</a>. As a quick reference, have a look at the list of useful commands below:

* Do a quickconfig for WinRM with HTTPS: `winrm quickconfig -transport:https`
* View the complete WinRM configuration: `winrm get winrm/config`
* View the listeners that have been configured: `winrm enumerate winrm/config/listener`
* Create an HTTP listener: `winrm create winrm/config/listener?Address=*+Transport=HTTP` (also done by `winrm quickconfig`)
* Allow all hosts to connect to the WinRM listener: `winrm set winrm/config/client @{TrustedHosts="*"}`
* Allow a fixed set of hosts to connect to the WinRM listener: `winrm set winrm/config/client @{TrustedHosts="host1,host2..."}`

<a name="cifs_host_setup_krb5"></a>
#### Kerberos - XL Release host

**Note:** You will only need to configure Kerberos if you are going to use Windows domain accounts to access the remote host with the **WINRM_INTERNAL** connection type.

In addition to the setup described in [the WINRM section](#cifs_host_setup_winrm), using Kerberos authentication requires that you follow the [Kerberos Requirements for Java](http://docs.oracle.com/javase/6/docs/technotes/guides/security/jgss/tutorials/KerberosReq.html) on the host that runs the XL Release server.

Create a file called `krb5.conf` (Unix) or `krb5.ini` (Windows) with at least the following content: 

    [realms]
    EXAMPLE.COM = {
        kdc = KDC.EXAMPLE.COM
    }

Replace the values with the name of your domain/realm and the hostname of your domain controller (multiple entries can be added to allow the XL Release server host to connect to multiple domains) and place the file in the default location for your operating system:

* Linux: `/etc/krb5.conf`
* Solaris: `/etc/krb5/krb5.conf`
* Windows: `C:\Windows\krb5.ini`

Alternatively, place the file somewhere else and edit the `server.sh` or `server.cmd` startup script and add the following Java system property to the command line: `-Djava.security.krb5.conf=/path/to/krb5.conf`. Replace the path with the location of the file you just created. 

See [the Kerberos V5 System Administrator's Guide at MIT](http://web.mit.edu/kerberos/krb5-1.10/krb5-1.10.6/doc/krb5-admin.html#krb5_002econf) for more information on the `krb5.conf` format.

<a name="cifs_host_setup_spn"></a>
#### Kerberos - remote host

**Note:** You will only need to configure Kerberos if you are going to use Windows domain accounts to access the remote host with the **WINRM_INTERNAL** connection type.

By default, XL Release will request access to a Kerberos <a href="http://msdn.microsoft.com/en-us/library/windows/desktop/ms677949(v=vs.85).aspx">service principal name</a> of the form <code>WSMAN/<em>HOST</em></code>, for which an SPN should be configured automatically when you [configure WinRM for a remote host](#cifs_host_setup_winrm).

If that was not configured correctly, e.g. if you have overridden the default SPN for which a ticket is requested through the **winrmKerberosAddPortToSpn** or the **winrmKerberosUseHttpSpn** properties, you will have configure the service principal names manually.

This can be achieved by invoking the <a href="http://technet.microsoft.com/en-us/library/cc731241(v=ws.10).aspx">setspn</a> command, as an Administrator, on any host in the domain, as follows:

    setspn -A <em>PROTOCOL</em>/<em>ADDRESS</em>:<em>PORT</em> <em>WINDOWS-HOST</em>

where:

* `PROTOCOL` is either `WSMAN` (default) or `HTTP` (if **winrmKerberosUseHttpSpn** has been set to `true`).
* `ADDRESS` is the **address** used to connect to the remote host,
* `PORT` (optional) is the **port** used to connect to the remote host (usually 5985 or 5986, only necessary if **winrmKerberosAddPortToSpn** has been set to `true`), and
* `WINDOWS-HOST` is the short Windows hostname of the remote host.

Some other useful commands:

* List all service principal names configured for the domain: `setspn -Q */*` 
* List all service principal names configured for a specific host in the domain: `setspn -L _WINDOWS-HOST_`
 
<a name="cifs_troubleshooting"></a>
### Troubleshooting CIFS, WinrRM and Telnet

This section lists a number of common configuration errors that can occur when using XL Release with CIFS, WinRM and/or Telnet.

For more troubleshooting tips for Kerberos, please refer to the [Kerberos troubleshooting guide in the Java SE documentation](http://docs.oracle.com/javase/6/docs/technotes/guides/security/jgss/tutorials/Troubleshooting.html).

#### CIFS connections are very slow to set up.

The [JCIFS library](http://jcifs.samba.org), which XL Release uses to connect to CIFS shares, will try and query the Windows domain controller to resolve the hostname in SMB URLs. JCIFS will send packets over port 139 (one of the [NetBIOS over TCP/IP] ports) to query the <a href="http://en.wikipedia.org/wiki/Distributed_File_System_(Microsoft)">DFS</a>. If that port is blocked by a firewall, JCIFS will only fall back to using regular hostname resolution after a timeout has occurred.

Set the following Java system property to prevent JCIFS from sending DFS query packets:
`-Djcifs.smb.client.dfs.disabled=true`.

See [this article on the JCIFS mailing list](http://lists.samba.org/archive/jcifs/2009-December/009029.html) for a more detailed explanation.

#### CIFS connections time out

If the problem cannot be solved by changing the network topology, try increasing the JCIFS timeout values documented in the [JCIFS documentation](http://jcifs.samba.org/src/docs/api/overview-summary.html#scp). Another system property not mentioned there but only on the [JCIFS homepage](http://jcifs.samba.org/) is `jcifs.smb.client.connTimeout`.

To get more debug information from JCIFS, set the system property `jcifs.util.loglevel` to 3.

#### Kerberos authentication fails with the message `Unable to load realm info from SCDynamicStore`

The Kerberos subsystem of Java cannot start up. Did you configure it as described in [the section on Kerberos setup for the source host](#cifs_host_setup_krb5)?

#### Kerberos authentication fails with the message `Cannot get kdc for realm ...`

The Kerberos subsystem of Java cannot find the information for the realm in the `krb5.conf` file. The realm name specified in [the Kerberos configuration on the source host](#cifs_host_setup_krb5) is case sensitive and must be entered in upper case in the `krb5.conf` file.

Alternatively, you can use the `dns_lookup_kdc` and `dns_lookup_realm` options in the `libdefaults` section to automatically find the right realm and KDC from the DNS server if it has been configured to include the necessary `SRV` and `TXT` records:

    [libdefaults]
        dns_lookup_kdc = true
        dns_lookup_realm = true

#### Kerberos authentication fails with the message `Server not found in Kerberos database (7)`

The service principal name for the remote host has not been added to Active Directory. Did you add the SPN as described in [the section on Kerberos setup for remote hosts](#cifs_host_setup_spn)?

#### Kerberos authentication fails with the message `Pre-authentication information was invalid (24)` or `Identifier doesn't match expected value (906)`

The username or the password supplied was invalid. Did you supply the correct credentials?

#### Kerberos authentication fails with the message `Integrity check on decrypted field failed (31)`

Is the target host part of a Windows 2000 domain? In that case, you'll have to add `rc4-hmac` to the supported encryption types:

    [libdefaults]
        default_tgs_enctypes = aes256-cts-hmac-sha1-96 des3-cbc-sha1 arcfour-hmac-md5 des-cbc-crc des-cbc-md5 des-cbc-md4 rc4-hmac
        default_tkt_enctypes = aes256-cts-hmac-sha1-96 des3-cbc-sha1 arcfour-hmac-md5 des-cbc-crc des-cbc-md5 des-cbc-md4 rc4-hmac

#### Kerberos authentication fails with the message `Message stream modified (41)`

The realm name specified in [the Kerberos configuration on the source host](#cifs_host_setup_krb5) does not match the case of the Windows domain name. The realm name is case sensitive and must be entered in upper case in the `krb5.conf` file.

#### I am not using Kerberos authentication and I still see messages saying `Unable to load realm info from SCDynamicStore`

The Kerberos subsystem of Java cannot start up and the remote WinRM server is sending a Kerberos authentication challenge. If you are using local accounts, the authentication will proceed successfully despite this message. To remove these messages either configure Kerberos as described in [the section on Kerberos setup for the source host](#cifs_host_setup_krb5) or disallow Kerberos on the WinRM server as described in step 4 of [the section on WinRM setup](#cifs_host_setup_winrm).

#### Telnet connection fails with the message `VT100/ANSI escape sequence found in output stream. Please configure the Windows Telnet server to use stream mode (tlntadmn config mode=stream).`

The Telnet service has been configured to be in "Console" mode. Did you configure it as described in [the section on Telnet setup](#cifs_host_setup_telnet)?

#### The `winrm` configuration command fails with the message `There are no more endpoints available from the endpoint mapper`

The Windows Firewall has not been started. See [Microsoft Knowledge Base article #2004640](http://support.microsoft.com/kb/2004640) for more information.

#### The `winrm` configuration command fails with the message `The WinRM client cannot process the request`

This can occur if you have disabled the `Negotiate` authentication method in the WinRM configuration. To fix this situation, edit the configuration in the Windows registry under the key `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\` and restart the Windows Remote Management service.

_Courtesy of [this blog post by Chris Knight](http://blog.chrisara.com.au/2012/06/recovering-from-winrm-authentication.html)._

#### WinRM command fails with the message `java.net.ConnectException: Connection refused`

The Windows Remote Management service is not running or is not running on the port that has been configured. Start the service or configure XL Release to use a different **port**.

#### WinRM command fails with a 401 response code

Multiple causes can lead to this error message:

1. The Kerberos ticket is not accepted by the remote host:

    * Did you set up the correct service principal names (SPNs) as described in [the section on Kerberos setup for remote hosts](#cifs_host_setup_spn)? The hostname is case insensitive, but it has to be the same as the one used in the **address** property, i.e. a simple hostname or a fully qualified domain name. Domain policies may prevent the Windows Management Service from creating the required SPNs. See [this blog by LazyJeff](http://fix.lazyjeff.com/2011/02/how-to-fix-winrm-service-failed-to.html) for more information.

    * Has the reverse DNS of the remote host been set up correctly? See [Principal names and DNS](http://web.mit.edu/Kerberos/krb5-devel/doc/admin/princ_dns.html) for more information. Please note that the `rdns` option is not available in Java's Kerberos implementation.

1. The WinRM service is not set up to accept unencrypted traffic. Did you execute step #8 of the [host setup for WinRM](#cifs_host_setup_winrm)?

1. The user is not allowed to log in. Did you uncheck the "User must change password at next logon" checkbox when you created the user in Windows?

1. The user is not allowed to perform a WinRM command. Did you grant the user (local) administrative privileges?

1. Multiple domains are in use and they are not mapped in the `[domain_realm]` section of the Kerberos `krb5.conf` file. For example:

        [realms] 
        EXAMPLE.COM = { 
        kdc = HILVERSUM.EXAMPLE.COM 
        kdc = AMSTERDAM.EXAMPLE.COM 
        kdc = ROTTERDAM.EXAMPLE.COM 
        default_domain = EXAMPLE.COM 
        }

        EXAMPLEDMZ.COM = { 
        kdc = localhost:2088 
        default_domain = EXAMPLEDMZ.COM 
        }

        [domain_realm] 
        example.com = example.COM 
        .example.com = example.COM 
        exampledmz.com = EXAMPLEDMZ.COM 
        .exampledmz.com = EXAMPLEDMZ.COM

        [libdefaults] 
        default_realm = EXAMPLE.COM 
        rdns = false 
        udp_preference_limit = 1

Refer to the [Kerberos documentation](http://web.mit.edu/kerberos/krb5-current/doc/admin/conf_files/krb5_conf.html) for more information about `krb5.conf`.

#### WinRM command fails with a 500 response code

Multiple causes can lead to this error message:

1. If the command was executing for a long time, this might have been caused by a timeout. You can increase the WinRM timeout specified by the **winrmTimeout** property to increase the request timeout. Don't forget to increase the `MaxTimeoutms` setting on the remote host as well. For example, to set the maximum timeout on the server to five minutes, enter the following command:

        winrm set winrm/config @{MaxTimeoutms="300000"}

1. If a lot of commands are being executed concurrently, increase the `MaxConcurrentOperationsPerUser` setting on the server. For example, to set the maximum number of concurrent operations per user to 100, enter the following command:

        winrm set winrm/config/service @{MaxConcurrentOperationsPerUser="100"}

Other configuration options that may be of use are `Service/MaxConcurrentOperations` and `MaxProviderRequests` (WinRM 1.0 only).

#### WinRM command fails with an unknown error code

If you see an unknown WinRM error code in the logging, you can use the `winrm helpmsg` command to get more information, e.g.

    winrm helpmsg 0x80338104
    The WS-Management service cannot process the request. The WMI service returned an 'access denied' error.

_Courtesy of [this PowerShell Magazine blog post by Shay Levy](http://www.powershellmagazine.com/2013/03/06/pstip-decoding-winrm-error-messages/)._

#### WinRS command fails with `out of memory` error

After customizing the value of `MaxMemoryPerShellMB`, you may receive an "Out of memory" error when executing a WinRS command. This is caused by an error in WinRM. A hot fix is available from [Microsoft](http://support.microsoft.com/kb/2842230).


### Exposing additional Overthere properties in XL Release

Most of the Overthere connection properties defined in the [Overthere documentation](https://github.com/xebialabs/overthere/blob/master/README.md) are available as regular properties or as hidden properties on the **overthere.SshHost** and **overthere.CifsHost** types. If you need access to any additional properties, you can create a `type-modification` in the `ext/synthetic.xml` file like this:

	<type-modification type="overthere.SshHost">
		<property name="listFilesCommand" hidden="true" default="/bin/ls -a1 {0}" />
		<property name="getFileInfoCommand" hidden="true" default="/bin/ls -ld {0}" />
	</type-modification>

