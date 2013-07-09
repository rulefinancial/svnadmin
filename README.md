SVN-Admin
========
A Web Interface for Administering Subversion Repositories
---------------
The problem after setting up a subversion server with Apache and the mod\_dav\_svn module is to give users the right to change their passwords, administer their repositories, get backups, etc. without having a shell account on the subversion server.

This script should close this gap by providing the most common functionality.

Screenshot
-------------
<iframe src="shots/dau.html" height="200" width="90%">
  <a href="shots/admin.html">screenshot</a>
</iframe>
<center>Change Password Interface</center>

<iframe src="shots/dau.html" height="200" width="90%">
  <a href="shots/admin.html">screenshot</a>
</iframe>
<center>Administrator Interface</center>

<iframe src="shots/dau.html" height="200" width="90%">
  <a href="shots/admin.html">screenshot</a>
</iframe>
<center>Administrate Repository</center>

Quick install instruction
--------------------------
Install apache and mod\_dav\_svn as usual. Then create a new directory that contains subversion repositories (e.g. /srv/www/subversion). Put the admin.cgi script into another directory (e.g. /srv/www/svnadmin). You should open it with some editor and adapt the paths at the beginning of the script. Then add the following config to your httpd.conf:

    <IfModule mod_dav_svn.c>
      <Location /svn>
        DAV svn
        SVNParentPath /srv/www/subversion
    
        # The access control policy
        # Allow anonymous access, unless explicitly forbidden 
        Satisfy Any
        Require valid-user
        AuthzSVNAccessFile /srv/www/subversion/.htsvnaccess
    
        AuthType Basic
        AuthName "Subversion repository"
        AuthUserFile /srv/www/subversion/.htpasswd
      </Location>
    </IfModule>
    
    ScriptAlias /svnadmin /srv/www/svnadmin/admin.cgi
    <Location /svnadmin>
        AllowOverride None
        Options +ExecCGI
        Order allow,deny
        Allow from all
    
        Satisfy All
        Require valid-user
    
        AuthType Basic
        AuthName "Subversion repository"
        AuthUserFile /srv/www/subversion/.htpasswd
    </Location>

Now create the empty files /srv/www/subversion/.htpasswd and /srv/www/subversion/.htuserinfo and add an initial user with

    htpasswd -m .htpasswd hoenicke
    echo 'hoenicke:Jochen Hoenicke:hoenicke@...' > .htuserinfo

If you update from a previous version of admin.cgi, you need to create the file .htuserinfo manually.

Create /srv/www/subversion/.htsvnaccess with the following content:

    [groups]
    admin = hoenicke

Now you're ready to go. Put your browser to the URL http://your.svn.server/svnadmin/, enter the credentials for an administrator login, and create repositories. You can add new users at the configuration page of the repository.

Copyright (c) 2007-2008 Jochen Hoenicke, Michael Möller

>This program is free software; you can redistribute it and/or modify it under the >terms of the GNU General Public License as published by the Free Software >Foundation; either version 2, or (at your option) any later version.
>
>This program is distributed in the hope that it will be useful, but WITHOUT ANY >WARRANTY; without even the implied warranty of MERCHANTABILITY or >FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
