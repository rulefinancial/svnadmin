# Subversion Admin Tool

## Introduction

## Installation
* Install Apache
* Use `conf/svn_admin_httpd.conf.dist` as a template to create `svn_admin_httpd.conf` and include it from your main Apache config file.
* Use `scripts/config.pl.dist` as a template to create `scripts/config.pl`.
* Make sure you have Perl installed.  This has been tested to work with perl 5.10 on Ubuntu 8.10 and on Strawberry Perl 5.16.3 on Windows 7 and on Windows Server 2008 R2.
* Make sure you have the required Perl modules installed.  The following commands will install the required modules:
    `cpan install CGI`

    `cpan install Net::LDAP`

    `cpan install HTML::Template`

