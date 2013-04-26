# Subversion Admin Tool

## Introduction

## Installation
* Install Apache
* Use <code>conf/svn_admin_httpd.conf.dist</code> as a template to create <code>svn_admin_httpd.conf</code> and include it from your main Apache config file.
* Use <code>scripts/config.pl.dist</code> as a template to create <code>scripts/config.pl</code>.
* Make sure you have Perl installed.  This has been tested to work with perl 5.10 on Ubuntu 8.10 and on Strawberry Perl 5.16.3 on Windows 7 and on Windows Server 2008 R2.
* Make sure you have the required Perl modules installed.  The following commands will install the required modules:
  <code>cpan install CGI</code>
  <code>cpan install Net::LDAP</code>
  <code>cpan install HTML::Template</code>

