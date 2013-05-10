#!C:/strawberry_perl/perl/bin/perl.exe
## CGI to allow people to change SVN repositories
## $Id$

use strict;
use warnings;
use CGI qw/:standard/;
use Net::LDAP;
use Net::LDAP::Control::Paged;
use Net::LDAP::Constant qw( LDAP_CONTROL_PAGED ); 
use File::Basename;
use HTML::Template;
use Carp;
use lib dirname $0;
$| = 1;

my $config = require "config.pl";
my $template_dir = dirname($0) . '/../templates/';

sub populate_template($$) {
  my ($template_name, $params) = @_;
  my $template = HTML::Template->new(filename => ${template_dir} . ${template_name});
  $template->param($params);
  return $template->output;
}

sub websvnpath($$) {
  my ($repos, $path) = @_;
  if ($config->{websvn}) {
    my $url = $config->{viewcvspath}."/listing.php?repname=$repos";
    $url .= "\&path=$path/" if $path ne "/";
    return $url;
  } else {
    return $config->{viewcvspath}."/".$repos.$path;
  }
}

# Given a list, return a new list with only unique entries.
sub unique {
  my %seen = ();
  my @uniq = ();
  foreach my $item (@_) {
    push(@uniq, $item) unless $seen{$item}++;
  }
  return @uniq;
}

# Take a ref to the existing groups hash and a list of values.
# Return an expanded list of values, recursively replacing
# any @... group references.
sub expand_group {
  my ($groupsRef, @values) = @_;
  my @expanded_values = ();
  my $done = 0;
  while (not $done) {
    $done = 1;
    foreach my $value (@values) {
      if ($value =~ /^\@(.*)$/) {
        $done = 0;
        push @expanded_values, @{$groupsRef->{$1}};
      } else {
        push @expanded_values, ($value);
      }
    }
    @values = unique @expanded_values;
  }
  return @values;
}

sub read_svn_access($) {
  my ($filename) = @_;
  my %repositories;
  my %globals;
  my $repos;
  my $path;
  if (!open(SVNACCESS, "<$filename")) {
    print header(-status=>'500 Internal Server Error'),
    populate_template('error.html', {
        ERROR_TITLE => 'Internal Error',
        ERROR_DETAILS => "Cannot find configuration file [$filename]",
      });
    exit 255;
  }
  while (<SVNACCESS>) {
    s/\#.*$//;
    next unless /\S/;
    chomp;
    s/\s+/ /g;

    if (/^\[([^\]]+)\]$/) {
      $path = $1;
      if ($path =~ /([^:]*):(.*)/) {
        $repos = $1;
        $path = $2;
        $repositories{$repos} = {} if (! defined $repositories{$repos});
        $repositories{$repos}{$path} = {};
      } else {
        $repos = "";
        $globals{$path} = {};
      }
      next;
    }

    if ($_ =~ /(.*?)\s*=\s*(.*)/) {
      my $key = $1;
      my @value = split(/\s*,\s*/, $2);

      if ($repos) {
        $repositories{$repos}{$path}{$key} = \@value;
    } else {
      $globals{$path}{$key} = \@value;
  }
}
  }
  close(SVNACCESS);

  return (\%repositories, \%globals);
}

#
# Redirect svnadmin to svnadmin/
# This is necessary to make repository links work.
#

if (path_info() eq "") {
  print redirect(url()."/");
  exit;
}

# Now check authorization.  The apache server already checks the
# password, we just have to check the user name.

my $curuser = $ENV{'REMOTE_USER'};
unless (defined $curuser) {
  print header(-status=>'401 Authorization Required',
    -www_authenticate=>'Basic realm: "Subversion repository"'),
  populate_template('error.html', {
      ERROR_TITLE => 'Authorisation required',
      ERROR_DETAILS => "This server could not verify that you are authorized to access this URL. You either supplied the wrong password, or your browser doesn't understand how to supply the credentials required.",
    });
  exit 0;
}

#
# Read in current config.
#

my $action = param('action') || '';
my ($repositories, $globals) = read_svn_access($config->{svnaccess_conf});
my %users;

if ($config->{htpasswd_users}) {
  # Get users from .htpasswd file
  if (!open(HTPASSWD, "<$config->{htpasswd_file}")) {
    print header(-status=>'500 Internal Server Error'),
    populate_template('error.html', {
        ERROR_TITLE => 'Internal Error',
        ERROR_DETAILS => "Cannot find configuration file [$config->{htpasswd_file}].",
      });
    exit 255;
  }
  while (<HTPASSWD>) {
    s/\#.*$//;
    next unless /\S/;
    chomp;
    s/\s+/ /g;

    my $htpasswd_user;
    ($htpasswd_user, @_) = split ':', $_;
    if (defined $users{$htpasswd_user}) {
      warn "HTPASSWD entry overwriting existing user: $htpasswd_user";
    }
    $users{$htpasswd_user} = {
      'username' => $htpasswd_user,
      'source' => 'HTPASSWD',
      'displayName' => $htpasswd_user,
    }
  }
  close(HTPASSWD);
}

if ($config->{ldap_users}) {
  # Get users from LDAP / Active Directory
  my $ldap = Net::LDAP->new($config->{ldap_server},
    inet4 => 1,
    onerror => sub {
      my ($message) = @_;
      print header(-status=>'500 Internal Server Error'),
      populate_template('error.html', {
          ERROR_TITLE => 'Internal Error',
          ERROR_DETAILS => 'LDAP server error: ' . $message->error,
        });
      confess "LDAP error code: " . $message->code . ", error: " . $message->error;
    });
  my $page = Net::LDAP::Control::Paged->new( size => 100 );
  if (not defined $ldap) {
    print header(-status=>'500 Internal Server Error'),
    populate_template('error.html', {
        ERROR_TITLE => 'Internal Error',
        ERROR_DETAILS => "Cannot connect to LDAP server '$config->{ldap_server}'.",
      });
    die "$@";
  }
  my $ldap_mesg;
  $ldap_mesg = $ldap->bind($config->{ldap_bind_dn}, password => $config->{ldap_bind_password});
  my @args = (      base    => $config->{ldap_base_dn},
    filter  => $config->{ldap_filter},
    control => [ $page ], ); 
  my $cookie;
  while(1) {
    $ldap_mesg = $ldap->search(@args);
    my $ldap_entry;
    foreach $ldap_entry ($ldap_mesg->entries) {
      my $ldap_username = $ldap_entry->get_value('sAMAccountName');
      my $ldap_cn = $ldap_entry->get_value('cn');
      if ($ldap_username) {
        if (defined $users{$ldap_username}) {
          warn "LDAP entry overwriting existing user: $ldap_username";
        }
        $users{$ldap_username} = {
          'username' => $ldap_username,
          'source' => 'LDAP',
          'displayName' => $ldap_cn,
        }
      }
    }
    my ($resp) = $ldap_mesg->control( LDAP_CONTROL_PAGED ) or last;
    $cookie = $resp->cookie or last;
    $page->cookie($cookie);
  }
  if ($cookie)    {
    $page->cookie($cookie);
    $page->size(0);
    $ldap->search(@args);
  }
  $ldap_mesg = $ldap->unbind;
}


sub write_repos() {
  my $repos;
  my $path;
  my $key;
  my $filename = $config->{svnaccess_conf};
  if (!open(SVNACCESS, ">$filename.new")) {
    print "Can't change access rights\n";
    return;
  }
  print SVNACCESS "#\n# Automatically generated by svnadmin.cgi\n#\n\n";

  foreach $path (sort keys %$globals) {
    print SVNACCESS "[$path]\n";
    foreach $key (sort keys %{$globals->{$path}}) {
      print SVNACCESS "$key = ".
      join(",", @{$globals->{$path}{$key}})."\n";
    }
    print SVNACCESS "\n";
  }
  foreach $repos (sort keys %$repositories) {
    foreach $path (sort keys %{$repositories->{$repos}}) {
      print SVNACCESS "[$repos:$path]\n";
      foreach $key (sort keys %{$repositories->{$repos}{$path}}) {
        print SVNACCESS "$key = ".
        join(",", @{$repositories->{$repos}{$path}{$key}})."\n";
      }
      print SVNACCESS "\n";
    }
  }
  close(SVNACCESS);
  if (!rename("$filename.new", "$filename")) {
    print "Can't change access rights\n";
    return;
  }
  chmod $config->{svnaccess_conf_perm}, "$filename";
}

sub in_group($) {
  my ($group, @dummy) = @_;
  my @expanded = expand_group \%{$globals->{'groups'}}, @{$globals->{'groups'}{$group}};
return grep(/^$curuser$/, @expanded) == 1;
}

#
# Backup Part
# -----------
#
# Allow to get last revision number and GPG encrypted dump of repository
#

my %gpgfpr;
sub read_gpg_keys() {
  if (!open(GPGFPR, "-|", $config->{gpg}, "--homedir", "$config->{gpghome}", "--fingerprint")) {
    return 0;
  }
  while (<GPGFPR>) {
    if ($_ =~ /Key fingerprint = ([0-9A-F ]+)/) {
      my $fingerprint = $1;
      $fingerprint =~ s/\s+//g;
      my $id = lc(substr($fingerprint, -16));
      my $uid = <GPGFPR>;
      if ($uid =~ /^uid\s+(.*)$/) {
        $gpgfpr{$id} = $1;
      }
    }
  }
  close(GPGFPR);
  return 1;
}

sub get_gpg_keyid($) {
  my $repos = $_[0];
  my @keys = ();

  if (!open(GPGKEYS, "<$config->{gpgkeys}")) {
    print header(-status=>'500 Internal Server Error'),
    populate_template('error.html', {
        ERROR_TITLE => 'Internal Error',
        ERROR_DETAILS => "Cannot find configuration file '$config->{gpgkeys}'.",
      });
    exit 255;
  }
  while (<GPGKEYS>) {
    if ($_ =~ m/^$repos:([0-9a-fA-F]+(,[0-9a-fA-F]+)*)$/) {
      @keys = split ',', $1;
      last;
    }
  }
  close GPGKEYS;
  return @keys;
}

sub write_gpg_keyid($@) {
  my ($repos, @keys) = @_;

  if (!open(GPGKEYS, "<$config->{gpgkeys}")) {
    print header(-status=>'500 Internal Server Error'),
    populate_template('error.html', {
        ERROR_TITLE => 'Internal Error',
        ERROR_DETAILS => "Cannot find configuration file '$config->{gpgkeys}'.",
      });
    exit 255;
  }
  if (!open(NEWGPGKEYS, ">$config->{gpgkeys}.new")) {
    print p("Can't change gpg keys\n");
    return;
  }
  my $found = 0;
  while (<GPGKEYS>) {
    if ($_ =~ m/^$repos:([0-9a-fA-F]+(,[0-9a-fA-F]+)*)$/) {
      print NEWGPGKEYS "$repos:".join(',', @keys)."\n";
      $found = 1;
    } else {
      print NEWGPGKEYS $_;
    }
  }
  print NEWGPGKEYS "$repos:".join(',', @keys)."\n" unless $found;
  close GPGKEYS;
  close NEWGPGKEYS;
  if (!rename("$config->{gpgkeys}.new", "$config->{gpgkeys}")) {
    print p("Can't change gpg keys\n");
    return;
  }
  chmod $config->{svnaccess_conf_perm}, "$config->{gpgkeys}";
}

sub make_backup($$$$) {
  my ($repos, $revision, $full, $ext) = @_;
  if (!in_group("$repos-admins")
    && ($ext ne ".gpg" || !in_group("$repos-backup"))) {
    print header(-status=>'403 Forbidden');
    populate_template('error.html', {
        ERROR_TITLE => 'Forbidden',
        ERROR_DETAILS => "Sorry, user [$curuser] is not allowed to dump repository [$repos].",
      });
    exit 0;
  }

  my @gpgkeyids = ();
  if ($ext eq ".gpg") {
    @gpgkeyids = get_gpg_keyid($repos);
    if (!@gpgkeyids) {
      print header(-status=>'404 Not Found');
      populate_template('error.html', {
          ERROR_TITLE => 'GPG keys missing',
          ERROR_DETAILS => "Dumping Repository not supported.  You need to setup the GPG keys first.",
        });
      exit 0;
    }
  }

  my @command = ($config->{svnadmin}, "dump", "-q");
  if ($revision) {
    push @command, "-r";
    push @command, "$revision";
    push @command, "--incremental" unless ($full eq "f");
  }
  push @command, "$config->{svnroot}/$repos";
  print header(-type=>'application/octetstream');
  if ($ext ne ".dump") {
    my $pid = open (SVNDUMP, "-|");
    if ($pid) {
      # parent

      if ($ext eq ".gpg") {
        my @param = ();
        my $keyid;
        foreach $keyid (@gpgkeyids) {
          push @param, "-r", $keyid;
        }
        open (FILTER, "|-", $config->{gpg}, "--homedir", "$config->{gpghome}", "-e", 
          @param);
      } else {
        open (FILTER, "|$config->{gzip} -c");
      }
      my $bytesread;
      my $buffer;
      while ($bytesread=read(SVNDUMP,$buffer,1024)) {
        print FILTER $buffer;
      }
      close(FILTER);
      exit 0;
    } else {
      exec (@command);
      exit 255;
    }
  } else {
    exec (@command);
    exit 255;
  }
}

if ($config->{enable_backup} and path_info() =~ /^\/([a-zA-Z0-9\-][a-zA-Z0-9\.\-]*)\.rev$/) {
  my $repos = $1;
  if (in_group("$repos-backup") || in_group("$repos-admins")) {
    print header(-type=>'text/plain');
    # errors goto stderr, so shunt it to stdout before running svnlook
    open STDERR, ">&STDOUT";
    exec ($config->{svnlook}, "youngest", "$config->{svnroot}/$repos");
    exit 255;
  } else {
    print header(-status=>'403 Forbidden');
    populate_template('error.html', {
        ERROR_TITLE => 'Forbidden',
        ERROR_DETAILS => "Sorry, user [$curuser] is not allowed to backup repository [$repos].",
      });
    exit 0;
  }
}

#
# Repository dumps.
# This has to come first as no HTML must be printed before.
#
# DEPRECATED URL
if ($config->{enable_backup} and path_info() =~ /^\/(([0-9]*(:[0-9]+)?)(f?)\/)?([a-zA-Z0-9\-][a-zA-Z0-9\.\-]*)\.dump(\.gz|)$/) {
  my $repos = $5;
  my $revision = $1 ? $2 : "";
  my $full = $1 ? $4 : "f";
  my $compressed = $6;
  make_backup($repos, $revision, $full, $6 ? $6 : ".dump");
}

# The preferred URL for getting a dump
#  repos(-\d+:\d+f?)?.(gz|gpg|dump)
if ($config->{enable_backup} and path_info() =~ /^\/([a-zA-Z0-9\-][a-zA-Z0-9\.\-]*)(-([0-9]*(:[0-9]+)?)(f?))?(\.gpg|\.gz|\.dump)$/) {

  make_backup($1, $2 ? $3 : "", $2 ? $5 : "f", $6);
}

#
# For all other requests print HTML headers.
#
print header, start_html(-title => 'Subversion  eXtended Administration');

#
# Change passphrase
#
if ($action eq "changepw") {
  my $pw = param('passphrase') || '';
  my $vpw = param('verify') || '';

  print h3("Changing Passphrase");
  if (length($pw) < 6) {
    print p("Sorry, the passphrase needs to be at least 6 characters long");
  } elsif (length($pw) > 80) {
    print p("Sorry, the passphrase can only be 80 characters maximum");
  } elsif ($pw ne $vpw) {
    print p("The passphrase and the verification don't match, please try again.");
  } else {
    # ok, things are good, do the htpasswd call
    print "<pre>\n";

    # errors from htpasswd goto stderr, so shunt it to stdout before running htpasswd
    open STDERR, ">&STDOUT";

    # the braces get around a perl warning
    { system ($config->{htpasswd}, '-b', '-m', $config->{htpasswd_file}, $curuser, $pw); }
    print "</pre>";
  }
}

#
# Get repository from the parameters.  This can be either given by a parameter
# or as directory.
#
my $repos;
if (param('repos')) {
  $repos = param('repos');
} elsif (path_info() =~ /\/([a-zA-Z0-9\-][a-zA-Z0-9\.\-]*)$/) {
  $repos = $1;
} else {
  $repos = '';
}

if ($action eq "create" && in_group("admins")) {
  my $reposadmin = param('reposadmin')||'';
  print h2("Creating repository");
  if ($repos !~ /^[a-zA-Z0-9\-][a-zA-Z0-9\.\-]*$/) {
    print p("The name of the repository may only contain printable ",
      "characters.  Please try a different name");
  } elsif ($reposadmin !~ /^\@?[a-z][a-z0-9]*$/) {
    print p("The name of the repository administrator should be a valid ",
      "login name.  Please try again.");
  } elsif (-e "$config->{svnroot}/$repos") {
    print p("A repository with that name already exists.");
  } else {
    print p("Creating repository ",code($repos),":"),"<pre>\n";
    if (mkdir("$config->{svnroot}/$repos", 0770)
      && system($config->{svnadmin}, "create", 
        "--fs-type", "fsfs", "$config->{svnroot}/$repos") == 0) {
      print "</pre>";
      print p("The repository",code($repos),
        "was created for $reposadmin.");
      $repositories->{$repos} = { "/" => {"$reposadmin" => ["rw"]}};
      $globals->{'groups'}{"$repos-admins"} = [ $reposadmin ];
      write_repos();
    } else {
      print "</pre>", 
      p("An unexpected error occured while creating repository.");
    }
  }
}

if ($action eq "chgroupacl" && in_group("$repos-admins")) {
  my $needupdate = 0;
  my $numgroups = int(param("numgroups"));
  my @deletegrp = param("deletegrp");
  my $numacl = int(param("numacl"));
  my @deleteacl = param("deleteacl");

  my $i;
  groups:
  for ($i = 0; $i < $numgroups + 1; $i++) {
    my $grpname = param("grpname[$i]")||'';
    my $users = param("users[$i]") ||
    join(',', param("l_users[$i]")) || '';
    if ($grpname eq "") {
      # ignore added entry
    } elsif ($grpname !~ /^[a-zA-Z0-9_]+$/) {
      print p("The name of the new group should only contain ",
        "alphanumeric characters.  Please try again.");
    } elsif (grep /^$i$/, @deletegrp) {
      my $j;
      for ($j = 0; $j < $numacl; $j++) {
        my $key = param("usergroup[$j]") || '';
        if ($key eq "\@$repos-$grpname" && ! grep /^$j$/, @deleteacl) {
          print p("Cannot delete group $repos-$grpname, ".
            "because it is still in use.\n");
          next groups;
        }
      }
      print p("Deleting group ${repos}-${grpname}.");
      delete $globals->{'groups'}{"${repos}-${grpname}"};
      $needupdate = 1;
    } elsif ($users !~ /^\@?[a-z][a-z0-9]*(\s*,\s*[a-z][a-z0-9]*)*$/) {
      print p("The name of the group members of group $repos-$grpname ",
        "should be valid login names.  Please try again.");
    } else {
      my @value = split(/\s*,\s*/, $users);
      my $origvalue = $globals->{'groups'}{"${repos}-${grpname}"};
      if (!defined $origvalue) {
        print p("Added group ${repos}-${grpname} with users $users");
        $globals->{'groups'}{"${repos}-${grpname}"} = \@value;
      $needupdate = 1;
    } elsif ($i == $numgroups) {
      # The expected behaviour is to add users to an
      # existing group.
      my @newvalue = @{$origvalue};
      my $user;
      foreach $user (@value) {
        if (! grep {$_ eq $user} @newvalue) {
          print p("Added user $user to group ${repos}-${grpname}");
          push @newvalue, $user;
          $needupdate = 1;
        }
      }
      $globals->{'groups'}{"${repos}-${grpname}"} = \@newvalue;
  } elsif (join(",", @{$origvalue}) ne join(",", @value)) {
    print p("Changed group ${repos}-${grpname} to $users");
    $globals->{'groups'}{"${repos}-${grpname}"} = \@value;
  $needupdate = 1;
}
    }
  }

  for ($i = 0; $i < $numacl + 1; $i++) {
    my $path = param("path[$i]")||'';
    my $key = param("usergroup[$i]") || '';
    my $value = param("access[$i]")||'';

    if ($key eq ""){
      $key = undef;
    } elsif ($key =~ /^\@([a-zA-Z0-9._-]+)$/) {
      if (! defined($globals->{'groups'}{$1}) && 
        ! grep /^$i$/, @deleteacl) {
        print p(escapeHTML("Unknown group: $1"));
        $key = undef;
      }
    } elsif ($key !~ /^[A-Za-z][A-Za-z0-9._-]+$/ && $key ne '*') {
      print p(escapeHTML("Invalid login name: $key"));
      $key = undef;
    }

    if (!defined $key) {
      # error printed above
    } elsif ($value !~ /^(rw?)?$/
      || $path !~ /^[!-Z^-~]+$/) {
      print p(escapeHTML("Invalid values: $path $key $value"));
    } else {
      if (grep /^$i$/, @deleteacl) {
        delete $repositories->{$repos}{$path}{$key};
        $needupdate = 1;
        if (scalar(keys %{$repositories->{$repos}{$path}}) == 0) {
          delete $repositories->{$repos}{$path};
          print p("Delete a path: $repos:$path $key");
        } else {
          print p("Delete a user: $repos:$path $key");
        }
      } elsif (!defined $repositories->{$repos}{$path}) {
        $repositories->{$repos}{$path} = {$key => [$value]};
        print p("Creating a path: $repos:$path $key $value");
        $needupdate = 1;
      } elsif (!defined $repositories->{$repos}{$path}{$key}) {
        print p("Creating a user: $repos:$path $key $value");
        $repositories->{$repos}{$path}{$key} = [$value];
        $needupdate = 1;
      } elsif (join(",", @{$repositories->{$repos}{$path}{$key}}) 
        ne $value) {
        $repositories->{$repos}{$path}{$key} = [$value];
        print p("Changing access entry: $repos:$path $key $value");
        $needupdate = 1;
      }
    }
  }
  write_repos() if ($needupdate);
  if (param("gpgaddkey") || param("gpgdelkey")) {
    my @gpgkeyids = get_gpg_keyid($repos);
    my $key = param("gpgaddkey");
    if ($key =~ /^[0-9a-f]+$/) {
      if (!grep {$_ eq $key} @gpgkeyids) {
        print p("Adding gpg key $key to backup");
        push @gpgkeyids, $key;
      }
    } elsif ($key) {
      print p(escapeHTML("Invalid key: $key"));
    }
    foreach $key (param("gpgdelkey")) {
      if ($key =~ /^[0-9a-f]+$/) {
        print p("Removing gpg key $key for backup");
        @gpgkeyids = grep {$_ ne $key} @gpgkeyids;
      } elsif ($key) {
        print p(escapeHTML("Invalid key: $key"));
      }
    }
    write_gpg_keyid($repos, @gpgkeyids);
  }

  my $gpgkeyfile = upload('gpgkeyfile');
  if (defined $gpgkeyfile) {
    print p("Importing GPG key:");
    print "<pre>\n";

    # errors from GPG goto stderr, so shunt it to stdout before running gpg
    open STDERR, ">&STDOUT";

    # upload a new public key
    open (GPG, "|-", $config->{gpg}, "--homedir", "$config->{gpghome}", "--import");
    my $bytesread;
    my $buffer;
    while ($bytesread=read($gpgkeyfile,$buffer,1024)) {
      print GPG $buffer;
    }
    close(GPG);
    close($gpgkeyfile);

    print "</pre>";
  }
}

if ($action eq "load" && in_group("$repos-admins")) {
  my $dumpfile = upload('dumpfile');
  my $dumpsubdir = param('dumpsubdir')||'';
  print h2(escapeHTML("Loading repository dump file into $repos:$dumpsubdir"));
  if (!defined $dumpfile) {
    print p("No file was uploaded (",
      escapeHTML($dumpfile),",",
      escapeHTML(param("dumpfile")),",",
      escapeHTML(cgi_error).")???");
  } else {
    my $result;
    my $dumpfilename = param('dumpfile');
    my @command = ($config->{svnadmin}, "load");
    if ($dumpsubdir) {
      push @command, "--parent-dir", "$dumpsubdir";
    }
    push @command,"$config->{svnroot}/$repos";
    my $pid = open (SVNDUMP, "-|");
    if (!defined $pid) {
      print p(escapeHTML("Cannot fork: $!"));
    } elsif ($pid) { 
      # parent
      print "<pre>\n";
      while (<SVNDUMP>) {
        print escapeHTML($_);
      }
      print "</pre>\n";
      close(SVNDUMP);
    } else {
      open (STDIN, "<&=", $dumpfile);
      open (STDERR, ">&STDOUT");
      if ($dumpfilename =~ /\.gz$/) {
        open (STDIN, "$config->{gzip} -dc|");
      }
      exec @command;
      exit 255;
    }
  }
}

print h3("Hello $curuser,");
my @admgroups;
my $admgroup;
foreach $admgroup (sort grep /-admins$/, keys %{$globals->{'groups'}}) {
  if (in_group($admgroup)) {
    push @admgroups, $admgroup;
  }
}
if (@admgroups) {
  print "<p>", "You are administrator for";
  foreach $admgroup (@admgroups) {
    $admgroup =~ /(.*)-admins$/;
    my $therepos = $1;
    if ($repos eq $therepos) {
      print " [$therepos]";
    } else {
      print " ", a({-href=>$therepos}, "[$therepos]");
    }
  }
  print ". ";
  print a({-href=>"."}, "General administration")."." if ($repos);
  print "</p>";
}

if ($repos ne "" && in_group("$repos-admins")) {
  print h2({-id=>$repos},"Administrate repository ".
    a({href=> websvnpath($repos,"/")}, $repos));

  if (in_group("admins")) {
    print start_form(-method => 'post');
    print hidden(-name => 'action', -default => 'adduser', -force => '1');
    print h3("Create Users");
    print "<table style=\"border:1pt solid;\">";

    print Tr(td("User (Login):"),
      td(textfield(-name => "newUser", -default => "",
          -size => "30", -maxlength => "30")));
    print Tr(td("Full name:"),
      td(textfield(-name => "fullname", -default => '',
          -size => '60', -maxlength => '80')));
    print Tr(td("Email:"),
      td(textfield(-name => "email", -default => '',
          -size => '60', -maxlength => '180')));
    print Tr(td("Passphrase:"),
      td(password_field(-name => "pwd", 
          -size => '32', -maxlength => '80')));
    print Tr(td("Verify passphrase:"),
      td(password_field(-name => "vpwd", 
          -size => '32', -maxlength => '80')));
    print "<tr><td rowspan='2'><input type='submit' name='add' value='Add'/></td></tr>";
    print "</table>";
    print end_form;
  }

  print start_form(-method => 'post', -enctype => 'multipart/form-data');
  print hidden(-name => 'repos', -default => "$repos", -force =>'1');
  print hidden(-name => 'action', -default => 'chgroupacl', -force => '1');
  print h3("Groups");
  print "<table style=\"border:1pt solid;\">";
  print Tr(th("Group"),th("Users"));
  my @reposgroups = 
  sort grep /^$repos-[a-zA-Z0-9_]+$/, keys %{$globals->{'groups'}};
  my $group;
  my $grpnr = 0;
  foreach $group (@reposgroups) {
    $group =~ /^$repos-(.*)$/;
    my $grpname = $1;
    my $users = join(",", @{$globals->{'groups'}{$group}});
    print Tr(td(hidden(-name => "grpname[$grpnr]", -default => "$grpname",
          -force => '1').$group), 
      td(textfield(-name => "users[$grpnr]", -default => $users, 
          -size => '50', -force => '1')),
      td($grpname eq "admins" ? "" : 
        checkbox(-name => "deletegrp", -value => "$grpnr", 
          -checked => 0, -force => 1,
          -label => "Delete")));
    $grpnr++;
  }
  print Tr(td(hidden(-name => 'numgroups', -default => $grpnr, -force =>'1').
      "${repos}-".
      textfield(-name => "grpname[$grpnr]", -default => '', 
        -force => '1', -size => '15')), 
    td(scrolling_list(-name => "l_users[$grpnr]",
        -value => [sort (keys %users)],
        -labels => {map {$_ => "$_ (" . $users{$_}->{'displayName'} . ')' } 
          (keys %users)},
        -size => 5,
        -multiple => 'true')),
    td(submit(-name => 'add', -label => 'Add')));
  print Tr(td({-colspan => '3', -align => 'center'}, 
      submit(-name => 'commit', -label => 'Commit Changes')));
  print "</table>";

  print h3("Access Control Table");
  print "<table style=\"border:1pt solid;\">";

  my $path;
  my $key;
  my $aclnr = 0;
  my $manual = a({href => "http://svnbook.red-bean.com/en/1.5/svn.serverconfig.httpd.html#svn.serverconfig.httpd.authz.perdir"}, "Manual");
  print Tr(th("Path"),th("User(group)"),th("Access"),th(""));
  foreach $path (sort keys %{$repositories->{$repos}}) {
    foreach $key (sort keys %{$repositories->{$repos}{$path}}) {
      my $value = join(",", @{$repositories->{$repos}{$path}{$key}});
      print Tr(td([hidden(-name => "path[$aclnr]", -value => "$path", 
              -force => 1) . $path,
            hidden(-name => "usergroup[$aclnr]", -value => "$key", 
              -force => 1) . $key,
            popup_menu(-name => "access[$aclnr]", 
              -values => [ 'rw', 'r', ''], 
              -default => $value, -force => 1,
              -labels => { '' => '-' }),
            checkbox(-name => "deleteacl", -value => "$aclnr", 
              -checked => 0, -force => 1,
              -label => "Delete")]));
      $aclnr++;
    }
  }

  print Tr(td([hidden(-name => 'numacl', -default => "$aclnr", -force =>'1').
        textfield(-name => "path[$aclnr]", -default => '/', 
          -force =>'1', -size => '30'),
        popup_menu(-name => "usergroup[$aclnr]",
          -default => '', -force => 1,
          -values => [ '', (map { '@'.$_ } @reposgroups),
            sort (keys %users) ]),
        popup_menu(-name => "access[$aclnr]",
          -values => [ 'rw', 'r', ''],
          -default => 'rw', -labels => { '' => '-' }),
        submit(-label => 'Add')]));
  print Tr(td({-colspan => '4', -align => 'center'},
      submit(-name => 'commit', -label => 'Commit Changes')));
  print "</table>";
  print p("You can give read/write or read-only rights to a single user or a user group. A user group is denoted by \@$repos-\&lt;groupname\&gt;.  The access rights are valid for the given path and all sub directories.  For details see the $manual.");
  print p(strong("Warning:"), "the ViewCVS script does not always respect path restrictions.  A skilled user with read-only access to one directory of the repository can read the whole repository.  Better use different repositories.");

  if ($config->{enable_backup} and read_gpg_keys()) {
    print h3("Manage GPG Keys");
    print p("The users in the group $repos-backup can download an encrypted backup ", a({href => "$repos.gpg"}, "$repos.gpg"),". For regular backups you can adapt this ", a({href => "/svnbackup"}, "backup shell script"),". The backup is encrypted with the GPG keys in the following list.");

    print "<table style=\"border:1pt solid;\">";
    my @gpgkeyids = get_gpg_keyid($repos);
    my $id;
    for $id (@gpgkeyids) {
      print Tr(td($id."&nbsp;".escapeHTML($gpgfpr{$id})),
        td(checkbox(-name => "gpgdelkey", -value => "$id", 
            -checked => 0, -force => 1,
            -label => "Remove")));
    }
    $gpgfpr{""}="";
    print Tr(td(popup_menu(-name => "gpgaddkey",
          -value => [sort keys %gpgfpr],
          -force => '1',
          -labels => {map {$_ => "$_ $gpgfpr{$_}" } 
            (keys %gpgfpr)})),
      td(submit(-name => 'add', -label => 'Add')));

    print Tr(td([strong("GPG Public Key: ").
          filefield(-name => 'gpgkeyfile', -default => '', 
            -size => '40')]));
    print Tr(td({-colspan => '2', -align => 'center'},
        submit(-name => 'commit', -label => 'Commit Changes')));
    print "</table>";
  }
  print endform;


  if ($config->{enable_backup}) {
    print h3("Get/Upload dump file");
    print p("Click here, to download a ".
      a({href => "$repos.gz"}, "dump file").
      " of repository $repos");
    print p("Upload an ",b("incremental"),
      " dump file into repository $repos:"),
    start_form(-method=>"post", -enctype=>"multipart/form-data"), 
    hidden(-name => 'action', -default => 'load', -force =>'1'),
    hidden(-name => 'repos', -default => "$repos", -force =>'1'),
    table(Tr([td([strong("Dump File: "),
              filefield(-name => 'dumpfile', -default => '', 
                -size => '40')]),
          td([strong("Subdirectory: "),
              textfield(-name => 'dumpsubdir', -default => '', 
                -size => '20')])
        ])),
    submit(-label => 'Load'),
    end_form;

    print hr;
  }


#   print h3("Get/Upload configuration file");
#   print p("Click here, to download ".
#       a({href => "$repos/svnserve.conf"}, "svnserve.conf").
#       " of repository $repos");
#   print p("Upload a new svnserve.conf into repository $repos:"),
#   start_form(-method=>"post", -enctype=>"multipart/form-data"), 
#   hidden(-name => 'action', -default => 'loadconf', -force =>'1'),
#   hidden(-name => 'repos', -default => "$repos", -force =>'1'),
#   table(Tr([td([strong("Config File: "),
#             filefield(-name => 'conffile', -default => '', 
#               -size => '40')]),
#         ])),
#   submit(-label => 'Load'),
#   end_form;

#   print hr;

} elsif ($repos eq "") {

  # Only offer to change passphrase if we are an HTPASSWD user - otherwise passwords are managed externally.
  if ($users{$curuser}->{'source'} eq 'HTPASSWD') {
    print h2("Change Passphrase"),"\n";
    print p("please enter your new choice of passphrase below, and then verify it by entering it again."),"\n",
    start_form,
    hidden(-name => 'action', -default => "changepw"),
    table(Tr([
          td([strong("Passphrase: "),
              password_field(-name => 'passphrase', -size => 32, -maxlength => 80),
              "(6-80 chars)"]),
          td([strong("Verify: "),
              password_field(-name => 'verify', -size => 32, -maxlength => 80)])
        ])),
    submit(-label => 'change passphrase'),
    end_form,
    "\n",p("You can either use a passphrase (preferably of decent length, include punctuation, etc,) or a password.  Good passwords have these properties:"),"\n",
    ul(
      li('is not based upon a dictionary word'),
      li('does not have numbers substituted for common letters (ie. 3 for E 1 for I, 0 for O, etc) or numbers used as a suffix/prefix (ie.  4sale, 2by4, etc.)'),
      li('is at least 8 characters long (length of 6 to 80 is required)'),
      li('is made up of a combination of non-repeating upper/lower case letters, numbers, and punctuation.'),
      li('is hard to guess ;)'),
    ),
    "\n",p,"Also note that the passphrase is case-sensitive.\n",hr;
  }

  if (in_group("admins")) {
    print h2("Create a new repository");
    print start_form, 
    hidden(-name => 'action', -default => 'create', -force =>'1'),
    table(Tr([td([strong("Name of new repository: "),
              textfield(-name => 'repos', -default => '', 
                -size => '20')]),
          td([strong("Administrator: "),
              textfield(-name => 'reposadmin', -default => "$curuser", 
                -size => '20')])
        ])),
    submit(-label => 'Create'),
    end_form,hr;
  }

  {
    print h2("Your access rights"),
    p("You have ", strong("read-write")," access to the following repositories:"),"<ul>";
    foreach $repos (sort keys %$repositories) {
      foreach my $path (sort keys %{$repositories->{$repos}}) {
        foreach my $key (sort keys %{$repositories->{$repos}{$path}}) {
          next if @{$repositories->{$repos}{$path}{$key}} != 1;
          next if $repositories->{$repos}{$path}{$key}[0] ne "rw";
          if ($key eq $curuser
            || $key eq '*'
            || ($key =~ /^@(.*)$/ && in_group("$1"))) {
            print li(a({href => websvnpath($repos,$path)}, 
                "$config->{baseurl}$config->{svnpath}/$repos$path"));
          }
        }
      }
    }
    print "</ul>",
    p("You have ", strong("read-only")," access to the following repositories:"),"<ul>";
    foreach $repos (sort keys %$repositories) {
      foreach my $path (sort keys %{$repositories->{$repos}}) {
        foreach my $key (sort keys %{$repositories->{$repos}{$path}}) {
          next if @{$repositories->{$repos}{$path}{$key}} != 1;
          next if $repositories->{$repos}{$path}{$key}[0] ne "r";
          if ($key eq $curuser || $key eq '*'
            || ($key =~ /^@(.*)$/ && in_group("$1"))) {
            print li(a({href => websvnpath($repos,$path)}, 
                "$config->{baseurl}$config->{svnpath}/$repos$path"));
          }
        }
      }
    }
    print "</ul>",hr;
  }
}
print p("<small>Copyright 2005&ndash;2009 Jochen Hoenicke, Michael M&ouml;ller, Marco L&uuml;bcke; based on code from Theo Van Dinter</small>"),"\n";
print end_html,"\n";

1;

__END__

GNU GENERAL PUBLIC LICENSE
Version 2, June 1991

Copyright (C) 1989, 1991 Free Software Foundation, Inc.
59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
Everyone is permitted to copy and distribute verbatim copies
of this license document, but changing it is not allowed.

Preamble

The licenses for most software are designed to take away your
freedom to share and change it.  By contrast, the GNU General Public
License is intended to guarantee your freedom to share and change free
software--to make sure the software is free for all its users.  This
General Public License applies to most of the Free Software
Foundation's software and to any other program whose authors commit to
using it.  (Some other Free Software Foundation software is covered by
the GNU Library General Public License instead.)  You can apply it to
your programs, too.

When we speak of free software, we are referring to freedom, not
price.  Our General Public Licenses are designed to make sure that you
have the freedom to distribute copies of free software (and charge for
this service if you wish), that you receive source code or can get it
if you want it, that you can change the software or use pieces of it
in new free programs; and that you know you can do these things.

To protect your rights, we need to make restrictions that forbid
anyone to deny you these rights or to ask you to surrender the rights.
These restrictions translate to certain responsibilities for you if you
distribute copies of the software, or if you modify it.

For example, if you distribute copies of such a program, whether
gratis or for a fee, you must give the recipients all the rights that
you have.  You must make sure that they, too, receive or can get the
source code.  And you must show them these terms so they know their
rights.

We protect your rights with two steps: (1) copyright the software, and
(2) offer you this license which gives you legal permission to copy,
distribute and/or modify the software.

Also, for each author's protection and ours, we want to make certain
that everyone understands that there is no warranty for this free
software.  If the software is modified by someone else and passed on, we
want its recipients to know that what they have is not the original, so
that any problems introduced by others will not reflect on the original
authors' reputations.

Finally, any free program is threatened constantly by software
patents.  We wish to avoid the danger that redistributors of a free
program will individually obtain patent licenses, in effect making the
program proprietary.  To prevent this, we have made it clear that any
patent must be licensed for everyone's free use or not licensed at all.

The precise terms and conditions for copying, distribution and
modification follow.

GNU GENERAL PUBLIC LICENSE
TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

0. This License applies to any program or other work which contains
a notice placed by the copyright holder saying it may be distributed
under the terms of this General Public License.  The "Program", below,
refers to any such program or work, and a "work based on the Program"
means either the Program or any derivative work under copyright law:
that is to say, a work containing the Program or a portion of it,
either verbatim or with modifications and/or translated into another
language.  (Hereinafter, translation is included without limitation in
the term "modification".)  Each licensee is addressed as "you".

Activities other than copying, distribution and modification are not
covered by this License; they are outside its scope.  The act of
running the Program is not restricted, and the output from the Program
is covered only if its contents constitute a work based on the
Program (independent of having been made by running the Program).
Whether that is true depends on what the Program does.

1. You may copy and distribute verbatim copies of the Program's
source code as you receive it, in any medium, provided that you
conspicuously and appropriately publish on each copy an appropriate
copyright notice and disclaimer of warranty; keep intact all the
notices that refer to this License and to the absence of any warranty;
  and give any other recipients of the Program a copy of this License
along with the Program.

You may charge a fee for the physical act of transferring a copy, and
you may at your option offer warranty protection in exchange for a fee.

2. You may modify your copy or copies of the Program or any portion
of it, thus forming a work based on the Program, and copy and
distribute such modifications or work under the terms of Section 1
above, provided that you also meet all of these conditions:

a) You must cause the modified files to carry prominent notices
stating that you changed the files and the date of any change.

b) You must cause any work that you distribute or publish, that in
whole or in part contains or is derived from the Program or any
part thereof, to be licensed as a whole at no charge to all third
parties under the terms of this License.

c) If the modified program normally reads commands interactively
when run, you must cause it, when started running for such
interactive use in the most ordinary way, to print or display an
announcement including an appropriate copyright notice and a
notice that there is no warranty (or else, saying that you provide
a warranty) and that users may redistribute the program under
these conditions, and telling the user how to view a copy of this
License.  (Exception: if the Program itself is interactive but
does not normally print such an announcement, your work based on
the Program is not required to print an announcement.)

These requirements apply to the modified work as a whole.  If
identifiable sections of that work are not derived from the Program,
  and can be reasonably considered independent and separate works in
themselves, then this License, and its terms, do not apply to those
sections when you distribute them as separate works.  But when you
distribute the same sections as part of a whole which is a work based
on the Program, the distribution of the whole must be on the terms of
this License, whose permissions for other licensees extend to the
entire whole, and thus to each and every part regardless of who wrote it.

Thus, it is not the intent of this section to claim rights or contest
your rights to work written entirely by you; rather, the intent is to
exercise the right to control the distribution of derivative or
collective works based on the Program.

In addition, mere aggregation of another work not based on the Program
with the Program (or with a work based on the Program) on a volume of
a storage or distribution medium does not bring the other work under
the scope of this License.

3. You may copy and distribute the Program (or a work based on it,
under Section 2) in object code or executable form under the terms of
Sections 1 and 2 above provided that you also do one of the following:

a) Accompany it with the complete corresponding machine-readable
source code, which must be distributed under the terms of Sections
1 and 2 above on a medium customarily used for software interchange; or,

b) Accompany it with a written offer, valid for at least three
years, to give any third party, for a charge no more than your
cost of physically performing source distribution, a complete
machine-readable copy of the corresponding source code, to be
distributed under the terms of Sections 1 and 2 above on a medium
customarily used for software interchange; or,

c) Accompany it with the information you received as to the offer
to distribute corresponding source code.  (This alternative is
allowed only for noncommercial distribution and only if you
received the program in object code or executable form with such
an offer, in accord with Subsection b above.)

The source code for a work means the preferred form of the work for
making modifications to it.  For an executable work, complete source
code means all the source code for all modules it contains, plus any
associated interface definition files, plus the scripts used to
control compilation and installation of the executable.  However, as a
special exception, the source code distributed need not include
anything that is normally distributed (in either source or binary
form) with the major components (compiler, kernel, and so on) of the
operating system on which the executable runs, unless that component
itself accompanies the executable.

If distribution of executable or object code is made by offering
access to copy from a designated place, then offering equivalent
access to copy the source code from the same place counts as
distribution of the source code, even though third parties are not
compelled to copy the source along with the object code.

4. You may not copy, modify, sublicense, or distribute the Program
except as expressly provided under this License.  Any attempt
otherwise to copy, modify, sublicense or distribute the Program is
void, and will automatically terminate your rights under this License.
However, parties who have received copies, or rights, from you under
this License will not have their licenses terminated so long as such
parties remain in full compliance.

5. You are not required to accept this License, since you have not
signed it.  However, nothing else grants you permission to modify or
distribute the Program or its derivative works.  These actions are
prohibited by law if you do not accept this License.  Therefore, by
modifying or distributing the Program (or any work based on the
Program), you indicate your acceptance of this License to do so, and
all its terms and conditions for copying, distributing or modifying
the Program or works based on it.

6. Each time you redistribute the Program (or any work based on the
Program), the recipient automatically receives a license from the
original licensor to copy, distribute or modify the Program subject to
these terms and conditions.  You may not impose any further
restrictions on the recipients' exercise of the rights granted herein.
You are not responsible for enforcing compliance by third parties to
this License.

7. If, as a consequence of a court judgment or allegation of patent
infringement or for any other reason (not limited to patent issues),
conditions are imposed on you (whether by court order, agreement or
otherwise) that contradict the conditions of this License, they do not
excuse you from the conditions of this License.  If you cannot
distribute so as to satisfy simultaneously your obligations under this
License and any other pertinent obligations, then as a consequence you
may not distribute the Program at all.  For example, if a patent
license would not permit royalty-free redistribution of the Program by
all those who receive copies directly or indirectly through you, then
the only way you could satisfy both it and this License would be to
refrain entirely from distribution of the Program.

If any portion of this section is held invalid or unenforceable under
any particular circumstance, the balance of the section is intended to
apply and the section as a whole is intended to apply in other
circumstances.

It is not the purpose of this section to induce you to infringe any
patents or other property right claims or to contest validity of any
such claims; this section has the sole purpose of protecting the
integrity of the free software distribution system, which is
implemented by public license practices.  Many people have made
generous contributions to the wide range of software distributed
through that system in reliance on consistent application of that
system; it is up to the author/donor to decide if he or she is willing
to distribute software through any other system and a licensee cannot
impose that choice.

This section is intended to make thoroughly clear what is believed to
be a consequence of the rest of this License.

8. If the distribution and/or use of the Program is restricted in
certain countries either by patents or by copyrighted interfaces, the
original copyright holder who places the Program under this License
may add an explicit geographical distribution limitation excluding
those countries, so that distribution is permitted only in or among
countries not thus excluded.  In such case, this License incorporates
the limitation as if written in the body of this License.

9. The Free Software Foundation may publish revised and/or new versions
of the General Public License from time to time.  Such new versions will
be similar in spirit to the present version, but may differ in detail to
address new problems or concerns.

Each version is given a distinguishing version number.  If the Program
specifies a version number of this License which applies to it and "any
later version", you have the option of following the terms and conditions
either of that version or of any later version published by the Free
Software Foundation.  If the Program does not specify a version number of
this License, you may choose any version ever published by the Free Software
Foundation.

10. If you wish to incorporate parts of the Program into other free
programs whose distribution conditions are different, write to the author
to ask for permission.  For software which is copyrighted by the Free
Software Foundation, write to the Free Software Foundation; we sometimes
make exceptions for this.  Our decision will be guided by the two goals
of preserving the free status of all derivatives of our free software and
of promoting the sharing and reuse of software generally.

NO WARRANTY

11. BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
REPAIR OR CORRECTION.

12. IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
POSSIBILITY OF SUCH DAMAGES.

END OF TERMS AND CONDITIONS

How to Apply These Terms to Your New Programs

If you develop a new program, and you want it to be of the greatest
possible use to the public, the best way to achieve this is to make it
free software which everyone can redistribute and change under these terms.

To do so, attach the following notices to the program.  It is safest
to attach them to the start of each source file to most effectively
convey the exclusion of warranty; and each file should have at least
the "copyright" line and a pointer to where the full notice is found.

<one line to give the program's name and a brief idea of what it does.>
Copyright (C) 19yy  <name of author>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


Also add information on how to contact you by electronic and paper mail.

If the program is interactive, make it output a short notice like this
when it starts in an interactive mode:

Gnomovision version 69, Copyright (C) 19yy name of author
Gnomovision comes with ABSOLUTELY NO WARRANTY; for details type `show w'.
This is free software, and you are welcome to redistribute it
under certain conditions; type `show c' for details.

The hypothetical commands `show w' and `show c' should show the appropriate
parts of the General Public License.  Of course, the commands you use may
be called something other than `show w' and `show c'; they could even be
mouse-clicks or menu items--whatever suits your program.

You should also get your employer (if you work as a programmer) or your
school, if any, to sign a "copyright disclaimer" for the program, if
necessary.  Here is a sample; alter the names:

Yoyodyne, Inc., hereby disclaims all copyright interest in the program
`Gnomovision' (which makes passes at compilers) written by James Hacker.

<signature of Ty Coon>, 1 April 1989
Ty Coon, President of Vice

This General Public License does not permit incorporating your program into
proprietary programs.  If your program is a subroutine library, you may
consider it more useful to permit linking proprietary applications with the
library.  If this is what you want to do, use the GNU Library General
Public License instead of this License.
