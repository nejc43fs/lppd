#!/usr/bin/perl -w
$|++;

# Postfix Policy Daemon:
# Sprejema requeste od postfixov in sprašuje mailboxHoste o stanju quote 

package PPD;
@ISA = qw(Net::Server::Fork);

use strict;
use Net::Server::Fork;
use Sys::Syslog qw(:standard);
use IO::Socket::INET;
use Config::General;
use Net::LDAP;
use Net::LDAP::Filter;

#################  :: variables ::  #################

my $config_file = "/opt/lppd/ppd.conf";
my $run_as = "nobody";
my $bind_port = 9200;
my $dovecot_policy_port = 9300;
my $dovecot_policy_timeout = 5;
my $tcp_timeout = 10;
my $ldap_server = "localhost";
my $ldap_dn = "uid=root,o=top";
my $ldap_base = "ou=domains,o=top";
my $ldap_pass = "password";
my $pid_file = "/tmp/ppd.pid";
my (%query, $quota_request, $rt, $line, $field, $value, $return_value, %config, $mailboxHost);
my $ldap_filter= '(|(uid=%s)(mailAlternateAddress=%s)(mail=%s))'; # %s expands to recipient
my $RESPONSE_DUNNO = "action=dunno\n\n";
my $logfile = "/tmp/lppd.log";
my $daemonize = 0; # 0 - if foreground, 1 - background

my $debug = 1;

#################  :: main ::  ###################

# open and parse config file
%config = new Config::General($config_file)->getall;
parse_config();

# open syslog
openlog("ppd", "ndelay", "mail");
syslog("err", "Postfix Policy Server: Going to daemon land");
syslog("err", "Binding to port " . $bind_port);

# start listening
PPD->run(
	port => $bind_port,
	log_level => 0,
	log_file => $logfile,
	background => $daemonize,
	#pid_file => $pid_file,
	user => $run_as
);

#################  :: subroutines ::  ###################

# syslog logging subroutine
# input: recipient, status (0-reject, 1-ok, 2-dunno), cached
sub log_request
{
	my $recipient = shift;
	my $status = shift;
	my $cached = shift;
	syslog("err", "log_request: Response: $recipient : $status");	
}

# parse_recipient(alias): checks whether the user corresponding to $alias is over quota (uses timestamp cache)
# input: alias, size
# output: 0-reject, 1-ok, 2-dunno
sub parse_recipient
{
	my $recipient = shift;
	my $size = shift;
	my ($rv, $entry, $username, $db, $query, $updated, $logEntry, $max_checks);
	$rv = "dunno";

	syslog("err", "Starting LDAP:" ) if $debug;
	my $ldap = Net::LDAP->new( $ldap_server, timeout => 15 ) or return 2;
	$ldap->bind($ldap_dn, password => $ldap_pass);
	syslog("err", "LDAP: bind success" ) if $debug;

	my $filter = $ldap_filter;
	$filter =~ s/%s/$recipient/g;

	my $result = $ldap->search(
		base   => $ldap_base,
		filter => Net::LDAP::Filter->new( $filter ),
		attrs => ['uid', 'mailHost']
	);
	syslog("err", "LDAP: searching base: " .$ldap_base ." filter: " .$filter ) if $debug;

	if (!$result->code) {
		syslog("err", "result code is" .$result->code ) if $debug;
		if ($result->count == 0) {
			$rv="dunno";
			log_request($recipient,$rv,0);
			syslog("err", "Request for $recipient [unknown mail alias]") if $debug; 
		} elsif($result->count == 1) {
			foreach my $entry ($result->entries) {
				$mailboxHost = $entry->get_value("mailHost") || "";
				$username = $entry->get_value("uid") || "";
				syslog("err", "Response received: mailhost: " .$mailboxHost ." username: " .$username ) if $debug;
				$rv = check_quota($username, $mailboxHost, $size) || "dunno";
				syslog("err", "Return from check_quota: " . $rv) if $debug;
				log_request($recipient,$rv,0);
			}
		} else {
			syslog("err", "Too many responses") if $debug;
			$rv = "dunno";
		}
	} else {
		syslog("err", "LDAP query failed: " . $result->error ) if $debug;
	}
	syslog("err", "Unbinding LDAP") if $debug;
	$ldap->unbind;
	alarm 0;
	syslog("err", "returning from parse_recipient: " .$rv) if $debug;
	return $rv;
}

# desc: makes tcp connection to policy server @ mailbox host, asks for username quota status  and returns "boolean"
# input: username, mailboxserver, size
# output: 0-reject, 1-ok, 2-dunno
sub check_quota
{
	my $username = shift;
	my $mboxHost = shift;
	my $mailsize = shift;
	local $SIG{ALRM} = sub { syslog("err", "check_quota has timed out (". $dovecot_policy_timeout ."s)"); die; };
	alarm $dovecot_policy_timeout;
	my $action = "dunno";
	eval {
		my $socket = IO::Socket::INET->new(
			PeerAddr => $mboxHost,
			Proto => "tcp",
			PeerPort => $dovecot_policy_port);
		if(!defined $socket) {
			syslog("err", "Cannot connect to socket (" . $mboxHost . ":" . $dovecot_policy_port. ")") if $debug;
			die;
		}
		my $data = "recipient=" . $username . "\n" ."size=" .$mailsize ."\n\n";
		syslog("err", "Sending to " .$mboxHost ." port: " .$dovecot_policy_port ." request: " .$data) if $debug;
		$socket->printflush($data);
		while($line = $socket->getline)
		{
			last if($line =~ m/^$/);
			$action = $1 if($line =~ m/^action=(.*)/);
		}
		syslog("err", "Got response: " .$action) if $debug;
		$socket->close;
		alarm 0;
	}; 
	if($@) { 
		return "dunno"; 
		syslog("err", "Error in eval for : " . $username ."\@" .$mboxHost ) if $debug; 
	}
	return $action;
}

# parse_config
# checks config parameters and issues a warning if problems are found
sub parse_config
{
	$run_as = $config{run_as} if $config{run_as};
	$bind_port = $config{bind_port} if $config{bind_port};
	$dovecot_policy_port = $config{dovecot_policy_port} if $config{dovecot_policy_port};
	$dovecot_policy_timeout = $config{dovecot_policy_timeout} if $config{dovecot_policy_timeout};
	$tcp_timeout = $config{tcp_timeout} if $config{tcp_timeout};
	$pid_file = $config{pid_file} if $config{pid_file};
	$ldap_server = $config{ldap_server} if $config{ldap_server};
	$ldap_base = $config{ldap_base} if $config{ldap_base};
	$ldap_dn = $config{ldap_dn} if $config{ldap_dn};
	$ldap_pass = $config{ldap_pass} if $config{ldap_pass};
	$ldap_filter = $config{ldap_filter} if $config{ldap_filter};

	unless($bind_port =~ /^[1-9]+?\d*?$/ && $bind_port > 0 && $bind_port < 65536) {
		print "bind_port must be an integer in the range of 1-65535\n"; exit;
	}
	unless($dovecot_policy_timeout =~ /^[1-9]+?\d*?$/ && $dovecot_policy_timeout > 0) {
		print "dovecot_policy_timeout must be a positive integer\n"; exit;
	}
	unless($tcp_timeout =~ /^[1-9]+?\d*?$/ && $tcp_timeout > 0) {
		print "tcp_timeout must be a positive integer\n"; exit;
	}
	unless($dovecot_policy_port =~ /^[1-9]+?\d*?$/ && $dovecot_policy_port > 0 && $bind_port < 65536) {
		print "dovecot_policy_port must be an integer in the range of 1-65535\n"; exit;
	}
}

# process_request
# overriden Net::Server:Fork subroutine. called for each new client connection (after forking)
sub process_request {
	my $self = shift;
	%query = ();
	local $SIG{ALRM} = sub { syslog("err", "Connection timeout "); die; };
	alarm $tcp_timeout;
	eval {
		while (my $line = <STDIN>) {
			chomp $line;
			if ( $line =~ /^$/ ) {
				if(!defined $query{recipient} || !defined $query{size}) {
					syslog("err", "Invalid request - no recipient or size"); die;
				}
				last;
			} elsif ( $line =~ /\w=.*/ ) {
				( $field, $value ) = split( /=/, lc $line, 2 );
				$query{$field} = $value if (length($field) > 0 && length($value) > 0 );
			} else {
				syslog("err", "Invalid request line:\"" .$line ."\"\n"); 
			}
		}
		alarm 0;
	}; 
	if($@) {
		syslog("err", "Error processing");
		print $RESPONSE_DUNNO; return;
	}
	if(keys(%query) > 0 && defined $query{recipient} && defined $query{size}) {
		syslog("err", "Request: recipient=" . $query{recipient} ." size=" .$query{size});
		my $rv = parse_recipient($query{recipient}, $query{size});
		syslog("err", "Return value from parse_recipient: " . $rv );
		print "action=" .$rv;
		return;
	}
	print $RESPONSE_DUNNO;
	return;
}


