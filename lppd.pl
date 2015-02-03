#!/usr/bin/perl -w

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

#################  :: variables ::  #################

my $config_file = "/opt/lppd/ppd.conf";
my $run_as = "nobody";
my $bind_port = 9200;
my $dovecot_policy_port = 9300;
my $dovecot_policy_timeout = 5;
my $tcp_timeout = 10;
my $ldap_server = "localhost";
my $ldap_base = "ou=domains,o=top";
my $pid_file = "/tmp/ppd.pid";
my (%query, $quota_request, $rt, $line, $field, $value, $return_value, %config, $mailboxHost);
my $ldap_filter= '(|(uid=%s)(mailAlternateAddress=%s)(mail=%s))';
my $RESPONSE_DUNNO = "action=dunno\n\n";
my $RESPONSE_OK = "action=dunno\n\n";
#my $RESPONSE_REJECT = "action=reject\n\n";
#my $RESPONSE_REJECT = "action=dunno\n\n";
my $RESPONSE_REJECT = "action=defer_if_permit User over quota\n\n";
my $logfile = "/tmp/lppd.log";

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
	background => 1,
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
	my $flags;
	my $logEntry = "Request for $recipient";
	if($cached == 1) { $flags .= 'cached'; }
	elsif($cached == 2) { $flags .= ($flags ? ', ' : '') . 'updated'; }
	elsif($cached == 3) { $flags .= ($flags ? ', ' : '') . 'updated, max-checks'; }
	if($status == 0) { $flags .= ($flags ? ', ' : '') . 'over quota'; }
	if($status == 1) { $flags .= ($flags ? ', ' : '') . 'quota ok'; }
	if($status == 2) { $flags .= ($flags ? ', ' : '') . 'no quota/unknown user'; }
	if(!$flags) { syslog("err", $logEntry); }
	else { syslog("err", $logEntry . " [" . $flags . "]"); }
}

# parse_recipient(alias): checks whether the user corresponding to $alias is over quota (uses timestamp cache)
# input: alias
# output: 0-reject, 1-ok, 2-dunno
sub parse_recipient
{
	my $recipient = shift;
	my $size = shift;
	my ($rv, $entry, $username, $db, $query, $updated, $logEntry, $max_checks);
	$rv = 2;

	eval {
		my $ldap = Net::LDAP->new( $ldap_server ) or die $@;
		$ldap->bind;
 
		my $filter = $ldap_filter;
		$filter =~ s/%s/$recipient/g;

		my $result = $ldap->search(
		    base   => $ldap_base,
		    filter => $filter,
		    attrs => ['uid', 'mailHost']
		);
 
		if (!$result->code) {
			if($result->count == 0) {
				$rv=2;
				log_request($recipient,$rv,0);
				#syslog("err", "Request for $recipient [unknown mail alias]"); $rv = 2;	
			}
			elsif($result->count == 1) {
				$mailboxHost = $result->get_value("mailHost") || "";
				$username = $result->get_value("uid") || "";
				$rv = check_quota($username, $mailboxHost, $size) || "2";
				return $rv;
			}
		} else {
			syslog("err", "LDAP query failed: " . $result->error );
		}
		$ldap->unbind;
		alarm 0;
	};
	return $rv;
}

# desc: makes tcp connection to policy server @ mailbox host, asks for username quota status  and returns "boolean"
# input: username, mailboxserver, size
# output: 0-reject, 1-ok, 2-dunno
sub check_quota
{
	my $action;
	my $username = shift;
	my $mboxHost = shift;
	my $mailsize = shift;
	local $SIG{ALRM} = sub { syslog("err", "check_quota has timed out (". $dovecot_policy_timeout ."s)"); die; };
	alarm $dovecot_policy_timeout;
	eval {
		my $socket = IO::Socket::INET->new(
			PeerAddr => $mboxHost,
			Proto => "tcp",
			PeerPort => $dovecot_policy_port);
		if(!defined $socket) {
			syslog("err", "Cannot connect to socket (" . $mboxHost . ":" . $dovecot_policy_port. ")");
			die;
		}
		my $data = "recipient=" . $username . "\n" ."size=" .$mailsize ."\n\n";
		$socket->printflush($data);
		while($line = $socket->getline)
		{
			last if($line =~ m/^$/);
			$action = $1 if($line =~ m/^action=(.*)/);
		#	$socket->close;
		}
		$socket->close;
		alarm 0;
	}; if($@) { return 2; syslog("err", "Error in eval for : " . $username ."\@" .$mboxHost ); }
	return 1 if($action eq "ok");
	return 2 if($action eq "dunno");
	return 0;
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
				if(!defined $query{recipient}) {
					syslog("err", "Invalid request - no recipient"); die;
				}
				last;
			} else {
				( $field, $value ) = split( /=/, lc $line, 2 );
				$query{$field} = $value if (length($field) > 0 && length($value) > 0 );
			}
		}
		alarm 0;
	}; if($@) {
		print $RESPONSE_DUNNO; return;
	}
	if(keys(%query) > 0 && defined $query{recipient} && defined $query{size}) {
		my $rv = parse_recipient($query{recipient}, $query{size});
		#log_request($rv,$rv,0);
		if($rv < 2) {
			print $rv ? $RESPONSE_OK : $RESPONSE_REJECT; return;
		} else {
			print $RESPONSE_DUNNO; return;
		}
	}
	print $RESPONSE_DUNNO;
	return;
}


