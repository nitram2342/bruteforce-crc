#!/usr/bin/perl
#
# Parse number-containing strings and rewrite them as either
# hex or binary strings.
#
# Input format:
# - bits, e.g.: 100100101
# - hex, e.g.: 0xcafecafecafecafe or deadbeefdeadbeef
# - hex, e.g.: 0x23, 0x5, 0x17
#
# Input data might contain spaces and comments (indicated by a hash mark '#')
#
# Output format:
# - bits, e.g., 1010010101010
# - hex, e.g.: ac1d
#
#
# Author: Martin Schobert <schobert@sitsec.net>
#

use strict;
use Data::Dumper;
use POSIX;

my $mode = shift;
my $file = shift;
my $verbose = 0;

if(not defined($file) or not( -f $file)) {
    print "$0 [bits|hexbytes] <filename>\n";
    exit(1);
}

# parse messages
my $msg_list = rewrite_messages($file);


foreach my $msg (@$msg_list) {

    if($mode eq 'bits') {
	print $msg, "\n";
    }
    elsif($mode eq 'hexbytes') {
	print unpack("H*", pack("B*", $msg)), "\n";
    }
}

sub line_to_bits {
    my $line = shift;

    # We cannot use the perl module Bit::Vector directly,
    # because we have to know the vector's length. Thus,
    # we have to preparse it by our own.

    $line =~ s!\s*!!g;

    # process comma seperated values, e.g.: 0x5, 0x23, 0x42
    if($line =~ m!\,!) {
	my $l = "0x";
	foreach my $i (split(/\,/, $line)) {
	    if($i =~ m!0x(.*)!) {
		$l .= sprintf("%02x", hex($1));
	    }
	    else {
		die "Error: number [$i] in a value list [$line] is not in hex.\n";
	    }
	}
	$line = $l;
	print "parsing pre-transformed message: [$line]\n" if($verbose);
    }

    my $bits;

    # process binary string
    if($line =~ m!^[01]+$!) {
	$bits = $line;

    }
    # process hex strings prefixed with 0x
    elsif($line =~ m!^(0x)?([\da-f]+)$!i) {
	my $h = $2;
	my $hlen = length($h);
        my $blen = $hlen * 4;
	$bits = unpack("B$blen", pack("H$hlen", $h)); #XXX
    }
    else {
	die "Error: Can't parse line [$line]\n";
    }

    return $bits;

}

sub rewrite_messages {
    my $file = shift;
    my @messages;

    open(FILE, "< $file") or die "can't open file: $!\n";
    
    while(defined(my $line = <FILE>)) {
	chomp $line;
	print "parsing line in message file: [$line]\n" if($verbose);
	
	if($line =~ m!\s*\#!) {
	    # ignore comments
	}
	elsif($line =~ m![^\s]!) {
	    push @messages, line_to_bits($line);
	}
    }
    return \@messages;
}
