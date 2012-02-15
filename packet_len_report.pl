#!/usr/bin/perl

use strict;
use warnings;
use Data::Dumper;

my $myIp='10.72.164.101';

#-----------------------------------------------------------------------------
sub maxValue($$$) {
  my($data, $name, $value) = @_;

  if (defined $data->{$name} && $data->{$name} != $value) {
    $data->{$name} = $value if ($value > $data->{$name});
    #print "WARNING: $name $value flutuates\n";
    return 1;
  } else {
    $data->{$name} = $value;
    return 0;
  }
}

#-----------------------------------------------------------------------------
{
  my %data;
  my $server;
  my $client;

  my $command = 'tshark -n -r ' . $ARGV[0] . ' -o  column.format:\'"No.", "%m", "Source", "%s", "srcport", "%uS", "info", "%i"';
  foreach my $item (qw(ip.len tcp.len ip.hdr_len tcp.hdr_len)) {
    $command .= ", \"$item\", \"%Cus:$item\"";
  }

  #print $command, "\n";
  open(TSHARK, $command . "' | ");

  while(<TSHARK>) {
   #print;
    if (m|^\s*\d+\s+($myIp \d+)\s+.*\[SYN\].+Win=(\d+).+MSS=(\d+)|) {
      $client = $1;
      $data{$1}->{type} = 'client';
      maxValue($data{$1}, 'win', $2);
      maxValue($data{$1}, 'mss', $3);
    } elsif (m|^\s*\d+\s+(\S+\s+\d+)\s+.*\[SYN, ACK\].+Win=(\d+).+MSS=(\d+)|) {
      $server = $1;
      $data{$1}->{type} = 'server';
      maxValue($data{$1}, 'win', $2);
      maxValue($data{$1}, 'mss', $3);
    } elsif (m|^\s*\d+\s+(\S+\s+\d+)\s+.+\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$|) {
      #print "tcp $2 ip $3\n";
      print if ($3 > 1500);
      maxValue($data{$1}, 'iplen', $2);
      maxValue($data{$1}, 'tcplen', $3);
      maxValue($data{$1}, 'iphdrlen', $4);
      maxValue($data{$1}, 'tcphdrlen', $5);
    }
  }

  foreach my $key (keys %data) {
    my($ip, $port) = split(' ', $key);
    my $hostname = `host $ip`;
    $hostname =~ s/.+\s+(\S+)\.$/$1/;
    $data{$key}->{hostname} = $hostname;
  }

  #print Dumper(\%data);

  my $site = $ARGV[0];
  $site =~ s/.pcap//;
  my $stats = "$site";
  my $header = "site";
  foreach my $item (qw(iplen tcplen iphdrlen tcphdrlen mss win)) {
    $header .= "\t$item";
    $stats .= "\t$data{$server}->{$item}";
  }
  print "$header\n";
  print "$stats\n";
}

