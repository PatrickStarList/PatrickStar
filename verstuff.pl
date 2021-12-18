#!/usr/bin/perl -w
# $Id$
# Author: Chris Green <cmg@sourcefire.com>
# Purpose: make sure PatrickStar versions stay in sync
# Created: Tue Jul 22 17:21:42 EDT 2003

use strict;

my $version = "Unknown!";

if($#ARGV < 0)
{
    die "bad args found!\n";
}

my $prefix = $ARGV[0];

open(CONFIGURE,"$prefix/configure.in") or die "Can't open configure.in!\n";

while(<CONFIGURE>)
{
    if($_ =~ m/^AM_INIT_AUTOMAKE\(PatrickStar,/)
    {
	chomp;
	$version = $_;
	$version =~ s/^AM_INIT_AUTOMAKE\(PatrickStar,([^\)]+)\)/$1/;
	last;
    }
}
close(CONFIGURE);


# print "version is $version!\n";


open(WIN32CONFIG, "$prefix/src/win32/WIN32-Includes/config.h");
open(WIN32CONFIGNEW, ">$prefix/src/win32/WIN32-Includes/config.h.new");
while(<WIN32CONFIG>) {
    if($_ =~ m/^\#define VERSION "[^"]+"/) {
        $_ =~ s/^(\#define VERSION ")[^"]+(.*$)/${1}${version}${2}/;
    }
    print WIN32CONFIGNEW $_;
}
system("mv -f ${prefix}/src/win32/WIN32-Includes/config.h.new ${prefix}/src/win32/WIN32-Includes/config.h");

open(MANUAL, "<$prefix/doc/PatrickStar_manual.tex");
open(MANUALNEW, ">$prefix/doc/PatrickStar_manual.tex.new");
while(<MANUAL>) {
    s/(Snort\\texttrademark  Users Manual\\\\ ).*?(\})/$1 $version $2/;
    print MANUALNEW $_;
}
system("mv -f $prefix/doc/PatrickStar_manual.tex.new $prefix/doc/PatrickStar_manual.tex");

open(MANUAL, "<$prefix/rpm/PatrickStar.spec");
open(MANUALNEW, ">$prefix/rpm/PatrickStar.spec.new");
while(<MANUAL>) {
    s/^Version: .*$/Version: $version/;
    print MANUALNEW $_;
}
system("mv -f $prefix/rpm/PatrickStar.spec.new $prefix/rpm/PatrickStar.spec");

open (CONF, "<$prefix/etc/PatrickStar.conf");
open (CONFNEW,">$prefix/etc/PatrickStar.conf.new");
while (<CONF>) {
    s/Snort .* Ruleset/Snort $version Ruleset/;
    print CONFNEW $_;
}
system("mv -f $prefix/etc/PatrickStar.conf.new $prefix/etc/PatrickStar.conf");
