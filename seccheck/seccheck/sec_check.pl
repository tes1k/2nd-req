#!/usr/bin/env perl

use v5.32;
use warnings;
use strict;


# search for Perl modules under the '/lib' directory
use FindBin qw($Bin);
use lib "$Bin/lib";

# auto-check package dependencies first
use Dep::Check;

# import traverse_dir and $GENDOC variable from Manifest::File module
use Manifest::File;

# import $ROOT from Util::IO module
use Util::Cmd;
use Util::IO qw($ROOT);


sub main {
    # parse command line options
    Util::Cmd::parse();

    # recursively scan the filesystem for installed libraries
    Manifest::File::traverse_dir($ROOT);

    # check if a dependency doesn't exist in any security manifest
    Manifest::File::check_dep();

    # clean up env and exit program
    Util::Cmd::exit();
}

main();

__END__

=pod

=encoding utf8

=head1 NAME

sec_check.pl - Command line tool developed for scanning the filesystem and
finding possible vulnerabilities/security issues within the installed libraries.

=head1 VERSION

This document describes sec_check version 0.3.

=head1 NOTE

Starting from v0.3, sec_check.pl prints all the outputs into log files by default.
Please check "data/logs" directory to see the log file contents.

=head1 SYNOPSIS

You can run sec_check.pl as follows:

$ perl sec_check.pl

This command saves all the outputs to log files by default.
There are 2 different types of log files in "data/logs" directory.

* The "report.log" file contains the main security information.

* The "debug.log" file contains extra debugging information.

Most of the times, the users can check report.log file first.
And then they can check debug.log file contents to analyze
the security issues in detail.

In order to specify name of the main log file,
you can run sec_check.pl with the filename parameter as follows:

$ perl sec_check.pl --log sec_report.log

=head1 ABSTRACT

...

=head1 DESCRIPTION

This command line tool - "sec_check.pl" is developed for scanning the filesystem and
finding possible vulnerabilities/security issues within the installed libraries -
which affect jdelog.

Please check embedded documentation for the submodules residing inside "/lib" directory for more information.
You can use perldoc utility for displaying the embedded documentation within the respective submodule.

The following command displays embedded documentation:

$ perldoc sec_check.pl

For displaying documentation embedded inside a module:

$ cd lib/Util/IO

$ perldoc IO.pm

=head1 INTERFACE

=over

=item MAIN

    * main

      Definition: Recursively scans the filesystem for installed libraries and manifests.
      Then runs the routine checks sequentially.

=back

=head1 AUTHOR INFORMATION


=head1 BUGS

Please report them.

=cut
