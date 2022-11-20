package Util::Cmd v0.0.3;

use v5.32;
use warnings;
use strict;

use Exporter qw(import);
use FindBin qw($Bin);

# import Getopt modules to parse cdommand line parameters
use Getopt::Long qw(GetOptions);

use Pod::Usage qw(pod2usage);
use POSIX qw(strftime);

our @EXPORT = qw(log_debug log_line parse exit);

# log file path
my $LOG_PATH;

# log file content
my $LOG;

# problem counter
my $PCNT = 0;

my $file;


sub parse {
    my $help = 0;
    my $usage = 0;

    GetOptions('log=s' => \$LOG_PATH,# 'gendoc=s' => \$GENDOC,
               'help|usage' => \&pod2usage) or pod2usage(2);

    pod2usage(1) if $help;
    pod2usage(-verbose => 2) if $usage;
    #pod2usage("[info] $0: No file parameter supplied!\n")  if ((@ARGV == 0) && (-t STDIN));

    open_log();
    open_debug();
}


sub log_debug {
    my $line = shift;
    say $file $line;
}


sub open_debug {
    my $path = "data/logs/debug.log";
    open($file, ">>", $path);
    my $date_time = strftime "[%Y.%m.%0e-%H:%M:%S]", localtime;
    my $line = "\n[INFO] Started debugging on " . $date_time . "\n";
    say $file $line;
}


sub log_line {
    if (defined $LOG) {
        say $LOG "PROBLEM #" . (++$PCNT) . ": $_[0]";
    }
}


sub open_log {
    $LOG_PATH = "data/logs/report.log" unless defined $LOG_PATH;
    open($LOG, ">>", $LOG_PATH);

    my $date_time = strftime "[%Y.%m.%0e-%H:%M:%S]", localtime;
    my $msg = "\n[INFO] Started security check on " . $date_time . "\n";
    say $LOG $msg;
}


sub exit {
    close $LOG if defined $LOG;
    # print a warning and exit program
    # if any issues are found after the filesystem scan
    if (defined $PCNT) {
        say "[info] Security issues or vulnerabilities found!";
        say "[info] Please check the log files in '$Bin/data/logs/' directory for more information.";
        exit 1;
    }
}

1;
__END__

=pod

=encoding utf8

=head1 NAME

Cmd.pm - command line usage/documentation module.

=head1 VERSION

This document describes Util::Cmd version 0.3.

=head1 NOTE

Work in progress...

=head1 SYNOPSIS

use Util::Cmd;
...

=head1 ABSTRACT

...

=head1 DESCRIPTION

The Util::Cmd module parses command line parameters and
displays command line usage/documentation.

=head1 INTERFACE

=over

=item Util::Cmd

    * log_debug()

      Definition: Logs debug info to 'data/debug.log'.

      Input: Accepts $line string
      Output: ...

    * log_line()

      Definition: Logs issue info to 'data/report.log'.

      Input: Accepts $line string
      Output: ...

    * parse()

      Definition: Parses command line parameters and displays command usage.

      Input:  Not required
      Output: Prints command line usage docs

    * exit()

      Definition: Cleans up the environment and exit the program.

=back

=head1 AUTHOR INFORMATION

Koray Eyinç <korayeyinc@gmail.com>

=head1 BUGS

Please report them.

=cut
