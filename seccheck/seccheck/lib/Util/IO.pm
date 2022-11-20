package Util::IO v0.0.3;

use v5.32;
use warnings;
use strict;
use autodie;

# import realpath function from Cwd module
use Cwd qw(realpath);

# export functions
use Exporter qw(import);

use File::Spec::Functions qw(abs2rel);

use FindBin qw($Bin);

# import LoadFile function from YAML module
use YAML qw(LoadFile);

# search for Perl modules under the '/lib' directory
#use lib "$Bin/lib";

our @EXPORT = qw($GENDOC $ROOT load_yaml relpath);

# AsciiDoc file path
my $GENDOC;

# root path
my $ROOT = realpath("$Bin/../../");

sub load_yaml {
    my $filename = shift;
    my $yaml = LoadFile($filename);
    return $yaml;
}


sub relpath {
    abs2rel(realpath(shift), $ROOT);
}


1;
__END__

=pod

=encoding utf8

=head1 NAME

IO.pm - Filesystem Input/Output Utility module.

=head1 VERSION

This document describes Util::IO version 0.3.

=head1 NOTE

Work in progress...

=head1 SYNOPSIS

use Util::IO qw(load_yaml);
...

=head1 ABSTRACT

...

=head1 DESCRIPTION

The Util::IO module contains I/O functions for logging,
debugging and manipulating file/dir paths on the filesystem.

=head1 INTERFACE

=over

=item Util::IO

    * load_yaml()

      Definition: Loads YAML file

      Input: Accepts $filename string
      Output: Returns YAML data

    * relpath()

      Definition: Converts absolute path to real path

      Input: Accepts path string
      Output: Returns path string

=back

=head1 AUTHOR INFORMATION

Koray Eyinç <korayeyinc@gmail.com>

=head1 BUGS

Please report them.

=cut
