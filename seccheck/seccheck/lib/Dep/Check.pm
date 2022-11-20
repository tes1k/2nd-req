package Dep::Check v0.0.3;

use v5.32;
use warnings;
use strict;


INIT {
    eval 'use YAML';
    if ( $@ ) {
        die <<EOF
YAML package not found. Please install it to be able to run this script as following:

Ubuntu/Debian: # apt install libyaml-perl
RedHat:        # yum install perl-YAML
Arch:          # pacman -Sy perl-yaml
MSYS2:         \$ pacman -Sy perl-YAML
FreeBSD:       # pkg install textproc/p5-YAML

If packaged version is not available on your system, try running as root:

# cpan -i YAML

EOF
    }
}

1;
__END__

=pod

=encoding utf8

=head1 NAME

Check.pm - package dependency checker module.

=head1 VERSION

This document describes Dep::Check version 0.3.

=head1 NOTE

YAML is the only package used which do not reside in core library.
Please see README.md file for more information.

=head1 SYNOPSIS

use Dep::Check;
...

=head1 ABSTRACT

=head1 DESCRIPTION

The Dep::Check module checks if required package
dependencies are met on the current system.

The INIT block runs at compile time to check package dependencies.
Importing this module at the beginning runs the dependency check automatically.

=head1 INTERFACE

=over

=item Dep::Check

    * INIT

      Definition: The INIT block is run at compile time.

=back

=head1 AUTHOR INFORMATION

Koray Eyinç <korayeyinc@gmail.com>

=head1 BUGS

Please report them.

=cut
