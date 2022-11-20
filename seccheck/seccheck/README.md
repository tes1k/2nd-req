# sec_check.pl
Command line tool developed for scanning the filesystem and
finding possible vulnerabilities/security issues within the installed libraries -
affecting jdelog.

Note: Work in progress

## Viewing Documentation

### Using perldoc

```sh
$ perldoc sec_check.pl
```

### Using command line

```sh
usage: PROG [ --log <filename> | --help | --usage ]

optional arguments:
  --help                Show this help message and exit.
  --log                 Generate a log file in plain text format with the list and
                        description of the vulnerabilities affecting jdelog.
  --usage               Show this help message and exit.
```

## Usage

```sh
perl sec_check.pl
```

### To specify the log filename, please issue the following command:

```sh
perl sec_check.pl --log sec_report.log
```

## Requirements

Perl:
* Perl version 5.32 (minimum Perl version)

Perl modules:
* libyaml-perl (https://metacpan.org/release/YAML)

## Installation

Debian/Ubuntu:
```sh
# apt install libyaml-perl
```

RedHat:
```sh
# yum install perl-YAML
```

Arch:
```sh
# pacman -Sy perl-yaml
```

MSYS2:
```sh
\$ pacman -Sy perl-YAML
```

FreeBSD:
```sh
# pkg install textproc/p5-YAML
```

If packaged version is not available on your system, try running as root:
```sh
# cpan -i YAML
```

## TODO
* Fix AsciiDoc generation functionality.
* More documentation to be added.
* Complete the implementation of OSV::Client submodule.
* Write test scripts.
