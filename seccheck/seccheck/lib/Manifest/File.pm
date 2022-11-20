package Manifest::File v0.0.3;

use v5.32;
use warnings FATAL => "all";
use strict;

use HTTP::Tiny;
use List::Util qw(any);
use POSIX qw(strftime mktime);
use Exporter qw(import);

# search for Perl modules under the '/lib' directory
use FindBin qw($Bin);
use lib "$Bin/lib";


# import get_cves from NVD::Client
use NVD::Client qw(get_cves);

# import post_req function from OSV::Client module
# use OSV::Client qw(post_req);

use Util::Cmd qw(log_line log_debug);
use Util::IO qw($GENDOC  relpath load_yaml);

# export symbols from package
our @EXPORT = qw(check_dep gendoc traverse_dir);

# set timing of periodic CVE reviews
my $REVIEW_EVERY_MONTHS = 2;

# Maps build identifier from build definition to a human-readable build name
# (which is later included into the documentation)

my %BUILD_NAMES = (
    'ALL'             => 'All',
    'aix'             => 'AIX',
    'aix6'            => 'AIX 6',
    'fbsd11-amd64'    => 'FreeBSD 11 x64',
    'generic'         => 'Generic RPM and DEB',
    'generic-glibc25' => 'Generic GLIBC 2.5',
    'macos'           => 'MacOS',
    'macos-arm64'     => 'MacOS x64',
    'solaris10-sparc' => 'Solaris 10 SPARC',
    'solaris10-i386'  => 'Solaris 10 i386',
    'win64'           => 'Windows x64',
);


# Manifest validation schema is pretty self-explaining.
# Types supported are: string, array, hashmap.
# 'match' is a regex. Use qr/./ as 'non-empty' condition.
# For 'array' type with 'match' directive, every element of array is checked against 'match' expression.
# 'schema' defines sub-schema for 'hashmap' and 'array' types.

my $MANIFEST_SCHEMA = {
    name        => { required => 1,                                   type => 'string',              match => qr/./                             },
    cpe23       => {                                                  type => 'string',              match => qr/^cpe:2\.3:[aoh]:[\w-]*:[\w-]+/ },
    type        => { required => 1,                                   type => 'string',              match => qr/^(?:external|embedded)$/       },
    buildSource => { required => sub { $_[0]->{type} eq 'external' }, type => [ 'string', 'array' ], match => qr/^\w+$/                         },
    version     => { required => sub { $_[0]->{type} eq 'embedded' }, type => [ 'string', 'array' ], match => qr/./                             },
    versionMap  => {                                                  type => [ 'string', 'array' ], match => qr/^[\w\.-]+\s*->\s*[\w\.-]+$/    },
    reviewer    => { required => sub { !$_[0]->{cpe23} },             type => 'string',              match => qr/@/                             },
    reviewDate  => { required => sub { !$_[0]->{cpe23} },             type => 'string',              match => qr/^\d{4}-\d\d-\d\d$/             },
    comment     => {                                                  type => 'string'                                                          },
    CVEs        => { type => 'hashmap', keymatch => qr/^CVE-\d{4}-\d{4,}$/, schema => {
    status      => { required => 1, type => 'string', match => qr/^(?:Not\sapplicable|Observed|Active)$/i },
    description => { required => 1, type => 'string', match => qr/./                                      },
    reviewer    => { required => 1, type => 'string', match => qr/@/                                      },
    reviewDate  => { required => 1, type => 'string', match => qr/^\d{4}-\d\d-\d\d$/                      },
    comment     => {                type => 'string'                                                      },

    } }
};

my $NOW = strftime('%Y-%m-%d', localtime);

# set YAML build definition file path below
my $builddef_path = "$Bin/data/jdelog_build_definition_strategicmate.yml";

# try loading YAML file
my $builddef = load_yaml($builddef_path)
    or die "Cannot read build definition $builddef_path\n";

# Hash linking sourceset to an array of builds it is included in
# e.g. oldssl => [ aix, aix6 ]
my %sourceset_to_builds;

push $sourceset_to_builds{ $_->{(keys(%$_))[0]}{sourceSet} }->@*, (keys(%$_))[0]
    for $builddef->{deps}{binary}->@*;

# Hashset linking library identifier (buildSource, in terms of security manifest),
# its version and sourceset
# e.g. $libinfo{openssl10}{1.0.2u}{oldssl} = 1

my %libinfo;

while ( my ( $libid, $ver ) = each $builddef->{deps}{source}{default}->%* ) {
    $ver =~ s/^=//;
    $libinfo{$libid}{$ver}{default} = 1;
}


while ( my ( $sset, $libs ) = each $builddef->{deps}{source}{sets}->%* ) {
    while ( my ( $libid, $ver ) = each %$libs ) {
        $ver =~ s/^=//;
        $libinfo{$libid}{$ver}{$sset} = 1;
    }
}


# Maps type from validation schema to Perl reference type
my %TYPEMAP = (
    'string'  => '',
    'array'   => 'ARRAY',
    'hashmap' => 'HASH',
);


sub validate_manifest {
    my ( $manifest_clause, $manifest, $schema ) = @_;

    for my $k ( keys %$schema ) {
        my $sch = $schema->{$k};

        die "Required key '$k' is absent in $manifest_clause\n"
            if !ref $sch->{required} && $sch->{required} && !exists $manifest->{$k} ||
               ref $sch->{required} eq 'CODE' && $sch->{required}->($manifest) && !exists $manifest->{$k};
    }

    for my $k ( keys %$manifest ) {
        my $sch = $schema->{$k};
        die "Key '$k' is not known in $manifest_clause\n" unless $sch;

        my %types;

        if ( !ref $sch->{type} ) {
            $types{ $TYPEMAP{ $sch->{type} } } = 1;
        } elsif ( ref $sch->{type} eq 'ARRAY' ) {
            $types{ $TYPEMAP{$_} } = 1 for $sch->{type}->@*;
        }

        die "Value type for key '$k' is not valid in $manifest_clause\n"
            unless $types { ref $manifest->{$k} };

        my $validate_scalar = sub {
            my ( $sch, $val ) = @_;
            die "Value '$val' is not valid for key '$k' in $manifest_clause\n"
                if $sch->{match} && $val !~ $sch->{match};
        };

        if ( !ref $manifest->{$k} ) {
            $validate_scalar->( $sch, $manifest->{$k} );
        } elsif ( ref $manifest->{$k} eq 'ARRAY' ) {
            for ( $manifest->{$k}->@* ) {
                if ( $sch->{schema} ) {
                    validate_manifest($manifest_clause, $_, $sch->{schema} );
                } else {
                    $validate_scalar->($sch, $_);
                }
            }
        } elsif ( ref $manifest->{$k} eq 'HASH' ) {
            while ( my ( $hk, $hv ) = each $manifest->{$k}->%* ) {
                die "Key '$hk' under '$k' is not valid in $manifest_clause\n"
                if $sch->{keymatch} && $hk !~ $sch->{keymatch};

                validate_manifest($manifest_clause, $manifest->{$k}{$hk}, $sch->{schema}) if $sch->{schema};
            }
        }
    }
}


# Given CVE's {description}{description_data}, returns a human-readable string
# describing a vulnerability, by the way hacking CVE markdown to present a
# valid AsciiDoc
sub format_description {
    my $desc = shift;
    my $res;

    for (@$desc) {
        $res = $_->{value} and last if $_->{lang} eq 'en';
    }

    unless ($res) {
        for (@$desc) {
            $res = $_->{value} and last if !$_->{lang};
        }

        $res = $desc->[0]{value} unless $res; # Better than nothing
    }

    $res =~ s/~/\\~/g;
    return $res;
}


my %libids_met;
my @generated_docs;


sub gendoc {
    my ( $cveid, $manifest, $builds, $descr ) = @_;

    my $res = "=== https://nvd.nist.gov/vuln/detail/${cveid}[$cveid]\n\n";

    $res .= "Component affected:: $manifest->{name}\n\n";
    $res .= "Builds affected:: " . join(', ', map { $BUILD_NAMES{$_} // $_ } @$builds) . "\n\n";
    $res .= "$descr\n\n";
    $res .= "'''\n\n";

    return $res;
}


# Given a manifest, extracts all the library identifiers (buildSource-s) from
# it, marks them met and returns them as a list
sub getmark_libs {
    my $manifest = shift;

    if ( $manifest->{buildSource} ) {
        my @libids
            = ref $manifest->{buildSource} eq 'ARRAY'
            ? $manifest->{buildSource}->@*
            : ( $manifest->{buildSource} );

        $libids_met{$_} = 1 for @libids;

        return @libids;
    }

    ();
}


# Given a manifest, returns a reference to a hash mapping library versions to
# an array of build identifiers which are using that version
sub versions_builds {
    my $manifest = shift;
    my ( %versions, @versions, %version_to_sourcesets, %version_map );

    if ( $manifest->{type} eq 'external' ) {
        for my $libid ( getmark_libs($manifest) ) {
            for my $ver ( keys $libinfo{$libid}->%* )
            {
            $ver =~ s/^=//;
            push @versions, $ver;
            $version_to_sourcesets{$ver} = $libinfo{$libid}{$ver};
            }
        }
    } elsif ( $manifest->{type} eq 'embedded' ) {
        @versions = ref $manifest->{version} eq 'ARRAY'
        ? $manifest->{version}->@*
        : ( $manifest->{version} );
    }

    if ( $manifest->{versionMap} ) {
        my @version_map = ref $manifest->{versionMap} eq 'ARRAY'
            ? $manifest->{versionMap}->@*
            : ( $manifest->{versionMap} );

        for (@version_map) {
            my ( $from, $to ) = /^([\w\.-]+)\s*->\s*([\w\.-]+)$/;
            $version_map{$from} = $to;
        }
    }

    for my $ver (@versions) {
        my @builds_affected = ('ALL');

        if ( $manifest->{type} eq 'external' && !$version_to_sourcesets{$ver}{default} ) {
            my %builds;

            for my $sourceset ( keys $version_to_sourcesets{$ver}->%* ) {
                $builds{$_} = 1 for $sourceset_to_builds{$sourceset}->@*;
            }

            @builds_affected = sort keys %builds;
        }

        $versions{ $version_map{$ver} // $ver } = \@builds_affected;
    }

    return \%versions;
}


# Given a review date (YYYY-MM-DD string) calculates the next review date,
# adding $REVIEW_EVERY_MONTHS months
sub next_review_date {
    my @review_date = split /-/, shift;

    strftime( '%Y-%m-%d', localtime(
        mktime(
            0, 0, 0, $review_date[2],
            $review_date[1] - 1 + $REVIEW_EVERY_MONTHS,
            $review_date[0] - 1900
        )
    ));
}


# Performs checks of single manifest. Parameters are manifest itself and
# manifest file path (for logging). Dies on faiulre. Return value is undefined.
sub run_manifest_check {
    my ( $manifest, $manifest_relpath ) = @_;

    unless ( $manifest->{cpe23} ) {
        log_debug("Found managed dependency '$manifest->{name}' without a CPE");

        # Just mark libs as met
        getmark_libs($manifest);

        log_line( "Manifest for '$manifest->{name}' in $manifest_relpath has a review date in the future")
            if $manifest->{reviewDate} gt $NOW;

        my $next_review_date = next_review_date($manifest->{reviewDate});

        log_debug( "  Next review date: $next_review_date" );

        log_line( "Manifest for '$manifest->{name}' in $manifest_relpath should be reviewed as of $next_review_date" )
            if $NOW ge $next_review_date;

        return;
    }

    my @cpe_query = split /:/, $manifest->{cpe23};
    my $versions  = versions_builds($manifest);

    for my $ver ( sort keys %$versions ) {
        my $cpe = join ':', @cpe_query[ 0 .. 4 ], $ver;
        log_debug "  Requesting CVEs with CPE $cpe for '$manifest->{name}' version $ver";
        my $cves = get_cves($cpe);

        if ( $cves->{totalResults} ) {
            for my $cve ( $cves->{result}{CVE_Items}->@* ) {
                my $cveid = $cve->{cve}{CVE_data_meta}{ID};

                if ( $manifest->{CVEs} && $manifest->{CVEs}{$cveid} ) {
                    log_debug( "    Found managed $cveid" );

                    if ( any { $manifest->{CVEs}{$cveid}{status} eq $_ } qw(Active Observed) ) {
                        log_line( "$cveid for '$manifest->{name}' in $manifest_relpath has a review date in the future" )
                            if $manifest->{CVEs}{$cveid}{reviewDate} gt $NOW;

                        my $next_review_date = next_review_date( $manifest->{CVEs}{$cveid}{reviewDate} );

                        log_debug( "    Next review date: $next_review_date" );

                        log_line( "$cveid for '$manifest->{name}' in $manifest_relpath should be reviewed as of $next_review_date" )
                            if $NOW ge $next_review_date;
                    }

                    if ( $manifest->{CVEs}{$cveid}{status} eq 'Active' && $GENDOC ) {
                        my $descr = format_description($cve->{cve}{description}{description_data});
                        push @generated_docs, gendoc($cveid, $manifest, $versions->{$ver}, $descr);
                    }
                } else {
                    log_line( "Unmanaged $cveid found for '$manifest->{name}', version $ver, in $manifest_relpath, " .
                              "builds affected: " . join( ', ', $versions->{$ver}->@* ) .
                              " (see https://nvd.nist.gov/vuln/detail/$cveid)" );
                }
            }
        }
    }
}


sub traverse_dir {
    my $dir = shift;

    if (defined $dir) {
        log_debug("Entering $dir");
        process_dir($dir);
    } else {
        return;
    }

    opendir(my $dh, $dir) or die "Cannot open $dir: $!\n";

    while ( readdir $dh ) {
        next if /^\./;
        my $entry = "$dir/$_";
        traverse_dir($entry) if -d $entry;
    }

    closedir $dh;
}


sub process_dir {
    my $dir = shift;
    my $manifest_file = "./SecurityManifest.yml";

    if (defined $dir) {
        $manifest_file = "$dir/SecurityManifest.yml";
    }

    log_debug("  No manifest file found"), return unless -f $manifest_file;

    my $manifest_relpath = relpath($manifest_file);
    my @manifests = YAML::LoadFile($manifest_file) or die "Cannot read $manifest_relpath\n";
    die "Empty security manifest $manifest_relpath\n" unless @manifests;

    for my $manifest (@manifests) {
        next unless %$manifest; # Allow totally empty manifests, as a separator

        my $manifest_clause = (
            $manifest->{name} && !ref $manifest->{name}
            ? "manifest '$manifest->{name}'"
            : 'unnamed manifest'
        ) . " in $manifest_relpath";

        validate_manifest($manifest_clause, $manifest, $MANIFEST_SCHEMA);
        run_manifest_check($manifest, $manifest_relpath);
    }
}


sub check_dep {
    for (keys %libinfo) {
        log_line( "Build dependency '$_' is mentioned in the build definition but is not managed by any security manifest" )
            unless $libids_met{$_};
    }

    if ($GENDOC) {
        open my $outfh, '>', $GENDOC or die "Cannot open $GENDOC for writing: $!\n";
        print $outfh $_ for @generated_docs;
        close $outfh;
    }
}

1;
__END__

=pod

=encoding utf8

=head1 NAME

File.pm - Manifest::File module.

=head1 VERSION

This document describes Manifest::File version 0.3.

=head1 NOTE

While scanning the directories for manifest files,
the hidden directories (starting with '.') are ignored.

=head1 SYNOPSIS

use Manifest::File qw(traverse_dir);
...

=head1 ABSTRACT

...

=head1 DESCRIPTION

The Manifest::File module manages/updates manifest files.
This Perl module provides all the required functionality
to manage, update and generate manifest files.

It checks if a manifest file exists for the relevant library/package.
If it can't find one, then it fetches an updated version of the manifest file
from OSV database.

=head1 INTERFACE

=over

=item Manifest::File

    * check_dep()

      Definition: Check if there's a dependency in build definition
                  which is not present in any security manifest.

      Input:  ...
      Output: ...

    * gendoc()

      Definition: Generates AsciiDoc documentation snippet for a single CVE.

      Input: Accepts $cveid, $manifest, $builds, $descr strings
      Output: Generates response string as a CVE report

    * process_dir()

      Definition: Processes a single directory. Silently returns if no manifest file found.
                  Dies if manifest file is empty, unreadable or is not a valid YAML, or
                  if it fails to validate the manifest. Found problems are logged to STDERR.

      Input:  Accepts $dir string representing the directory path
      Output: ...

    * traverse_dir()

      Definition: Traverses directory tree, calling process_dir() for every directory

      Input:  Accepts $dir string representing the directory path
      Output: ...

    * validate_manifest()

      Definition: Validates a single manifest. Dies on failure.

      Input:  Accepts $manifest_clause, $manifest, $schema strings
      Output: ...

=back

=head1 AUTHOR INFORMATION

Koray Eyinç <korayeyinc@gmail.com>

=head1 BUGS

Please report them.

=cut
