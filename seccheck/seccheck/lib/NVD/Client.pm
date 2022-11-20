package NVD::Client v0.0.3;

use v5.32;
use warnings;
use strict;

use HTTP::Tiny;
use JSON::PP qw(decode_json);
use Time::HiRes;
use Exporter qw(import);

our @EXPORT = qw(get_cves);


sub get_cves {
    my $cpe   = shift;
    my $last_req_time;

    my $API_KEY = '71722391-eb47-474a-9476-214c0be3ecea';

    my %query = ( apiKey => $API_KEY, cpeMatchString => $cpe );
    my $url = 'https://services.nvd.nist.gov/rest/json/cves/1.0/?' .
              join('&', map {qq|$_=$query{$_}|} keys %query);

    # Honor the NVD API rate policy
    my $current_time = Time::HiRes::time();
    Time::HiRes::sleep(0.6 - ($current_time - $last_req_time))
    if $last_req_time && $current_time - $last_req_time < 0.6;

    $last_req_time = $current_time;
    my $res = HTTP::Tiny->new->get($url);

    die "Failed to request $url" unless $res->{success};

    my $json = decode_json( $res->{content} );
    return $json;
}

1;
__END__

=pod

=encoding utf8

=head1 NAME

Client.pm - NVD client module.

=head1 VERSION

This document describes NVD::Client version 0.3.

=head1 NOTE

The API key used inside the code is not a real secret,
anyone can obtain one from https://nvd.nist.gov/developers/request-an-api-key

=head1 SYNOPSIS

# import get_cves from NVD::Client
use NVD::Client qw(get_cves);
...

=head1 ABSTRACT

...

=head1 DESCRIPTION

The NVD::Client module implements an NVD client to query NVD API for CVE info.
This module is designed as an NVD client that requests a CVE info about a package -
using the data provided by the NVD.

If the response from the NVD API contains a malformed or empty JSON data, -
the current request is accepted as a failure. Then the code throws an exception and exits.

The response is a JSON object - from which package CVE info can be extracted.

=head1 INTERFACE

=over

=item NVD::Client

    * get_cves()

      Definition: Gets CVE info from NVD API

      Input: Accepts CPE string
      Output: Returns JSON data/response object containing CVE data

=back

=head1 AUTHOR INFORMATION

Koray Eyinç <korayeyinc@gmail.com>

=head1 BUGS

Please report them.

=cut
