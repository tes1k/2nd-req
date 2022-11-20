package OSV::Client v0.0.3;

use v5.32;
use warnings;
use strict;

use Data::Dumper;
use HTTP::Tiny;
use JSON::PP qw(encode_json decode_json);
use Exporter qw(import);

our @EXPORT = qw(post_req);


# Sends POST request to API URL
sub post_req {
    my $pkg_name = shift;
    my $ecosys   = shift;
    my $ver_str  = shift;

    my $url  = "https://api.osv.dev/v1/query";

    my $headers = {
        'Accept'       => "application/json",
        'Content-Type' => "application/json"
    };

    my $data = {
        "version" => $ver_str,
        "package" => {
            "name" => $pkg_name,
            "ecosystem" => $ecosys
        }
    };

    my $client = HTTP::Tiny->new;

    my $res = $client->post( $url => {
        content => encode_json($data),
        headers => $headers
    });

    return $res;
}

1;
__END__

=pod

=encoding utf8

=head1 NAME

Client.pm - OSV client module.

=head1 VERSION

This document describes OSV::Client version 0.3.

=head1 NOTE

Work in progress...

=head1 SYNOPSIS

use OSV::Client;
...

=head1 ABSTRACT

...

=head1 DESCRIPTION

The OSV::Client module acts as an OSV client to query OSV API via HTTP and
fetch package CVE data as JSON.

The "package name, version and ecosystem" fields must be specified
inside the request object before posting HTTP requests to OSV API.

If the response from the OSV API contains a malformed or empty JSON data, -
the current request is accepted as a failure. Then the code throws an exception and exits.

The response is a JSON object - from which package CVE info can be extracted.

=head1 INTERFACE

=over

=item

    * post_req()
      Definition: Sends a post request and queries the OSV API
      Input: Accepts $pkg_name, $ecosys, $ver_str parameters
      Output: Returns JSON data/response object

=back

=head1 AUTHOR INFORMATION

Koray Eyinç <korayeyinc@gmail.com>

=head1 BUGS

Please report them.

=cut
