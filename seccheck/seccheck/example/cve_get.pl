#!/usr/bin/env perl

use v5.32;
use warnings;
use strict;

use Data::Dumper;
use HTTP::Tiny;
use JSON::PP qw(encode_json decode_json);


# Sends POST request to API URL
sub post_req {
    my $url  = "https://api.osv.dev/v1/query";

    my $headers = {
        'Accept'       => "application/json",
        'Content-Type' => "application/json"
    };

    my $data = {
        "version" => "1.4.2",
        "package" => {
            "name" => "yajl-ruby",
            "ecosystem" => "RubyGems"
        }
    };

    my $client = HTTP::Tiny->new;

    my $res = $client->post( $url => {
        content => encode_json($data),
        headers => $headers
    });

    return $res;
}


sub main {
    my $res = post_req();

    if ( $res->{'success'} ) {
        my $data = decode_json($res->{content});
        say Dumper $data;
    } else {
        warn 'Bad JSON response!';
    }
}


main();

__END__

=pod

=encoding utf8

=head1 NAME

cve_get.pl - a simple OSV client example.

=head1 SYNOPSIS

This simple OSV client is written for demonstrating how to query OSV API via HTTP and
fetch a particular package CVE data as JSON.

=head1 ABSTRACT

=head1 DESCRIPTION

The "package name, version and ecosystem" fields must be specified
inside the HTTP request before posting request to OSV API endpoint.

The response is a JSON object - from which package data can be extracted.

=head1 INTERFACE

=over

=item

    * post_req()
      Definition: Sends a post request to the OSV API.
      Input: Not required
      Output: JSON response object

=back

=head1 AUTHOR INFORMATION



=head1 BUGS

Please report them.

=cut
