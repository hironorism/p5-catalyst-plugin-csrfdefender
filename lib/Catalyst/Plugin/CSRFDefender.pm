package Catalyst::Plugin::CSRFDefender;

#
# almost all code from Amon2::Plugin::Web::CSRFDefender
# https://metacpan.org/pod/Amon2::Plugin::Web::CSRFDefender
#

use strict;
use warnings;
use MRO::Compat;
use Data::Dumper;
use MIME::Base64 ();
use Digest::SHA ();
use Time::HiRes;

our $URANDOM_FH;

our $ERROR_HTML = <<'...';
<!doctype html>
<html>
  <head>
    <title>403 Forbidden</title>
  </head>
  <body>
    <h1>403 Forbidden</h1>
    <p>
      Session validation failed.
    </p>
  </body>
</html>
...

# $URANDOM_FH is undef if there is no /dev/urandom
open $URANDOM_FH, '<:raw', '/dev/urandom'
    or do {
    undef $URANDOM_FH;
    warn "Cannot open /dev/urandom: $!.";
};

sub dispatch {
    my $c = shift;
    if (not $c->validate_csrf()) {
        $c->res->status(403);
        $c->res->content_type('text/plain');
        $c->res->body($ERROR_HTML);
        return;
    }
    return $c->next::method(@_);
}

sub finalize {
    my $c = shift;
    my $html = $c->res->body();

    my $no_csrf_token = $c->stash->{no_csrf_token} || $c->config->{no_csrf_token};
    if ($html && !$no_csrf_token) {
        # post only
        my $csrf_token = $c->stash->{csrf_token};
        my $form_regexp = $c->config->{post_only} ? qr{<form\s*.*?\s*method=['"]?post['"]?\s*.*?>}is : qr{<form\s*.*?>}is;
        $html =~ s!($form_regexp)!qq{$1\n<input type="hidden" name="csrf_token" value="}.$csrf_token.qq{" />}!ge;
        $c->res->body($html);
        $c->stash->{csrf_token} = $csrf_token;
    }
    return $c->next::method(@_);
};

sub generate_session_id {
    if ($URANDOM_FH) {
        my $length = 30;
        # Generate session id from /dev/urandom.
        my $read = read($URANDOM_FH, my $buf, $length);
        if ($read != $length) {
            die "Cannot read bytes from /dev/urandom: $!";
        }
        my $result = MIME::Base64::encode_base64($buf, '');
        $result =~ tr|+/=|\-_|d; # make it url safe
        return $result;
    } else {
        # It's weaker than above. But it's portable.
        return Digest::SHA::sha1_hex(rand() . $$ . {} . Time::HiRes::time());
    }
}

sub get_csrf_defender_token {
    my ($c) = @_;

    if (my $token = $c->session->{csrf_token}) {
        $token;
    } else {
        my $token = generate_session_id();
        $c->session->{csrf_token} = $token;
        $token;
    }
}

sub validate_csrf {
    my ($c) = @_;

    my $no_csrf_validate = $c->stash->{no_csrf_validate} || $c->config->{no_csrf_validate};
    if ( !$no_csrf_validate && $c->req->method eq 'POST' ) {
        my $r_token       = $c->req->param('csrf_token') || $c->req->header('x-csrf-token') || "";
        my $session_token = $c->session->{csrf_token} || "";

        # delete csrf_token param
        delete $c->req->params->{csrf_token};
        if ( !$r_token || !$session_token || ( $r_token ne $session_token ) ) {
            return 0; # bad
        }
    }
    return 1; # good
}

1;
