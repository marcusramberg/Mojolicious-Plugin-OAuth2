package Mojolicious::Plugin::OAuth2::Mock;
use Mojo::Base -base;

require Mojolicious::Plugin::OAuth2;

use constant DEBUG => $ENV{MOJO_OAUTH2_DEBUG} || 0;

has provider => sub {
  return {
    authorization_endpoint_url => '/mocked/oauth2/authorize',
    end_session_endpoint_url   => '/mocked/oauth2/logout',
    issuer_url                 => '/mocked/oauth2/v2.0',
    jwks_url                   => '/mocked/oauth2/keys',
    return_code                => 'fake_code',
    return_token               => 'fake_token',
    token_endpoint_url         => '/mocked/oauth2/token',
  };
};

has _rsa => sub { require Crypt::OpenSSL::RSA; Crypt::OpenSSL::RSA->generate_key(2048) };

sub apply_to {
  my $self = ref $_[0] ? shift : shift->SUPER::new;
  my ($app, $provider) = @_;

  map { $self->provider->{$_} = $provider->{$_} } keys %$provider if $provider;
  push @{$app->renderer->classes}, __PACKAGE__;

  # Add mocked routes for "authorize", "token", ...
  for my $k (keys %{$self->provider}) {
    next unless $k =~ m!^([a-z].+)_url$!;
    my $method = "_action_$1";
    my $url    = $self->provider->{$k};
    warn "[Oauth2::Mock] $url => $method()\n" if DEBUG;
    $app->routes->any($url => sub { $self->$method(@_) });
  }
}

sub _action_authorization_endpoint {
  my ($self, $c) = @_;

  if ($c->param('response_mode') eq 'form_post') {
    return $c->render(
      template     => 'oauth2/mock/form_post',
      format       => 'html',
      code         => "authorize-code",
      redirect_uri => $c->param('redirect_uri'),
      state        => $c->param('state')
    );
  }

  # $c->param('response_mode') eq 'query'
  my $url = Mojo::URL->new($c->param('redirect_uri'));
  $url->query({code => 'authorize-code', state => $c->param('state')});
  return $c->redirect_to($url);
}

sub _action_authorize {
  my ($self, $c) = @_;

  if ($c->param('client_id') and $c->param('redirect_uri')) {
    my $url = Mojo::URL->new($c->param('redirect_uri'));
    $url->query->append(code => $self->provider->{return_code});
    $c->render(text => $c->tag('a', href => $url, sub {'Connect'}));
  }
  else {
    $c->render(text => "Invalid request\n", status => 400);
  }
}

sub _action_end_session_endpoint {
  my ($self, $c) = @_;
  my $rp_url = Mojo::URL->new($c->param('post_logout_redirect_uri'))
    ->query({id_token_hint => $c->param('id_token_hint'), state => $c->param('state')});
  $c->redirect_to($rp_url);
}

sub _action_issuer {
  my ($self, $c) = @_;
}

sub _action_jwks {
  my ($self, $c) = @_;

  my ($n, $e) = $self->_rsa->get_key_parameters;
  my $x5c = $self->_rsa->get_public_key_string;
  $x5c =~ s/\n/\\n/g;

  require MIME::Base64;
  return $c->render(
    template => 'oauth2/mock/keys',
    format   => 'json',
    n        => MIME::Base64::encode_base64url($n->to_bin),
    e        => MIME::Base64::encode_base64url($e->to_bin),
    x5c      => $x5c,
    issuer   => $c->url_for($self->provider->{issuer_url})->to_abs,
  );
}

sub _action_token {
  my ($self, $c) = @_;

  return $c->render(text => 'FAIL OVERFLOW', status => 404)
    unless 3 == grep { $c->param($_) } qw(client_secret redirect_uri code);

  $c->render(
    text => Mojo::Parameters->new(
      access_token  => $self->provider->{return_token},
      expires_in    => 3600,
      refresh_token => Mojo::Util::md5_sum(rand),
      scope         => $self->provider->{scopes} || 'some list of scopes',
      token_type    => 'bearer',
    )->to_string
  );
}

sub _action_token_endpoint {
  my ($self, $c) = @_;
  return $c->render(json => {error => 'invalid_request'}, status => 500)
    unless (($c->param('client_secret') and $c->param('redirect_uri') and $c->param('code'))
    || ($c->param('grant_type') eq 'refresh_token' and $c->param('refresh_token')));

  my $claims = {
    aud                => $c->param('client_id'),
    email              => 'foo.bar@example.com',
    iss                => $c->url_for($self->provider->{issuer_url})->to_abs,
    name               => 'foo bar',
    preferred_username => 'foo.bar@example.com',
    sub                => 'foo.bar'
  };

  require Mojo::JWT;
  my $id_token = Mojo::JWT->new(
    algorithm => 'RS256',
    secret    => $self->_rsa->get_private_key_string,
    set_iat   => 1,
    claims    => $claims,
    header    => {kid => 'TEST_SIGNING_KEY'}
  );

  return $c->render(
    template      => 'oauth2/mock/token',
    format        => 'json',
    id_token      => $id_token->expires(Mojo::JWT->now + 3600)->encode,
    refresh_token => $c->param('refresh_token') // 'refresh-token',
  );
}

sub _action_well_known {
  my ($self, $c) = @_;
  my $provider = $self->provider;
  my $req_url  = $c->req->url->to_abs;
  my $to_abs   = sub { $req_url->path(Mojo::URL->new(shift)->path)->to_abs };

  $c->render(
    template               => 'oauth2/mock/configuration',
    format                 => 'json',
    authorization_endpoint => $to_abs->($provider->{authorization_endpoint_url}),
    end_session_endpoint   => $to_abs->($provider->{end_session_endpoint_url}),
    issuer                 => $to_abs->($provider->{issuer_url}),
    jwks_uri               => $to_abs->($provider->{jwks_url}),
    token_endpoint         => $to_abs->($provider->{token_endpoint_url}),
  );
}

1;

=encoding utf8

=head1 NAME

Mojolicious::Plugin::OAuth2::Mock - Mock an Oauth2 and/or OpenID Connect provider

=head1 SYNOPSIS

  use Mojolicious::Plugin::OAuth2::Mock;
  use Mojolicious;

  my $app = Mojolicious->new;
  Mojolicious::Plugin::OAuth2::Mock->apply_to($app);

=head1 DESCRIPTION

L<Mojolicious::Plugin::OAuth2::Mock> is an EXPERIMENTAL module to make it
easier to test your L<Mojolicious::Plugin::OAuth2> based code.

=head1 METHODS

=head2 apply_to

  Mojolicious::Plugin::OAuth2::Mock->apply_to($app, \%provider_args);
  $mock->apply_to($app, \%provider_args);

Used to add mocked routes to a L<Mojolicious> application, based on all the
keys in C<%provider_args> that end with "_url". Example:


  * authorize_url              => /mocked/oauth/authorize
  * authorization_endpoint_url => /mocked/oauth2/authorize
  * end_session_endpoint_url   => /mocked/oauth2/logout
  * issuer_url                 => /mocked/oauth2/v2.0
  * jwks_url                   => /mocked/oauth2/keys
  * token_url                  => /mocked/oauth/token
  * token_endpoint_url         => /mocked/oauth2/token

=head1 SEE ALSO

L<Mojolicious::Plugin::OAuth2>.

=cut

__DATA__
@@ oauth2/mock/configuration.json.ep
{
  "authorization_endpoint":"<%= $authorization_endpoint %>",
  "claims_supported":["sub","iss","aud","exp","iat","auth_time","acr","nonce","name","ver","at_hash","c_hash","email"],
  "end_session_endpoint":"<%= $end_session_endpoint %>",
  "id_token_signing_alg_values_supported":["RS256"],
  "issuer":"<%= $issuer %>",
  "jwks_uri":"<%= $jwks_uri %>",
  "request_uri_parameter_supported":0,
  "response_modes_supported":["query","fragment","form_post"],
  "response_types_supported":["code","id_token","code id_token","id_token token"],
  "scopes_supported":["openid","profile","email","offline_access"],
  "subject_types_supported":["pairwise"],
  "token_endpoint":"<%= $token_endpoint %>",
  "token_endpoint_auth_methods_supported":["client_secret_post","private_key_jwt","client_secret_basic"]
}
@@ oauth2/mock/keys.json.ep
{
  "keys":[{
    "e":"<%= $e %>",
    "issuer":"<%= $issuer %>",
    "kid":"TEST_SIGNING_KEY",
    "kty":"RSA",
    "n":"<%= $n %>",
    "use":"sig",
    "x5c":"<%= $x5c %>",
    "x5t":"TEST_SIGNING_KEY"
  }]
}
@@ oauth2/mock/token.json.ep
 {
   "access_token":"access",
   "expires_in":3599,
   "ext_expires_in":3599,
   "id_token":"<%= $id_token %>",
   "refresh_token":"<%= $refresh_token %>",
   "scope":"openid",
   "token_type":"Bearer"
}
@@ oauth2/mock/form_post.html.ep
<html><head><title>In progress...</title></head>
<body>
    <form method="POST" name="hiddenform" action="<%= $redirect_uri %>">
        <input type="hidden" name="code" value="<%= $code %>"/>
        <input type="hidden" name="state" value="<%= $state %>"/>
        <noscript>
            <p>Script is disabled. Click Submit to continue.</p>
            <input type="submit" value="Submit"/>
        </noscript>
    </form>
    <script language="javascript">
    document.forms[0].submit();
    </script>
</body>
</html>
