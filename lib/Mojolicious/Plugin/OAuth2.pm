package Mojolicious::Plugin::OAuth2;
use Mojo::Base 'Mojolicious::Plugin';

use Mojo::Promise;
use Mojo::URL;
use Mojo::UserAgent;
use Carp 'croak';
use strict;

use constant MOJO_JWT => !!(eval { require Mojo::JWT; require Crypt::OpenSSL::RSA; require Crypt::OpenSSL::Bignum; 1 });

our $VERSION = '1.59';

has providers => sub {
  return {
    dailymotion => {
      authorize_url => "https://api.dailymotion.com/oauth/authorize",
      token_url     => "https://api.dailymotion.com/oauth/token"
    },
    eventbrite => {
      authorize_url => 'https://www.eventbrite.com/oauth/authorize',
      token_url     => 'https://www.eventbrite.com/oauth/token',
    },
    facebook => {
      authorize_url => "https://graph.facebook.com/oauth/authorize",
      token_url     => "https://graph.facebook.com/oauth/access_token",
    },
    instagram => {
      authorize_url => "https://api.instagram.com/oauth/authorize/?response_type=code",
      token_url     => "https://api.instagram.com/oauth/access_token",
    },
    github => {
      authorize_url => 'https://github.com/login/oauth/authorize',
      token_url     => 'https://github.com/login/oauth/access_token',
    },
    google => {
      authorize_url => "https://accounts.google.com/o/oauth2/v2/auth?response_type=code",
      token_url     => "https://www.googleapis.com/oauth2/v4/token",
    },
    vkontakte => {authorize_url => "https://oauth.vk.com/authorize", token_url => "https://oauth.vk.com/access_token",},
    mocked => {authorize_url => '/mocked/oauth/authorize', token_url => '/mocked/oauth/token', secret => 'fake_secret'},
  };
};

has _ua => sub { Mojo::UserAgent->new };

sub register {
  my ($self, $app, $config) = @_;
  my $providers = $self->providers;

  foreach my $provider (keys %$config) {
    $providers->{$provider} ||= {};
    for my $key (keys %{$config->{$provider}}) {
      $providers->{$provider}{$key} = $config->{$provider}{$key};
    }
  }

  $app->helper('oauth2.auth_url'    => sub { $self->_get_authorize_url($self->_args(@_)) });
  $app->helper('oauth2.providers'   => sub { $self->providers });
  $app->helper('oauth2.get_token_p' => sub { $self->_get_token($self->_args(@_), Mojo::Promise->new) });
  $app->helper(
    'oauth2.get_token' => sub {
      my $cb = ref $_[-1] eq 'CODE' ? pop : undef;
      my ($c, $args) = $self->_args(@_);

      # Make sure we return Mojolicious::Controller and not Mojo::Promise
      local $args->{return_controller} = 1;

      # Blocking
      return $self->_get_token($c, $args, undef) unless $cb;

      # Non-blocking
      my $p = Mojo::Promise->new;
      $p->then(sub { $c->$cb('', shift) })->catch(sub { $c->$cb(shift, undef) });
      return $self->_get_token($c, $args, $p);
    }
  );
  $app->helper(
    'oauth2.jwt_decode' => sub {
      my $peek = ref $_[-1] eq 'CODE' ? pop : undef;
      my ($c, $args) = $self->_args(@_);
      return $self->providers->{$args->{provider}}{jwt}->decode($args->{data}, $peek);
    }
  );
  $app->helper('oauth2.get_refresh_token_p' => sub { $self->_get_refresh_token($self->_args(@_), Mojo::Promise->new) });
  $app->helper('oauth2.logout_url'          => sub { $self->_get_logout_url($self->_args(@_)) });

  $self->_mock_interface($app) if $providers->{mocked}{key};
  $self->_warmup_openid($app)  if MOJO_JWT;
}

sub _args {
  my ($self, $c, $provider) = (shift, shift, shift);
  my $args = @_ % 2 ? shift : {@_};
  $args->{provider} = $provider || 'unknown';
  croak "Invalid OAuth2 provider: $args->{provider}" unless $self->providers->{$args->{provider}};
  return $c, $args;
}

sub _get_authorize_url {
  my ($self, $c, $args) = @_;
  my $provider_args = $self->providers->{$args->{provider}};
  my $authorize_url;

  $args->{scope}        ||= $provider_args->{scope};
  $args->{redirect_uri} ||= $c->url_for->to_abs->to_string;
  $authorize_url = Mojo::URL->new($provider_args->{authorize_url});
  $authorize_url->host($args->{host}) if exists $args->{host};
  $authorize_url->query->append(client_id => $provider_args->{key}, redirect_uri => $args->{redirect_uri});
  $authorize_url->query->append(scope     => $args->{scope}) if defined $args->{scope};
  $authorize_url->query->append(state     => $args->{state}) if defined $args->{state};
  $authorize_url->query($args->{authorize_query}) if exists $args->{authorize_query};
  $authorize_url;
}

sub _get_logout_url {
  my ($self, $c, $args) = @_;
  return Mojo::URL->new($self->providers->{$args->{provider}}{end_session_url})->tap(
    query => {
      post_logout_redirect_uri => $args->{post_logout_redirect_uri},
      id_token_hint            => $args->{id_token_hint},
      state                    => $args->{state}
    }
  );
}

sub _get_refresh_token {
  my ($self, $c, $args, $p) = @_;

  # Handle error response from oidc provider callback URL - TODO: is this possible?
  if (my $err = $c->param('error_description') || $c->param('error')) {
    die $err unless $p;    # die on blocking
    $p->reject($err);
    return $args->{return_controller} ? $c : $p;
  }

  my $provider_args = $self->providers->{$args->{provider}};
  my $params        = {
    client_secret => $provider_args->{secret},
    client_id     => $provider_args->{key},
    grant_type    => 'refresh_token',
    refresh_token => $args->{refresh_token},
    scope         => $provider_args->{scope},
  };

  my $token_url = Mojo::URL->new($provider_args->{token_url});
  $token_url->host($args->{host}) if exists $args->{host};

  return $self->_token_url_transact($token_url->to_abs, $params, $p, $args->{return_controller} ? $c : undef);
}

sub _get_token {
  my ($self, $c, $args, $p) = @_;

  # Handle error response from provider callback URL
  if (my $err = $c->param('error_description') || $c->param('error')) {
    die $err unless $p;    # die on blocking
    $p->reject($err);
    return $args->{return_controller} ? $c : $p;
  }

  # No error or code response from provider callback URL
  unless ($c->param('code')) {
    $c->redirect_to($self->_get_authorize_url($c, $args)) if $args->{redirect} // 1;
    return $p ? $p->resolve(undef) : undef;
  }

  # Handle "code" from provider callback
  my $provider_args = $self->providers->{$args->{provider}};
  my $params        = {
    client_secret => $provider_args->{secret},
    client_id     => $provider_args->{key},
    code          => scalar($c->param('code')),
    grant_type    => 'authorization_code',
    redirect_uri  => $args->{redirect_uri} || $c->url_for->to_abs->to_string,
  };
  $params->{state} = $c->param('state') if $c->param('state');

  my $token_url = Mojo::URL->new($provider_args->{token_url});
  $token_url->host($args->{host}) if exists $args->{host};

  return $self->_token_url_transact($token_url->to_abs, $params, $p, $args->{return_controller} ? $c : undef);
}

sub _parse_provider_response {
  my ($self, $tx) = @_;
  my $code = $tx->res->code || 'No response';

  # Will cause the promise to be rejected
  die sprintf '%s == %s', $tx->req->url, $tx->error->{message} // $code if $code ne '200';

  return $tx->res->headers->content_type =~ m!^(application/json|text/javascript)(;\s*charset=\S+)?$!
    ? $tx->res->json
    : Mojo::Parameters->new($tx->res->body)->to_hash;
}

sub _mock_interface {
  my ($self, $app) = @_;
  my $provider_args = $self->providers->{mocked};

  $self->_ua->server->app($app);
  return $self->_mock_interface_oidc($app, $provider_args) if MOJO_JWT and $provider_args->{well_known_url};

  $provider_args->{return_code}  ||= 'fake_code';
  $provider_args->{return_token} ||= 'fake_token';

  $app->routes->get(
    $provider_args->{authorize_url} => sub {
      my $c = shift;
      if ($c->param('client_id') and $c->param('redirect_uri')) {
        my $url = Mojo::URL->new($c->param('redirect_uri'));
        $url->query->append(code => $provider_args->{return_code});
        $c->render(text => $c->tag('a', href => $url, sub {'Connect'}));
      }
      else {
        $c->render(text => "Invalid request\n", status => 400);
      }
    }
  );

  $app->routes->post(
    $provider_args->{token_url} => sub {
      my $c = shift;
      if ($c->param('client_secret') and $c->param('redirect_uri') and $c->param('code')) {
        my $qp = Mojo::Parameters->new(
          access_token  => $provider_args->{return_token},
          expires_in    => 3600,
          refresh_token => Mojo::Util::md5_sum(rand),
          scope         => $provider_args->{scopes} || 'some list of scopes',
          token_type    => 'bearer',
        );
        $c->render(text => $qp->to_string);
      }
      else {
        $c->render(status => 404, text => 'FAIL OVERFLOW');
      }
    }
  );
}

sub _mock_interface_oidc {
  my ($self, $app, $provider) = @_;
  my $nb_url = $app->ua->server->nb_url;
  my $rsa    = Crypt::OpenSSL::RSA->generate_key(2048);
  my $known  = $provider->{well_known_url};
  my $auth   = '/mocked/oauth2/authorize';
  my $iss    = '/mocked/oauth2/v2.0';
  my $jwks   = '/mocked/oauth2/keys';
  my $logout = '/mocked/oauth2/logout';
  my $token  = '/mocked/oauth2/token';
  push @{$app->renderer->classes}, __PACKAGE__;
  $app->routes->get(
    $known => sub {
      my $c = shift;
      $c->render(
        'oauth2/mock/configuration',
        format                 => 'json',
        authorization_endpoint => $nb_url->clone->tap(path => $auth),
        end_session_endpoint   => $nb_url->clone->tap(path => $logout),
        issuer                 => $nb_url->clone->tap(path => $iss),
        jwks_uri               => $nb_url->clone->tap(path => $jwks),
        token_endpoint         => $nb_url->clone->tap(path => $token)
      );
    }
  );
  $app->routes->get(
    $jwks => sub {
      my $c = shift;
      my ($n, $e) = $rsa->get_key_parameters;
      (my $x5c = $rsa->get_public_key_string) =~ s/\n/\\n/g;
      require MIME::Base64;
      return $c->render(
        'oauth2/mock/keys',
        format => 'json',
        'n'    => MIME::Base64::encode_base64url($n->to_bin),
        'e'    => MIME::Base64::encode_base64url($e->to_bin),
        'x5c'  => $x5c,
        issuer => $c->url_for($iss)->to_abs,
      );
    }
  );

  $app->routes->any(
    $auth => sub {
      my $c = shift;
      return $c->render(
        'oauth2/mock/form_post',
        format       => 'html',
        redirect_uri => $c->param('redirect_uri'),
        code         => "authorize-code",
        state        => $c->param('state')
      ) if ($c->param('response_mode') eq 'form_post');

      # $c->param('response_mode') eq 'query'
      my $url = Mojo::URL->new($c->param('redirect_uri'));
      $url->query({code => "authorize-code", state => $c->param('state')});
      return $c->redirect_to($url);
    }
  );

  $app->routes->any(
    $token => sub {
      my $c = shift;
      return $c->render(json => {error => 'invalid_request'}, status => 500)
        unless (($c->param('client_secret') and $c->param('redirect_uri') and $c->param('code'))
        || ($c->param('grant_type') eq 'refresh_token' and $c->param('refresh_token')));
      my $claims = {
        aud                => $c->param('client_id'),
        email              => 'foo.bar@example.com',
        iss                => $c->url_for($iss)->to_abs,
        name               => 'foo bar',
        preferred_username => 'foo.bar@example.com',
        sub                => 'foo.bar'
      };
      return $c->render(
        'oauth2/mock/token',
        format   => 'json',
        id_token => Mojo::JWT->new(
          algorithm => 'RS256',
          secret    => $rsa->get_private_key_string,
          set_iat   => 1,
          claims    => $claims,
          header    => {kid => 'TEST_SIGNING_KEY'}
        )->expires(Mojo::JWT->now + 3600)->encode,
        refresh_token => $c->param('refresh_token') // 'refresh-token',
      );
    }
  );

  $app->routes->any(
    $logout => sub {
      my $c      = shift;
      my $rp_url = Mojo::URL->new($c->param('post_logout_redirect_uri'))
        ->query({id_token_hint => $c->param('id_token_hint'), state => $c->param('state'),});
      $c->redirect_to($rp_url);
    }
  );
  return $self;
}

sub _token_url_transact {
  my ($self, $token_url, $params, $p, $c) = @_;
  if ($p) {
    $self->_ua->post_p($token_url, form => $params)->then(sub { $p->resolve($self->_parse_provider_response(@_)) })
      ->catch(sub { $p->reject(@_); () });
    return $c || $p;
  }
  else {
    return $self->_parse_provider_response($self->_ua->post($token_url, form => $params));
  }
}

sub _warmup_openid {
  my ($self, $app) = (shift, shift);
  my $providers = $self->providers;
  for my $provider (keys %$providers) {
    next unless my $well_known = $providers->{$provider}->{well_known_url};
    $app->log->debug("Fetching OpenID configuration from $well_known");
    $self->_warmup_openid_provider_p($provider, $well_known)->catch(sub { $app->log->error(shift) })->wait;
  }
  return $self;
}

sub _warmup_openid_provider_p {
  my ($self, $provider, $well_known) = (shift, shift, shift);
  my $config = $self->providers->{$provider};
  $self->_ua->get_p($well_known)->then(
    sub {
      my $tx  = shift;
      my $res = $tx->result->json;
      $config->{authorize_url}   = $res->{authorization_endpoint};
      $config->{end_session_url} = $res->{end_session_endpoint};
      $config->{token_url}       = $res->{token_endpoint};
      $config->{userinfo_url}    = $res->{userinfo_endpoint};
      $config->{issuer}          = $res->{issuer};
      $config->{scope} //= 'openid';
      $res;
    }
  )->then(sub { $self->_ua->get_p(shift->{jwks_uri}) })
    ->then(sub { $config->{jwt} = Mojo::JWT->new->add_jwkset(shift->result->json) })->catch(sub { warn @_; });
}

1;

=head1 NAME

Mojolicious::Plugin::OAuth2 - Auth against OAuth2 APIs including OpenID Connect

=head1 DESCRIPTION

This Mojolicious plugin allows you to easily authenticate against a
L<OAuth2|http://oauth.net> provider. It includes configurations for a few
popular providers, but you can add your own easily as well.

Note that OAuth2 requires https, so you need to have the optional Mojolicious
dependency required to support it. Run the command below to check if
L<IO::Socket::SSL> is installed.

   $ mojo version

=head2 References

=over 4

=item * L<http://oauth.net/documentation/>

=item * L<http://aaronparecki.com/articles/2012/07/29/1/oauth2-simplified>

=item * L<http://homakov.blogspot.jp/2013/03/oauth1-oauth2-oauth.html>

=item * L<http://en.wikipedia.org/wiki/OAuth#OAuth_2.0>

=item * L<https://openid.net/connect/>

=back

=head1 SYNOPSIS

=head2 Example non-blocking application

  use Mojolicious::Lite;

  plugin "OAuth2" => {
    facebook => {
      key    => "some-public-app-id",
      secret => $ENV{OAUTH2_FACEBOOK_SECRET},
    },
  };

  get "/connect" => sub {
    my $c = shift;
    my $get_token_args = {redirect_uri => $c->url_for("connect")->userinfo(undef)->to_abs};

    $c->oauth2->get_token_p(facebook => $get_token_args)->then(sub {
      return unless my $provider_res = shift; # Redirct to Facebook
      $c->session(token => $provider_res->{access_token});
      $c->redirect_to("profile");
    })->catch(sub {
      $c->render("connect", error => shift);
    });
  };

=head2 Custom connect button

You can add a "connect link" to your template using the L</oauth2.auth_url>
helper. Example template:

  Click here to log in:
  <%= link_to "Connect!", $c->oauth2->auth_url("facebook", scope => "user_about_me email") %>

=head2 Configuration

This plugin takes a hash as config, where the keys are provider names and the
values are configuration for each provider. Here is a complete example:

  plugin "OAuth2" => {
    custom_provider => {
      key           => "APP_ID",
      secret        => "SECRET_KEY",
      authorize_url => "https://provider.example.com/auth",
      token_url     => "https://provider.example.com/token",
    },
  };

For L<OpenID Connect|https://openid.net/connect/>, C<authorize_url> and C<token_url> are configured from the
C<well_known_url> so these are replaced by the C<well_known_url> key.

  plugin "OAuth2" => {
    azure_ad => {
      key            => "APP_ID",
      secret         => "SECRET_KEY",
      well_known_url => "https://login.microsoftonline.com/tenant-id/v2.0/.well-known/openid-configuration",
    },
  };

To make it a bit easier, L<Mojolicious::Plugin::OAuth2> has already
values for C<authorize_url> and C<token_url> for the following providers:

=over 4

=item * dailymotion

Authentication for Dailymotion video site.

=item * eventbrite

Authentication for L<https://www.eventbrite.com> event site.

See also L<http://developer.eventbrite.com/docs/auth/>.

=item * facebook

OAuth2 for Facebook's graph API, L<http://graph.facebook.com/>. You can find
C<key> (App ID) and C<secret> (App Secret) from the app dashboard here:
L<https://developers.facebook.com/apps>.

See also L<https://developers.facebook.com/docs/reference/dialogs/oauth/>.

=item * instagram

OAuth2 for Instagram API. You can find C<key> (Client ID) and
C<secret> (Client Secret) from the app dashboard here:
L<https://www.instagram.com/developer/clients/manage/>.

See also L<https://www.instagram.com/developer/authentication/>.

=item * github

Authentication with Github.

See also L<https://developer.github.com/v3/oauth/>.

=item * google

OAuth2 for Google. You can find the C<key> (CLIENT ID) and C<secret>
(CLIENT SECRET) from the app console here under "APIs & Auth" and
"Credentials" in the menu at L<https://console.developers.google.com/project>.

See also L<https://developers.google.com/+/quickstart/>.

=item * vkontakte

OAuth2 for Vkontakte. You can find C<key> (App ID) and C<secret>
(Secure key) from the app dashboard here: L<https://vk.com/apps?act=manage>.

See also L<https://vk.com/dev/authcode_flow_user>.

=back

=head2 Testing

THIS API IS EXPERIMENTAL AND CAN CHANGE WITHOUT NOTICE.

To enable a "mocked" OAuth2 api, you need to give the special "mocked"
provider a "key":

  plugin "OAuth2" => { mocked => {key => 42} };

The code above will add two new routes to your application:

=over 4

=item * GET /mocked/oauth/authorize

This route is a web page which contains a link that takes you back to
"redirect_uri", with a "code". The "code" default to "fake_code", but
can be configured:

  $c->app->oauth2->providers->{mocked}{return_code} = "...";

The route it self can also be customized:

  plugin "OAuth2" => { mocked => {authorize_url => '...'} };

=item * POST /mocked/oauth/token

This route is will return a "access_token" which is available in your
L</oauth2.get_token> callback. The default is "fake_token", but it can
be configured:

  $c->app->oauth2->providers->{mocked}{return_token} = "...";

The route it self can also be customized:

  plugin "OAuth2" => { mocked => {token_url => '...'} };

=back

=head1 HELPERS

=head2 oauth2.auth_url

  $url = $c->oauth2->auth_url($provider => \%args);

Returns a L<Mojo::URL> object which contain the authorize URL. This is
useful if you want to add the authorize URL as a link to your webpage
instead of doing a redirect like L</oauth2.get_token> does. C<%args> is optional,
but can contain:

=over 4

=item * host

Useful if your provider uses different hosts for accessing different accounts.
The default is specified in the provider configuration.

  $url->host($host);

=item * authorize_query

Either a hash-ref or an array-ref which can be used to give extra query
params to the URL.

  $url->query($authorize_url);

=item * redirect_uri

Useful if you want to go back to a different page than what you came from.
The default is:

  $c->url_for->to_abs->to_string

=item * scope

Scope to ask for credentials to. Should be a space separated list.

=item * state

A string that will be sent to the identity provider. When the user returns
from the identity provider, this exact same string will be carried with the user,
as a GET parameter called C<state> in the URL that the user will return to.

=back

=head2 oauth2.get_token

  $data = $c->oauth2->get_token($provider_name => \%args);
  $c    = $c->oauth2->get_token($provider_name => \%args, sub {
            my ($c, $err, $data) = @_;
            # do stuff with $data->{access_token} if it exists.
          });

L</oauth2.get_token> is used to either fetch access token from OAuth2 provider,
handle errors or redirect to OAuth2 provider. This method can be called in either
blocking or non-blocking mode. C<$err> holds a error description if something
went wrong. Blocking mode will C<die($err)> instead of returning it to caller.
C<$data> is a hash-ref containing the access token from the OAauth2 provider.
C<$data> in blocking mode can also be C<undef> if a redirect has been issued
by this module.

In more detail, this method will do one of two things:

=over 4

=item 1.

If called from an action on your site, it will redirect you to the
C<$provider_name>'s C<authorize_url>. This site will probably have some
sort of "Connect" and "Reject" button, allowing the visitor to either
connect your site with his/her profile on the OAuth2 provider's page or not.

=item 2.

The OAuth2 provider will redirect the user back to your site after clicking the
"Connect" or "Reject" button. C<$data> will then contain a key "access_token"
on "Connect" and a false value (or die in blocking mode) on "Reject".

=back

The method takes these arguments: C<$provider_name> need to match on of
the provider names under L</Configuration> or a custom provider defined
when L<registering|/SYNOPSIS> the plugin.

C<%args> can have:

=over 4

=item * host

Useful if your provider uses different hosts for accessing different accounts.
The default is specified in the provider configuration.

=item * redirect

Set C<redirect> to 0 to disable automatic redirect.

=item * scope

Scope to ask for credentials to. Should be a space separated list.

=back

=head2 oauth2.get_token_p

  $promise = $c->oauth2->get_token_p($provider_name => \%args);

Same as L</oauth2.get_token>, but returns a L<Mojo::Promise>. See L</SYNOPSIS>
for example usage.

=head2 oauth2.providers

This helper allow you to access the raw providers mapping, which looks
something like this:

  {
    facebook => {
      authorize_url => "https://graph.facebook.com/oauth/authorize",
      token_url     => "https://graph.facebook.com/oauth/access_token",
      key           => ...,
      secret        => ...,
    },
    ...
  }

=head2 oauth2.get_refresh_token_p

  $promise = $c->oauth2->get_refresh_token_p($provider_name => \%args);

When L<Mojolicious::Plugin::OAuth2> is being used in openid connect mode this helper allows for token refresh by
submitting a C<refresh_token> specified in C<%args>. Usage is similar to L</"oauth2.get_token_p">.

=head2 oauth2.jwt_decode

When L<Mojolicious::Plugin::OAuth2> is being used in openid connect mode this helper allows you to decode the response
data encoded with the JWKS discovered from C<well_known_url> configuration. This requires the optional dependencies
L<Mojo::JWT>, L<Crypt::OpenSSL::RSA> and L<Crypt::OpenSSL::Bignum>.

=head2 oauth2.logout_url

  $url = $c->oauth2->logout_url($provider_name => \%args);

When L<Mojolicious::Plugin::OAuth2> is being used in openid connect mode this helper creates the url to redirect to end
the session. The OpenID Connect Provider will redirect to the C<post_logout_redirect_uri> provided in C<%args>.
Additional keys for C<%args> are C<id_token_hint> and C<state>.

=head1 ATTRIBUTES

=head2 providers

Holds a hash of provider information. See L</oauth2.providers>.

=head1 METHODS

=head2 register

Will register this plugin in your application. See L</SYNOPSIS>.

=head1 AUTHOR

Marcus Ramberg - C<mramberg@cpan.org>

Jan Henning Thorsen - C<jhthorsen@cpan.org>

=head1 LICENSE

This software is licensed under the same terms as Perl itself.

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
