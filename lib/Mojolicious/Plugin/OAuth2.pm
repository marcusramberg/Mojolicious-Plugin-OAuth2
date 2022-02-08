package Mojolicious::Plugin::OAuth2;
use Mojo::Base 'Mojolicious::Plugin';

use Carp qw(croak);
use Mojo::Promise;
use Mojo::URL;
use Mojo::UserAgent;

use constant MOJO_JWT => eval 'use Mojo::JWT 0.09; use Crypt::OpenSSL::RSA; use Crypt::OpenSSL::Bignum; 1';

our @CARP_NOT = qw(Mojolicious::Plugin::OAuth2 Mojolicious::Renderer);
our $VERSION  = '2.02';

has providers => sub {
  return {
    dailymotion => {
      authorize_url => 'https://api.dailymotion.com/oauth/authorize',
      token_url     => 'https://api.dailymotion.com/oauth/token'
    },
    debian_salsa => {
      authorize_url => 'https://salsa.debian.org/oauth/authorize?response_type=code',
      token_url     => 'https://salsa.debian.org/oauth/token',
    },
    eventbrite => {
      authorize_url => 'https://www.eventbrite.com/oauth/authorize',
      token_url     => 'https://www.eventbrite.com/oauth/token',
    },
    facebook => {
      authorize_url => 'https://graph.facebook.com/oauth/authorize',
      token_url     => 'https://graph.facebook.com/oauth/access_token',
    },
    instagram => {
      authorize_url => 'https://api.instagram.com/oauth/authorize/?response_type=code',
      token_url     => 'https://api.instagram.com/oauth/access_token',
    },
    github => {
      authorize_url => 'https://github.com/login/oauth/authorize',
      token_url     => 'https://github.com/login/oauth/access_token',
    },
    google => {
      authorize_url => 'https://accounts.google.com/o/oauth2/v2/auth?response_type=code',
      token_url     => 'https://www.googleapis.com/oauth2/v4/token',
    },
    vkontakte => {authorize_url => 'https://oauth.vk.com/authorize', token_url => 'https://oauth.vk.com/access_token',},
    mocked => {authorize_url => '/mocked/oauth/authorize', token_url => '/mocked/oauth/token', secret => 'fake_secret'},
  };
};

has _ua => sub { Mojo::UserAgent->new };

sub register {
  my ($self, $app, $config) = @_;

  if ($config->{providers}) {
    $self->_config_to_providers($config->{providers});
    $self->_ua($config->{ua}) if $config->{ua};
    $self->_ua->proxy->detect if $config->{proxy};
  }
  else {
    $self->_config_to_providers($config);
  }

  $app->helper('oauth2.auth_url'            => sub { $self->_call(_auth_url            => @_) });
  $app->helper('oauth2.get_refresh_token_p' => sub { $self->_call(_get_refresh_token_p => @_) });
  $app->helper('oauth2.get_token_p'         => sub { $self->_call(_get_token_p         => @_) });
  $app->helper('oauth2.jwt_decode'          => sub { $self->_call(_jwt_decode          => @_) });
  $app->helper('oauth2.logout_url'          => sub { $self->_call(_logout_url          => @_) });
  $app->helper('oauth2.providers'           => sub { $self->providers });

  $self->_apply_mock($self->providers->{mocked}) if $self->providers->{mocked}{key};
  $self->_warmup_openid($app);
}

sub _apply_mock {
  my ($self, $provider_args) = @_;

  require Mojolicious::Plugin::OAuth2::Mock;
  require Mojolicious;
  my $app = $self->_ua->server->app || Mojolicious->new;
  Mojolicious::Plugin::OAuth2::Mock->apply_to($app, $provider_args);
  $self->_ua->server->app($app);
}

sub _auth_url {
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

sub _call {
  my ($self, $method, $c, $provider) = (shift, shift, shift, shift);
  my $args = @_ % 2 ? shift : {@_};
  $args->{provider} = $provider || 'unknown';
  croak "Invalid provider: $args->{provider}" unless $self->providers->{$args->{provider}};
  return $self->$method($c, $args);
}

sub _config_to_providers {
  my ($self, $config) = @_;

  for my $provider (keys %$config) {
    my $p = $self->providers->{$provider} ||= {};
    for my $key (keys %{$config->{$provider}}) {
      $p->{$key} = $config->{$provider}{$key};
    }
  }
}

sub _get_refresh_token_p {
  my ($self, $c, $args) = @_;

  # TODO: Handle error response from oidc provider callback URL, if possible
  my $err = $c->param('error_description') || $c->param('error');
  return Mojo::Promise->reject($err) if $err;

  my $provider_args = $self->providers->{$args->{provider}};
  my $params        = {
    client_id     => $provider_args->{key},
    client_secret => $provider_args->{secret},
    grant_type    => 'refresh_token',
    refresh_token => $args->{refresh_token},
    scope         => $provider_args->{scope},
  };

  my $token_url = Mojo::URL->new($provider_args->{token_url});
  $token_url->host($args->{host}) if exists $args->{host};

  return $self->_ua->post_p($token_url, form => $params)->then(sub { $self->_parse_provider_response(@_) });
}

sub _get_token_p {
  my ($self, $c, $args) = @_;

  # Handle error response from provider callback URL
  my $err = $c->param('error_description') || $c->param('error');
  return Mojo::Promise->reject($err) if $err;

  # No error or code response from provider callback URL
  unless ($c->param('code')) {
    $c->redirect_to($self->_auth_url($c, $args)) if $args->{redirect} // 1;
    return Mojo::Promise->resolve(undef);
  }

  # Handle "code" from provider callback
  my $provider_args = $self->providers->{$args->{provider}};
  my $params        = {
    client_id     => $provider_args->{key},
    client_secret => $provider_args->{secret},
    code          => scalar($c->param('code')),
    grant_type    => 'authorization_code',
    redirect_uri  => $args->{redirect_uri} || $c->url_for->to_abs->to_string,
  };

  $params->{state} = $c->param('state') if $c->param('state');

  my $token_url = Mojo::URL->new($provider_args->{token_url});
  $token_url->host($args->{host}) if exists $args->{host};

  return $self->_ua->post_p($token_url, form => $params)->then(sub { $self->_parse_provider_response(@_) });
}

sub _jwt_decode {
  my $peek = ref $_[-1] eq 'CODE' && pop;
  my ($self, $c, $args) = @_;
  croak 'Provider does not have "jwt" defined.' unless my $jwt = $self->providers->{$args->{provider}}{jwt};
  return $jwt->decode($args->{data}, $peek);
}

sub _logout_url {
  my ($self, $c, $args) = @_;
  return Mojo::URL->new($self->providers->{$args->{provider}}{end_session_url})->tap(
    query => {
      post_logout_redirect_uri => $args->{post_logout_redirect_uri},
      id_token_hint            => $args->{id_token_hint},
      state                    => $args->{state}
    }
  );
}

sub _parse_provider_response {
  my ($self, $tx) = @_;
  my $code = $tx->res->code || 'No response';

  # Will cause the promise to be rejected
  return Mojo::Promise->reject(sprintf '%s == %s', $tx->req->url, $tx->error->{message} // $code) if $code ne '200';
  return $tx->res->headers->content_type =~ m!^(application/json|text/javascript)(;\s*charset=\S+)?$!
    ? $tx->res->json
    : Mojo::Parameters->new($tx->res->body)->to_hash;
}

sub _warmup_openid {
  my ($self, $app) = (shift, shift);

  my ($providers, @p) = ($self->providers);
  for my $provider (values %$providers) {
    next unless $provider->{well_known_url};
    $app->log->debug("Fetching OpenID configuration from $provider->{well_known_url}");
    push @p, $self->_warmup_openid_provider_p($app, $provider);
  }

  return @p && Mojo::Promise->all(@p)->wait;
}

sub _warmup_openid_provider_p {
  my ($self, $app, $provider) = @_;

  return $self->_ua->get_p($provider->{well_known_url})->then(sub {
    my $tx  = shift;
    my $res = $tx->result->json;
    $provider->{authorize_url}   = $res->{authorization_endpoint};
    $provider->{end_session_url} = $res->{end_session_endpoint};
    $provider->{issuer}          = $res->{issuer};
    $provider->{token_url}       = $res->{token_endpoint};
    $provider->{userinfo_url}    = $res->{userinfo_endpoint};
    $provider->{scope} //= 'openid';

    return $self->_ua->get_p($res->{jwks_uri});
  })->then(sub {
    my $tx = shift;
    $provider->{jwt} = Mojo::JWT->new->add_jwkset($tx->result->json);
    return $provider;
  })->catch(sub {
    my $err = shift;
    $app->log->error("[OAuth2] Failed to warm up $provider->{well_known_url}: $err");
  });
}

1;

=head1 NAME

Mojolicious::Plugin::OAuth2 - Auth against OAuth2 APIs including OpenID Connect

=head1 SYNOPSIS

=head2 Example application

  use Mojolicious::Lite;

  plugin OAuth2 => {
    providers => {
      facebook => {
        key    => 'some-public-app-id',
        secret => $ENV{OAUTH2_FACEBOOK_SECRET},
      },
    },
  };

  get '/connect' => sub {
    my $c         = shift;
    my %get_token = (redirect_uri => $c->url_for('connect')->userinfo(undef)->to_abs);

    return $c->oauth2->get_token_p(facebook => \%get_token)->then(sub {
      # Redirected to Facebook
      return unless my $provider_res = shift;

      # Token received
      $c->session(token => $provider_res->{access_token});
      $c->redirect_to('profile');
    })->catch(sub {
      $c->render('connect', error => shift);
    });
  };

See L</register> for more details about the configuration this plugin takes.

=head2 Testing

Code using this plugin can perform offline testing, using the "mocked"
provider:

  $app->plugin(OAuth2 => {mocked => {key => 42}});
  $app->routes->get('/profile' => sub {
    my $c = shift;

    state $mocked = $ENV{TEST_MOCKED} && 'mocked';
    return $c->oauth2->get_token_p($mocked || 'facebook')->then(sub {
      ...
    });
  });

See L<Mojolicious::Plugin::OAuth2::Mock> for more details.

=head2 Connect button

You can add a "connect link" to your template using the L</oauth2.auth_url>
helper. Example template:

  Click here to log in:
  <%= link_to 'Connect!', $c->oauth2->auth_url('facebook', scope => 'user_about_me email') %>

=head1 DESCRIPTION

This Mojolicious plugin allows you to easily authenticate against a
L<OAuth2|http://oauth.net> or L<OpenID Connect|https://openid.net/connect/>
provider. It includes configurations for a few popular L<providers|/register>,
but you can add your own as well.

See L</register> for a full list of bundled providers.

To support "OpenID Connect", the following optional modules must be installed
manually: L<Crypt::OpenSSL::Bignum>, L<Crypt::OpenSSL::RSA> and L<Mojo::JWT>.
The modules can be installed with L<App::cpanminus>:

  $ cpanm Crypt::OpenSSL::Bignum Crypt::OpenSSL::RSA Mojo::JWT

=head1 HELPERS

=head2 oauth2.auth_url

  $url = $c->oauth2->auth_url($provider_name => \%args);

Returns a L<Mojo::URL> object which contain the authorize URL. This is
useful if you want to add the authorize URL as a link to your webpage
instead of doing a redirect like L</oauth2.get_token> does. C<%args> is optional,
but can contain:

=over 2

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

=head2 oauth2.get_refresh_token_p

  $promise = $c->oauth2->get_refresh_token_p($provider_name => \%args);

When L<Mojolicious::Plugin::OAuth2> is being used in OpenID Connect mode this
helper allows for a token to be refreshed by specifying a C<refresh_token> in
C<%args>. Usage is similar to L</"oauth2.get_token_p">.

=head2 oauth2.get_token_p

  $promise = $c->oauth2->get_token_p($provider_name => \%args)
               ->then(sub { my $provider_res = shift })
               ->catch(sub { my $err = shift; });

L</oauth2.get_token_p> is used to either fetch an access token from an OAuth2
provider, handle errors or redirect to OAuth2 provider.  C<$err> in the
rejection handler holds a error description if something went wrong.
C<$provider_res> is a hash-ref containing the access token from the OAauth2
provider or C<undef> if this plugin performed a 302 redirect to the provider's
connect website.

In more detail, this method will do one of two things:

=over 2

=item 1.

When called from an action on your site, it will redirect you to the provider's
C<authorize_url>. This site will probably have some sort of "Connect" and
"Reject" button, allowing the visitor to either connect your site with his/her
profile on the OAuth2 provider's page or not.

=item 2.

The OAuth2 provider will redirect the user back to your site after clicking the
"Connect" or "Reject" button. C<$provider_res> will then contain a key
"access_token" on "Connect" and a false value on "Reject".

=back

The method takes these arguments: C<$provider_name> need to match on of
the provider names under L</Configuration> or a custom provider defined
when L<registering|/SYNOPSIS> the plugin.

C<%args> can have:

=over 2

=item * host

Useful if your provider uses different hosts for accessing different accounts.
The default is specified in the provider configuration.

=item * redirect

Set C<redirect> to 0 to disable automatic redirect.

=item * scope

Scope to ask for credentials to. Should be a space separated list.

=back

=head2 oauth2.jwt_decode

  $claims = $c->oauth2->jwt_decode($provider, sub { my $jwt = shift; ... });
  $claims = $c->oauth2->jwt_decode($provider);

When L<Mojolicious::Plugin::OAuth2> is being used in OpenID Connect mode this
helper allows you to decode the response data encoded with the JWKS discovered
from C<well_known_url> configuration.

=head2 oauth2.logout_url

  $url = $c->oauth2->logout_url($provider_name => \%args);

When L<Mojolicious::Plugin::OAuth2> is being used in OpenID Connect mode this
helper creates the url to redirect to end the session. The OpenID Connect
Provider will redirect to the C<post_logout_redirect_uri> provided in C<%args>.
Additional keys for C<%args> are C<id_token_hint> and C<state>.

=head2 oauth2.providers

  $hash_ref = $c->oauth2->providers;

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

=head1 ATTRIBUTES

=head2 providers

  $hash_ref = $oauth2->providers;

Holds a hash of provider information. See L</oauth2.providers>.

=head1 METHODS

=head2 register

  $app->plugin(OAuth2 => \%provider_config);
  $app->plugin(OAuth2 => {providers => \%provider_config, proxy => 1, ua => Mojo::UserAgent->new});

Will register this plugin in your application with a given C<%provider_config>.
The keys in C<%provider_config> are provider names and the values are
configuration for each provider. Note that the value will be merged with the
predefined providers below.

Instead of just passing in C<%provider_config>, it is possible to pass in a
more complex config, with these keys:

=over 2

=item * providers

The C<%provider_config> must be present under this key.

=item * proxy

Setting this to a true value will automatically detect proxy settings using
L<Mojo::UserAgent::Proxy/detect>.

=item * ua

A custom L<Mojo::UserAgent>, in case you want to change proxy settings,
timeouts or other attributes.

=back

Instead of just passing in C<%provider_config>, it is possible to pass in a
hash-ref "providers" (C<%provider_config>) and "ua" (a custom
L<Mojo::UserAgent> object).

Here is an example to add adddition information like "key" and "secret":

  $app->plugin(OAuth2 => {
    providers => {
      custom_provider => {
        key           => 'APP_ID',
        secret        => 'SECRET_KEY',
        authorize_url => 'https://provider.example.com/auth',
        token_url     => 'https://provider.example.com/token',
      },
      github => {
        key    => 'APP_ID',
        secret => 'SECRET_KEY',
      },
    },
  });

For L<OpenID Connect|https://openid.net/connect/>, C<authorize_url> and C<token_url> are configured from the
C<well_known_url> so these are replaced by the C<well_known_url> key.

  $app->plugin(OAuth2 => {
    providers => {
      azure_ad => {
        key            => 'APP_ID',
        secret         => 'SECRET_KEY',
        well_known_url => 'https://login.microsoftonline.com/tenant-id/v2.0/.well-known/openid-configuration',
      },
    },
  });

To make it a bit easier the are already some predefined providers bundled with
this plugin:

=head3 dailymotion

Authentication for L<https://www.dailymotion.com/> video site.

=head3 debian_salsa

Authentication for L<https://salsa.debian.org/>.

=head3 eventbrite

Authentication for L<https://www.eventbrite.com> event site.

See also L<http://developer.eventbrite.com/docs/auth/>.

=head3 facebook

OAuth2 for Facebook's graph API, L<http://graph.facebook.com/>. You can find
C<key> (App ID) and C<secret> (App Secret) from the app dashboard here:
L<https://developers.facebook.com/apps>.

See also L<https://developers.facebook.com/docs/reference/dialogs/oauth/>.

=head3 instagram

OAuth2 for Instagram API. You can find C<key> (Client ID) and
C<secret> (Client Secret) from the app dashboard here:
L<https://www.instagram.com/developer/clients/manage/>.

See also L<https://www.instagram.com/developer/authentication/>.

=head3 github

Authentication with Github.

See also L<https://developer.github.com/v3/oauth/>.

=head3 google

OAuth2 for Google. You can find the C<key> (CLIENT ID) and C<secret>
(CLIENT SECRET) from the app console here under "APIs & Auth" and
"Credentials" in the menu at L<https://console.developers.google.com/project>.

See also L<https://developers.google.com/+/quickstart/>.

=head3 vkontakte

OAuth2 for Vkontakte. You can find C<key> (App ID) and C<secret>
(Secure key) from the app dashboard here: L<https://vk.com/apps?act=manage>.

See also L<https://vk.com/dev/authcode_flow_user>.

=head1 AUTHOR

Marcus Ramberg - C<mramberg@cpan.org>

Jan Henning Thorsen - C<jhthorsen@cpan.org>

=head1 LICENSE

This software is licensed under the same terms as Perl itself.

=head1 SEE ALSO

=over 2

=item * L<http://oauth.net/documentation/>

=item * L<http://aaronparecki.com/articles/2012/07/29/1/oauth2-simplified>

=item * L<http://homakov.blogspot.jp/2013/03/oauth1-oauth2-oauth.html>

=item * L<http://en.wikipedia.org/wiki/OAuth#OAuth_2.0>

=item * L<https://openid.net/connect/>

=back

=cut
