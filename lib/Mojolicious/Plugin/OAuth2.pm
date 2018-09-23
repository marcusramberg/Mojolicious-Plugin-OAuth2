package Mojolicious::Plugin::OAuth2;
use Mojo::Base 'Mojolicious::Plugin';

use Mojo::Promise;
use Mojo::UserAgent;
use Carp 'croak';
use strict;

our $VERSION = '1.55';

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
    github => {
      authorize_url => 'https://github.com/login/oauth/authorize',
      token_url     => 'https://github.com/login/oauth/access_token',
    },
    google => {
      authorize_url => "https://accounts.google.com/o/oauth2/v2/auth?response_type=code",
      token_url     => "https://www.googleapis.com/oauth2/v4/token",
    },
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

  $self->_mock_interface($app) if $providers->{mocked}{key};
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

  $args->{scope} ||= $provider_args->{scope};
  $args->{redirect_uri} ||= $c->url_for->to_abs->to_string;
  $authorize_url = Mojo::URL->new($provider_args->{authorize_url});
  $authorize_url->host($args->{host}) if exists $args->{host};
  $authorize_url->query->append(client_id => $provider_args->{key}, redirect_uri => $args->{redirect_uri});
  $authorize_url->query->append(scope => $args->{scope}) if defined $args->{scope};
  $authorize_url->query->append(state => $args->{state}) if defined $args->{state};
  $authorize_url->query($args->{authorize_query}) if exists $args->{authorize_query};
  $authorize_url;
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

  my $token_url = Mojo::URL->new($provider_args->{token_url});
  $token_url->host($args->{host}) if exists $args->{host};
  $token_url = $token_url->to_abs;

  if ($p) {
    $self->_ua->post_p($token_url, form => $params)->then(sub { $p->resolve($self->_parse_provider_response(@_)) })
      ->catch(sub { $p->reject(@_) });
    return $args->{return_controller} ? $c : $p;
  }
  else {
    return $self->_parse_provider_response($self->_ua->post($token_url, form => $params));
  }
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

1;

=head1 NAME

Mojolicious::Plugin::OAuth2 - Auth against OAuth2 APIs

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

=item * github

Authentication with Github.

See also L<https://developer.github.com/v3/oauth/>

=item * google

OAuth2 for Google. You can find the C<key> (CLIENT ID) and C<secret>
(CLIENT SECRET) from the app console here under "APIs & Auth" and
"Credentials" in the menu at L<https://console.developers.google.com/project>.

See also L<https://developers.google.com/+/quickstart/>.

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

=head1 ATTRIBUTES

=head2 providers

Holds a hash of provider information. See L<oauth2.providers>.

=head1 METHODS

=head2 register

Will register this plugin in your application. See L</SYNOPSIS>.

=head1 AUTHOR

Marcus Ramberg - C<mramberg@cpan.org>

Jan Henning Thorsen - C<jhthorsen@cpan.org>

=head1 LICENSE

This software is licensed under the same terms as Perl itself.

=cut
