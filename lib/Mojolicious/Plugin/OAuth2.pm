package Mojolicious::Plugin::OAuth2;

use Mojo::Base 'Mojolicious::Plugin';
use Mojo::UserAgent;
use Mojo::Util 'deprecated';
use Carp 'croak';
use strict;

our $VERSION = '1.3';

has providers => sub {
  return {
    eventbrite => {
      authorize_url => 'https://www.eventbrite.com/oauth/authorize',
      token_url     => 'https://www.eventbrite.com/oauth/token',
    },
    google => {
      authorize_url => 'https://accounts.google.com/o/oauth2/auth',
      token_url     => 'https://www.googleapis.com/oauth2/v3/token',
    },
    github => {
      authorize_url => 'https://github.com/login/oauth/authorize',
      token_url     => 'https://github.com/login/oauth/access_token',
    },
    facebook => {
      authorize_url => "https://graph.facebook.com/oauth/authorize",
      token_url     => "https://graph.facebook.com/oauth/access_token",
    },
    dailymotion => {
      authorize_url => "https://api.dailymotion.com/oauth/authorize",
      token_url     => "https://api.dailymotion.com/oauth/token"
    },
    google => {
      authorize_url => "https://accounts.google.com/o/oauth2/auth?response_type=code",
      token_url     => "https://accounts.google.com/o/oauth2/token",
    },
  };
};

has _ua => sub { Mojo::UserAgent->new };

sub register {
  my ($self, $app, $config) = @_;
  my $providers = $self->providers;

  foreach my $provider (keys %$config) {
    if (exists $providers->{$provider}) {
      foreach my $key (keys %{$config->{$provider}}) {
        $providers->{$provider}->{$key} = $config->{$provider}->{$key};
      }
    }
    else {
      $providers->{$provider} = $config->{$provider};
    }
  }

  $self->providers($providers);

  $app->helper('oauth2.auth_url'  => sub { $self->_get_authorize_url(@_) });
  $app->helper('oauth2.providers' => sub { $self->providers });
  $app->helper(
    'oauth2.get_token' => sub {
      my $c = shift;

      return $self->_process_response_error($c, @_) if $c->param('error');
      return $self->_process_response_code($c, @_) if $c->param('code');
      return $c->redirect_to($self->_get_authorize_url($c, @_));
    }
  );

  $app->renderer->add_helper(
    get_authorize_url => sub {
      deprecated "get_authorize_url() is DEPRECATED in favor of \$c->oauth2->auth_url(...)";
      $self->_get_authorize_url(@_);
    }
  );
  $app->renderer->add_helper(
    get_token => sub {
      my $c = shift;

      deprecated "get_token() is DEPRECATED in favor of \$c->oauth2->get_token(...)";

      if ($c->param('code')) {
        return $self->_handle_code($c, @_);
      }
      elsif ($c->param('error')) {
        return $self->_handle_error($c, @_);
      }
      else {
        return $c->redirect_to($self->_get_authorize_url($c, @_));
      }
    }
  );
}

sub _args {
  my $cb = ref $_[-1] eq 'CODE' ? pop : undef;
  my ($self, $c, $provider_id) = (shift, shift, shift);

  return $self, $c, $provider_id || 'undef()', (@_ % 2 ? shift : {@_}), $cb;
}

sub _get_authorize_url {
  my ($self, $c, $provider_id, $args, $cb) = _args(@_);
  my $provider = $self->providers->{$provider_id} or croak "[get_authorize_url] Unknown OAuth2 provider $provider_id";
  my $authorize_url;

  $provider->{key} or croak "[get_authorize_url] 'key' for $provider_id is missing";

  $args->{scope} ||= $self->providers->{$provider_id}{scope};
  $args->{redirect_uri} ||= $c->url_for->to_abs->to_string;
  $authorize_url = Mojo::URL->new($provider->{authorize_url});
  $authorize_url->host($args->{host}) if exists $args->{host};
  $authorize_url->query->append(client_id => $provider->{key}, redirect_uri => $args->{redirect_uri});
  $authorize_url->query->append(scope => $args->{scope}) if defined $args->{scope};
  $authorize_url->query->append(state => $args->{state}) if defined $args->{state};
  $authorize_url->query($args->{authorize_query}) if exists $args->{authorize_query};
  $authorize_url;
}

sub _get_auth_token {
  my ($self, $tx, $nb) = @_;
  my ($err, $token);
  my $res = $tx->res;

  if ($err = $tx->error) {
    1;
  }
  elsif ($res->headers->content_type =~ m!^(application/json|text/javascript)(;\s*charset=\S+)?$!) {
    $token = $res->json->{access_token};
  }
  else {
    $token = Mojo::Parameters->new($res->body)->param('access_token');
  }

  die $err->{message} || 'Unknown error' if !$token and !$nb;
  return $token, $tx;
}

sub _handle_code {
  my ($self, $c, $provider_id, $args, $cb) = _args(@_);
  my $provider  = $self->providers->{$provider_id} or croak "[code] Unknown OAuth2 provider $provider_id";
  my $token_url = Mojo::URL->new($provider->{token_url});
  my $params    = {
    client_secret => $provider->{secret},
    client_id     => $provider->{key},
    code          => scalar($c->param('code')),
    grant_type    => 'authorization_code',
    redirect_uri  => $args->{redirect_uri} || $c->url_for->to_abs->to_string,
  };

  $token_url->host($args->{host}) if exists $args->{host};

  if ($cb) {
    return $c->delay(
      sub {
        my ($delay) = @_;
        $self->_ua->post($token_url->to_abs, form => $params => $delay->begin);
      },
      sub {
        my ($delay, $tx) = @_;
        $c->$cb($self->_get_auth_token($tx, $cb));
      },
    );
  }
  else {
    return $self->_get_auth_token($self->_ua->post($token_url->to_abs, form => $params));
  }
}

sub _handle_error {
  my ($self, $c, $provider_id, $args, $cb) = _args(@_);
  my $error = $c->param('error');

  die $error unless $cb;
  my $provider = $self->providers->{$provider_id} or croak "[error] Unknown OAuth2 provider $provider_id";
  my $tx = $self->_ua->build_tx(GET => $provider->{authorize_url});
  $tx->res->error({message => $error});
  $c->$cb(undef, $tx);
  $c;
}

sub _process_response_code {
  my $cb = pop;
  my ($self, $c, $provider_id, $args) = @_;
  my $provider  = $self->providers->{$provider_id} or croak "[code] Unknown OAuth2 provider $provider_id";
  my $token_url = Mojo::URL->new($provider->{token_url});
  my $params    = {
    client_secret => $provider->{secret},
    client_id     => $provider->{key},
    code          => scalar($c->param('code')),
    grant_type    => 'authorization_code',
    redirect_uri  => $args->{redirect_uri} || $c->url_for->to_abs->to_string,
  };

  $token_url->host($args->{host}) if exists $args->{host};

  return $c->delay(
    sub {
      my ($delay) = @_;
      $self->_ua->post($token_url->to_abs, form => $params => $delay->begin);
    },
    sub {
      my ($delay, $tx) = @_;
      my $res = $tx->res;
      my $token;

      if (my $err = $tx->error) {
        return $c->$cb($err->{message} || $err->{code}, undef);
      }
      elsif ($res->headers->content_type =~ m!^(application/json|text/javascript)(;\s*charset=\S+)?$!) {
        $token = $res->json->{access_token};
      }
      else {
        $token = Mojo::Parameters->new($res->body)->param('access_token');
      }

      $c->$cb($token ? '' : 'Unknown error', $token);
    },
  );
}

sub _process_response_error {
  my $cb = pop;
  my ($self, $c, $provider_id, $args) = @_;

  $c->$cb($c->param('error_description') || $c->param('error'), undef);
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

=head2 Async example

  use Mojolicious::Lite;

  plugin "OAuth2" => {
    facebook => {
      key => "APP_ID",
      secret => $ENV{OAUTH2_FACEBOOK_SECRET},
    },
  };

  get "/auth" => sub {
    my $self = shift;
    $self->delay(
      sub {
        my $delay = shift;
        $self->get_token(facebook => $delay->begin)
      },
      sub {
        my($delay, $token, $tx) = @_;
        return $self->render(text => $tx->res->error) unless $token;
        $self->session(token => $token);
        $self->render(text => $token);
      },
    );
  };

=head2 Synchronous example

L</get_token> can also be called synchronous, but we encourage the async
example above.

  my $token = $self->get_token("facebook");

=head2 Custom connect button

You can add a "connect link" to your template using the L</get_authorize_url>
helper. Example template:

  Click here to log in:
  <%= link_to "Connect!", get_authorize_url("facebook", scope => "user_about_me email") %>

=head2 Configuration

This plugin takes a hash as config, where the keys are provider names and the
values are configuration for each provider. Here is a complete example:

  plugin "OAuth2" => {
    custom_provider => {
      key => "APP_ID",
      secret => "SECRET_KEY",
      authorize_url => "https://provider.example.com/auth",
      token_url => "https://provider.example.com/token",
    },
  };

To make it a bit easier, L<Mojolicious::Plugin::OAuth2> has already
values for C<authorize_url> and C<token_url> for the following providers:

=over 4

=item * facebook

OAuth2 for Facebook's graph API, L<http://graph.facebook.com/>. You can find
C<key> (App ID) and C<secret> (App Secret) from the app dashboard here:
L<https://developers.facebook.com/apps>.

See also L<https://developers.facebook.com/docs/reference/dialogs/oauth/>.

=item * dailymotion

Authentication for Dailymotion video site.

=item * google

OAuth2 for Google. You can find the C<key> (CLIENT ID) and C<secret>
(CLIENT SECRET) from the app console here under "APIs & Auth" and
"Credentials" in the menu at L<https://console.developers.google.com/project>.

See also L<https://developers.google.com/+/quickstart/>.

=back

=head1 HELPERS

=head2 get_authorize_url

  $url = $c->get_authorize_url($provider => \%args);

Returns a L<Mojo::URL> object which contain the authorize URL. This is
useful if you want to add the authorize URL as a link to your webpage
instead of doing a redirect like L</get_token> does. C<%args> is optional,
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

=head2 get_token

  $token = $c->get_token($provider_name => \%args);
  $c = $c->get_token($provider_name => \%args, sub { my ($c, $token, $tx) = @_; });

This method will do one of two things:

=over 4

=item 1.

If called from an action on your site, it will redirect you to the
C<$provider_name>'s C<authorize_url>. This site will probably have some
sort of "Connect" and "Reject" button, allowing the visitor to either
connect your site with his/her profile on the OAuth2 provider's page or not.

=item 2.

The OAuth2 provider will redirect the user back to your site after clicking the
"Connect" or "Reject" button. C<$token> will then contain a string on "Connect"
and a false value on "Reject". You can investigate
L<$tx|Mojo::Transaction::HTTP> if C<$token> holds a false value.

=back

Will redirect to the provider to allow for authorization, then fetch the
token. The token gets provided as a parameter to the callback function.
Usually you want to store the token in a session or similar to use for
API requests. Supported arguments:

=over 4

=item * host

Useful if your provider uses different hosts for accessing different accounts.
The default is specified in the provider configuration.

=item * scope

Scope to ask for credentials to. Should be a space separated list.

=back

=head1 AUTHOR

Marcus Ramberg - C<mramberg@cpan.org>

Jan Henning Thorsen - C<jhthorsen@cpan.org>

=head1 LICENSE

This software is licensed under the same terms as Perl itself.

=cut
