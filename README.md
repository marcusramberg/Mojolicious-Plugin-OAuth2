# NAME

Mojolicious::Plugin::OAuth2 - Auth against OAuth2 APIs including OpenID Connect

# SYNOPSIS

## Example application

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

See ["register"](#register) for more details about the configuration this plugin takes.

## Testing

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

See [Mojolicious::Plugin::OAuth2::Mock](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3AOAuth2%3A%3AMock) for more details.

## Connect button

You can add a "connect link" to your template using the ["oauth2.auth\_url"](#oauth2-auth_url)
helper. Example template:

    Click here to log in:
    <%= link_to 'Connect!', $c->oauth2->auth_url('facebook', scope => 'user_about_me email') %>

# DESCRIPTION

This Mojolicious plugin allows you to easily authenticate against a
[OAuth2](http://oauth.net) or [OpenID Connect](https://openid.net/connect/)
provider. It includes configurations for a few popular [providers](#register),
but you can add your own as well.

See ["register"](#register) for a full list of bundled providers.

To support "OpenID Connect", the following optional modules must be installed
manually: [Crypt::OpenSSL::Bignum](https://metacpan.org/pod/Crypt%3A%3AOpenSSL%3A%3ABignum), [Crypt::OpenSSL::RSA](https://metacpan.org/pod/Crypt%3A%3AOpenSSL%3A%3ARSA) and [Mojo::JWT](https://metacpan.org/pod/Mojo%3A%3AJWT).
The modules can be installed with [App::cpanminus](https://metacpan.org/pod/App%3A%3Acpanminus):

    $ cpanm Crypt::OpenSSL::Bignum Crypt::OpenSSL::RSA Mojo::JWT

# HELPERS

## oauth2.auth\_url

    $url = $c->oauth2->auth_url($provider_name => \%args);

Returns a [Mojo::URL](https://metacpan.org/pod/Mojo%3A%3AURL) object which contain the authorize URL. This is
useful if you want to add the authorize URL as a link to your webpage
instead of doing a redirect like ["oauth2.get\_token"](#oauth2-get_token) does. `%args` is optional,
but can contain:

- host

    Useful if your provider uses different hosts for accessing different accounts.
    The default is specified in the provider configuration.

        $url->host($host);

- authorize\_query

    Either a hash-ref or an array-ref which can be used to give extra query
    params to the URL.

        $url->query($authorize_url);

- redirect\_uri

    Useful if you want to go back to a different page than what you came from.
    The default is:

        $c->url_for->to_abs->to_string

- scope

    Scope to ask for credentials to. Should be a space separated list.

- state

    A string that will be sent to the identity provider. When the user returns
    from the identity provider, this exact same string will be carried with the user,
    as a GET parameter called `state` in the URL that the user will return to.

## oauth2.get\_refresh\_token\_p

    $promise = $c->oauth2->get_refresh_token_p($provider_name => \%args);

When [Mojolicious::Plugin::OAuth2](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3AOAuth2) is being used in OpenID Connect mode this
helper allows for a token to be refreshed by specifying a `refresh_token` in
`%args`. Usage is similar to ["oauth2.get\_token\_p"](#oauth2-get_token_p).

## oauth2.get\_token\_p

    $promise = $c->oauth2->get_token_p($provider_name => \%args)
                 ->then(sub { my $provider_res = shift })
                 ->catch(sub { my $err = shift; });

["oauth2.get\_token\_p"](#oauth2-get_token_p) is used to either fetch an access token from an OAuth2
provider, handle errors or redirect to OAuth2 provider.  `$err` in the
rejection handler holds a error description if something went wrong.
`$provider_res` is a hash-ref containing the access token from the OAauth2
provider or `undef` if this plugin performed a 302 redirect to the provider's
connect website.

In more detail, this method will do one of two things:

1. When called from an action on your site, it will redirect you to the provider's
`authorize_url`. This site will probably have some sort of "Connect" and
"Reject" button, allowing the visitor to either connect your site with his/her
profile on the OAuth2 provider's page or not.
2. The OAuth2 provider will redirect the user back to your site after clicking the
"Connect" or "Reject" button. `$provider_res` will then contain a key
"access\_token" on "Connect" and a false value on "Reject".

The method takes these arguments: `$provider_name` need to match on of
the provider names under ["Configuration"](#configuration) or a custom provider defined
when [registering](#synopsis) the plugin.

`%args` can have:

- host

    Useful if your provider uses different hosts for accessing different accounts.
    The default is specified in the provider configuration.

- redirect

    Set `redirect` to 0 to disable automatic redirect.

- scope

    Scope to ask for credentials to. Should be a space separated list.

## oauth2.jwt\_decode

    $claims = $c->oauth2->jwt_decode($provider, sub { my $jwt = shift; ... });
    $claims = $c->oauth2->jwt_decode($provider);

When [Mojolicious::Plugin::OAuth2](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3AOAuth2) is being used in OpenID Connect mode this
helper allows you to decode the response data encoded with the JWKS discovered
from `well_known_url` configuration.

## oauth2.logout\_url

    $url = $c->oauth2->logout_url($provider_name => \%args);

When [Mojolicious::Plugin::OAuth2](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3AOAuth2) is being used in OpenID Connect mode this
helper creates the url to redirect to end the session. The OpenID Connect
Provider will redirect to the `post_logout_redirect_uri` provided in `%args`.
Additional keys for `%args` are `id_token_hint` and `state`.

## oauth2.providers

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

# ATTRIBUTES

## providers

    $hash_ref = $oauth2->providers;

Holds a hash of provider information. See ["oauth2.providers"](#oauth2-providers).

# METHODS

## register

    $app->plugin(OAuth2 => \%provider_config);
    $app->plugin(OAuth2 => {providers => \%provider_config, proxy => 1, ua => Mojo::UserAgent->new});

Will register this plugin in your application with a given `%provider_config`.
The keys in `%provider_config` are provider names and the values are
configuration for each provider. Note that the value will be merged with the
predefined providers below.

Instead of just passing in `%provider_config`, it is possible to pass in a
more complex config, with these keys:

- providers

    The `%provider_config` must be present under this key.

- proxy

    Setting this to a true value will automatically detect proxy settings using
    ["detect" in Mojo::UserAgent::Proxy](https://metacpan.org/pod/Mojo%3A%3AUserAgent%3A%3AProxy#detect).

- ua

    A custom [Mojo::UserAgent](https://metacpan.org/pod/Mojo%3A%3AUserAgent), in case you want to change proxy settings,
    timeouts or other attributes.

Instead of just passing in `%provider_config`, it is possible to pass in a
hash-ref "providers" (`%provider_config`) and "ua" (a custom
[Mojo::UserAgent](https://metacpan.org/pod/Mojo%3A%3AUserAgent) object).

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

For [OpenID Connect](https://openid.net/connect/), `authorize_url` and `token_url` are configured from the
`well_known_url` so these are replaced by the `well_known_url` key.

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

### dailymotion

Authentication for [https://www.dailymotion.com/](https://www.dailymotion.com/) video site.

### debian\_salsa

Authentication for [https://salsa.debian.org/](https://salsa.debian.org/).

### eventbrite

Authentication for [https://www.eventbrite.com](https://www.eventbrite.com) event site.

See also [http://developer.eventbrite.com/docs/auth/](http://developer.eventbrite.com/docs/auth/).

### facebook

OAuth2 for Facebook's graph API, [http://graph.facebook.com/](http://graph.facebook.com/). You can find
`key` (App ID) and `secret` (App Secret) from the app dashboard here:
[https://developers.facebook.com/apps](https://developers.facebook.com/apps).

See also [https://developers.facebook.com/docs/reference/dialogs/oauth/](https://developers.facebook.com/docs/reference/dialogs/oauth/).

### instagram

OAuth2 for Instagram API. You can find `key` (Client ID) and
`secret` (Client Secret) from the app dashboard here:
[https://www.instagram.com/developer/clients/manage/](https://www.instagram.com/developer/clients/manage/).

See also [https://www.instagram.com/developer/authentication/](https://www.instagram.com/developer/authentication/).

### github

Authentication with Github.

See also [https://developer.github.com/v3/oauth/](https://developer.github.com/v3/oauth/).

### google

OAuth2 for Google. You can find the `key` (CLIENT ID) and `secret`
(CLIENT SECRET) from the app console here under "APIs & Auth" and
"Credentials" in the menu at [https://console.developers.google.com/project](https://console.developers.google.com/project).

See also [https://developers.google.com/+/quickstart/](https://developers.google.com/+/quickstart/).

### vkontakte

OAuth2 for Vkontakte. You can find `key` (App ID) and `secret`
(Secure key) from the app dashboard here: [https://vk.com/apps?act=manage](https://vk.com/apps?act=manage).

See also [https://vk.com/dev/authcode\_flow\_user](https://vk.com/dev/authcode_flow_user).

# AUTHOR

Marcus Ramberg - `mramberg@cpan.org`

Jan Henning Thorsen - `jhthorsen@cpan.org`

# LICENSE

This software is licensed under the same terms as Perl itself.

# SEE ALSO

- [http://oauth.net/documentation/](http://oauth.net/documentation/)
- [http://aaronparecki.com/articles/2012/07/29/1/oauth2-simplified](http://aaronparecki.com/articles/2012/07/29/1/oauth2-simplified)
- [http://homakov.blogspot.jp/2013/03/oauth1-oauth2-oauth.html](http://homakov.blogspot.jp/2013/03/oauth1-oauth2-oauth.html)
- [http://en.wikipedia.org/wiki/OAuth#OAuth\_2.0](http://en.wikipedia.org/wiki/OAuth#OAuth_2.0)
- [https://openid.net/connect/](https://openid.net/connect/)
