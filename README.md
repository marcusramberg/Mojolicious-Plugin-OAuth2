# NAME

Mojolicious::Plugin::OAuth2 - Auth against OAuth2 APIs

# DESCRIPTION

This Mojolicious plugin allows you to easily authenticate against a
[OAuth2](http://oauth.net) provider. It includes configurations for a few
popular providers, but you can add your own easily as well.

Note that OAuth2 requires https, so you need to have the optional Mojolicious
dependency required to support it. Run the command below to check if
[IO::Socket::SSL](https://metacpan.org/pod/IO%3A%3ASocket%3A%3ASSL) is installed.

    $ mojo version

## References

- [http://oauth.net/documentation/](http://oauth.net/documentation/)
- [http://aaronparecki.com/articles/2012/07/29/1/oauth2-simplified](http://aaronparecki.com/articles/2012/07/29/1/oauth2-simplified)
- [http://homakov.blogspot.jp/2013/03/oauth1-oauth2-oauth.html](http://homakov.blogspot.jp/2013/03/oauth1-oauth2-oauth.html)
- [http://en.wikipedia.org/wiki/OAuth#OAuth\_2.0](http://en.wikipedia.org/wiki/OAuth#OAuth_2.0)

# SYNOPSIS

## Example non-blocking application

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

## Custom connect button

You can add a "connect link" to your template using the ["oauth2.auth\_url"](#oauth2-auth_url)
helper. Example template:

    Click here to log in:
    <%= link_to "Connect!", $c->oauth2->auth_url("facebook", scope => "user_about_me email") %>

## Configuration

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

To make it a bit easier, [Mojolicious::Plugin::OAuth2](https://metacpan.org/pod/Mojolicious%3A%3APlugin%3A%3AOAuth2) has already
values for `authorize_url` and `token_url` for the following providers:

- dailymotion

    Authentication for Dailymotion video site.

- eventbrite

    Authentication for [https://www.eventbrite.com](https://www.eventbrite.com) event site.

    See also [http://developer.eventbrite.com/docs/auth/](http://developer.eventbrite.com/docs/auth/).

- facebook

    OAuth2 for Facebook's graph API, [http://graph.facebook.com/](http://graph.facebook.com/). You can find
    `key` (App ID) and `secret` (App Secret) from the app dashboard here:
    [https://developers.facebook.com/apps](https://developers.facebook.com/apps).

    See also [https://developers.facebook.com/docs/reference/dialogs/oauth/](https://developers.facebook.com/docs/reference/dialogs/oauth/).

- instagram

    OAuth2 for Instagram API. You can find `key` (Client ID) and
    `secret` (Client Secret) from the app dashboard here:
    [https://www.instagram.com/developer/clients/manage/](https://www.instagram.com/developer/clients/manage/).

    See also [https://www.instagram.com/developer/authentication/](https://www.instagram.com/developer/authentication/).

- github

    Authentication with Github.

    See also [https://developer.github.com/v3/oauth/](https://developer.github.com/v3/oauth/).

- google

    OAuth2 for Google. You can find the `key` (CLIENT ID) and `secret`
    (CLIENT SECRET) from the app console here under "APIs & Auth" and
    "Credentials" in the menu at [https://console.developers.google.com/project](https://console.developers.google.com/project).

    See also [https://developers.google.com/+/quickstart/](https://developers.google.com/+/quickstart/).

- vkontakte

    OAuth2 for Vkontakte. You can find `key` (App ID) and `secret`
    (Secure key) from the app dashboard here: [https://vk.com/apps?act=manage](https://vk.com/apps?act=manage).

    See also [https://vk.com/dev/authcode\_flow\_user](https://vk.com/dev/authcode_flow_user).

## Testing

THIS API IS EXPERIMENTAL AND CAN CHANGE WITHOUT NOTICE.

To enable a "mocked" OAuth2 api, you need to give the special "mocked"
provider a "key":

    plugin "OAuth2" => { mocked => {key => 42} };

The code above will add two new routes to your application:

- GET /mocked/oauth/authorize

    This route is a web page which contains a link that takes you back to
    "redirect\_uri", with a "code". The "code" default to "fake\_code", but
    can be configured:

        $c->app->oauth2->providers->{mocked}{return_code} = "...";

    The route it self can also be customized:

        plugin "OAuth2" => { mocked => {authorize_url => '...'} };

- POST /mocked/oauth/token

    This route is will return a "access\_token" which is available in your
    ["oauth2.get\_token"](#oauth2-get_token) callback. The default is "fake\_token", but it can
    be configured:

        $c->app->oauth2->providers->{mocked}{return_token} = "...";

    The route it self can also be customized:

        plugin "OAuth2" => { mocked => {token_url => '...'} };

# HELPERS

## oauth2.auth\_url

    $url = $c->oauth2->auth_url($provider => \%args);

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

## oauth2.get\_token

    $data = $c->oauth2->get_token($provider_name => \%args);
    $c    = $c->oauth2->get_token($provider_name => \%args, sub {
              my ($c, $err, $data) = @_;
              # do stuff with $data->{access_token} if it exists.
            });

["oauth2.get\_token"](#oauth2-get_token) is used to either fetch access token from OAuth2 provider,
handle errors or redirect to OAuth2 provider. This method can be called in either
blocking or non-blocking mode. `$err` holds a error description if something
went wrong. Blocking mode will `die($err)` instead of returning it to caller.
`$data` is a hash-ref containing the access token from the OAauth2 provider.
`$data` in blocking mode can also be `undef` if a redirect has been issued
by this module.

In more detail, this method will do one of two things:

1. If called from an action on your site, it will redirect you to the
`$provider_name`'s `authorize_url`. This site will probably have some
sort of "Connect" and "Reject" button, allowing the visitor to either
connect your site with his/her profile on the OAuth2 provider's page or not.
2. The OAuth2 provider will redirect the user back to your site after clicking the
"Connect" or "Reject" button. `$data` will then contain a key "access\_token"
on "Connect" and a false value (or die in blocking mode) on "Reject".

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

## oauth2.get\_token\_p

    $promise = $c->oauth2->get_token_p($provider_name => \%args);

Same as ["oauth2.get\_token"](#oauth2-get_token), but returns a [Mojo::Promise](https://metacpan.org/pod/Mojo%3A%3APromise). See ["SYNOPSIS"](#synopsis)
for example usage.

## oauth2.providers

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

Holds a hash of provider information. See ["oauth2.providers"](#oauth2-providers).

# METHODS

## register

Will register this plugin in your application. See ["SYNOPSIS"](#synopsis).

# AUTHOR

Marcus Ramberg - `mramberg@cpan.org`

Jan Henning Thorsen - `jhthorsen@cpan.org`

# LICENSE

This software is licensed under the same terms as Perl itself.
