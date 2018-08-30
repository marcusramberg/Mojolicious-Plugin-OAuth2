use lib '.';
use t::Helper;

my $app = t::Helper->make_app;
my $t   = Test::Mojo->new($app);

Mojo::Util::monkey_patch('Mojolicious::Plugin::OAuth2', _ua => sub { $t->ua });

$app->routes->get(
  '/oauth-error' => sub {
    my $c = shift;

    $c->oauth2->get_token_p('test')->then(
      sub {
        return unless my $provider_res = shift;
        return $c->render(text => "Token $provider_res->{access_token}");
      }
    )->catch(
      sub {
        return $c->render(text => shift, status => 500);
      }
    );
  }
);

$t->get_ok('/oauth-error')->status_is(302);    # ->content_like(qr/bar/);
$t->get_ok('/oauth-error?code=123')->status_is(200);
$t->get_ok('/oauth-error?error=access_denied')->status_is(500);

done_testing;
