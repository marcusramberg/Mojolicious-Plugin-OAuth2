use lib '.';
use t::Helper;

my $app = t::Helper->make_app;
my $t   = Test::Mojo->new($app);

Mojo::Util::monkey_patch('Mojolicious::Plugin::OAuth2', _ua         => sub { $t->ua });
my $state=0;
Mojo::Util::monkey_patch('Mojolicious::Plugin::OAuth2', _make_state => sub { ++ $state });

$app->routes->get(
  '/connect' => sub {
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

$t->get_ok('/connect')->status_is(302);    # ->content_like(qr/bar/);

# The first time the state is good, the second time it should be cleared from the flash
$t->get_ok('/connect?code=123&state=1')->status_is(200)->content_like(qr/bar/);
$t->get_ok('/connect?code=123&state=1')->status_is(500)->content_like(qr/bar/);

done_testing;
