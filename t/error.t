use t::Helper;

my $app = t::Helper->make_app;
my $t   = Test::Mojo->new($app);

Mojo::Util::monkey_patch('Mojolicious::Plugin::OAuth2', _ua => sub { $t->ua });

$app->routes->get(
  '/oauth-error' => sub {
    my $c = shift;

    $c->delay(
      sub {
        my $delay = shift;
        $c->get_token(test => $delay->begin);
      },
      sub {
        my ($delay, $token, $tx) = @_;
        return $c->render(text => $tx->res->error, status => 500) unless $token;
        return $c->render(text => "Token $token");
      },
    );
  }
);

$t->get_ok('/oauth-error')->status_is(302);    # ->content_like(qr/bar/);
$t->get_ok('/oauth-error?code=123')->status_is(200);
$t->get_ok('/oauth-error?error=access_denied')->status_is(500);

done_testing;
