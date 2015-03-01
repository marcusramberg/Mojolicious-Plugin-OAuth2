use t::Helper;

my $app = t::Helper->make_app;
my $t   = Test::Mojo->new($app);

Mojo::Util::monkey_patch('Mojolicious::Plugin::OAuth2', _ua => sub { $t->ua });

$app->routes->get(
  '/oauth-original' => sub {
    my $c = shift;

    $c->get_token(
      'test',
      async           => 1,
      scope           => 'fakescope',
      authorize_query => {extra => 1},
      sub {
        my ($c, $token, $tx) = @_;
        return $c->render(text => 'no token') unless $token;
        return $c->render(text => 'Token ' . $token);
      },
    );
  }
);

$t->get_ok('/oauth-original')->status_is(302);    # ->content_like(qr/bar/);
my $location     = Mojo::URL->new($t->tx->res->headers->location);
my $callback_url = Mojo::URL->new($location->query->param('redirect_uri'));
is($location->query->param('client_id'), 'fake_key', 'got client_id');

$t->get_ok($location)->status_is(302);
my $res = Mojo::URL->new($t->tx->res->headers->location);
is($res->path,                 $callback_url->path, 'Returns to the right place');
is($res->query->param('code'), 'fake_code',         'Includes fake code');

$t->get_ok($res)->status_is(200)->content_is('Token fake_token');

done_testing;
