use t::Helper;

my $app = t::Helper->make_app;
my $t   = Test::Mojo->new($app);

Mojo::Util::monkey_patch('Mojolicious::Plugin::OAuth2', _ua => sub { $t->ua });

$app->routes->get(
  '/oauth-sync' => sub {
    my $c = shift;
    $c->render(text => "Token " . $c->get_token('test'));
  }
);

local $TODO = 'Mojo::IOLoop already running';
$t->get_ok('/oauth-sync?code=200')->status_is(200);

done_testing;
