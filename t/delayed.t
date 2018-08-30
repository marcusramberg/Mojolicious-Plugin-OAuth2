use lib '.';
use t::Helper;

my $app = t::Helper->make_app;
my $t   = Test::Mojo->new($app);

Mojo::Util::monkey_patch('Mojolicious::Plugin::OAuth2', _ua => sub { $t->ua });

$t->app->helper(
  delay => sub {
    my $c  = shift;
    my $tx = $c->render_later->tx;
    Mojo::IOLoop->delay(@_)->catch(sub { $c->helpers->reply->exception(pop) and undef $tx })->wait;
  }
);

$app->routes->get(
  '/oauth-delayed' => sub {
    my $c = shift;

    $c->delay(
      sub {
        my $delay = shift;
        $c->oauth2->get_token(test => $delay->begin);
      },
      sub {
        my ($delay, $err, $provider_res) = @_;
        return $c->render(text => $err) unless $provider_res;
        return $c->render(text => "Token $provider_res->{access_token}");
      },
    );
  }
);

$t->get_ok('/oauth-delayed')->status_is(302);    # ->content_like(qr/bar/);
my $location     = Mojo::URL->new($t->tx->res->headers->location);
my $redirect_uri = Mojo::URL->new($location->query->param('redirect_uri'));
is($location->query->param('client_id'), 'fake_key', 'got client_id');

note $location;
$t->get_ok($location)->status_is(302);
$location = Mojo::URL->new($t->tx->res->headers->location || '/not/302');
is($location->path,                 $redirect_uri->path, 'Returns to the right place');
is($location->query->param('code'), 'fake_code',         'Includes fake code');

note $location;
$t->get_ok($location)->status_is(200)->content_is('Token fake_token');

done_testing;
