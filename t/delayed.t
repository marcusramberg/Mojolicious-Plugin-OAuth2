use lib '.';
use t::Helper;

my $app = t::Helper->make_app;
my $t   = Test::Mojo->new($app);

Mojo::Util::monkey_patch('Mojolicious::Plugin::OAuth2', _ua => sub { $t->ua });

$app->routes->get(
  '/oauth-delayed' => sub {
    my $c = shift;

    $c->oauth2->get_token(
      test => sub {
        my (undef, $err, $provider_res) = @_;
        return $c->render(text => $err) unless $provider_res;
        return $c->render(text => "Token $provider_res->{access_token}");
      }
    );
  }
);

$app->helper(
  'oauth2.get_token' => sub {
    my ($c, $args, $cb) = @_;
    $c->oauth2->get_token_p($args)->then(sub { $c->$cb('', shift) }, sub { $c->$cb(shift, {}) },);
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
