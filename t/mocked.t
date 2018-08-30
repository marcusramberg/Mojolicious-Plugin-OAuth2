use Mojo::Base -strict;
use Mojolicious;
use Test::Mojo;
use Test::More;

{
  use Mojolicious::Lite;
  plugin OAuth2 => {mocked => {key => '42'}};
  get '/test123' => sub {
    my $c = shift;

    $c->oauth2->get_token_p('mocked')->then(
      sub {
        return unless my $provider_res = shift;    # Redirect
        $c->render(text => "Token $provider_res->{access_token}");
      }
    )->catch(sub { $c->reply->exception(shift) });
  };
}

my $t = Test::Mojo->new;

$t->get_ok('/test123')->status_is(302);            # ->content_like(qr/bar/);
my $location     = Mojo::URL->new($t->tx->res->headers->location);
my $callback_url = Mojo::URL->new($location->query->param('redirect_uri'));
is($location->query->param('client_id'), '42', 'got client_id');

$t->get_ok($location)->status_is(200)->element_exists('a');
my $res = Mojo::URL->new($t->tx->res->dom->at('a')->{href});
is($res->path,                 $callback_url->path, 'Returns to the right place');
is($res->query->param('code'), 'fake_code',         'Includes fake code');

$t->get_ok($res)->status_is(200)->content_is('Token fake_token');
$t->get_ok('/test123?error=access_denied')->status_is(500)->content_like(qr{>access_denied<});

done_testing;
