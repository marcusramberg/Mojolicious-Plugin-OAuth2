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
        return $c->render(text => shift, status => 555);
      }
    );
  }
);

$t->get_ok('/connect?code=123&state=1')->status_is(200)->content_like(qr/state missing/); # 

$app->flash("state_for_test" => "this-is-a-secret");
$t->get_ok('/connect?code=123&state=this-is-a-secret')->status_is(500)->content_like(qr/Token/);
$t->get_ok('/connect?code=123&state=this-is-a-secret') ->status_is(500)->content_like(qr/state missing/);

done_testing;
