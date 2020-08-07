use lib '.';
use t::Helper;

my $app = t::Helper->make_app;
my $t   = Test::Mojo->new($app);

Mojo::Util::monkey_patch('Mojolicious::Plugin::OAuth2', _ua         => sub { $t->ua });

$app->routes->get(
  '/connect' => sub {
    my $c = shift;
   
    my $flash_state = $c->param('_flash_state');
    $c->flash("state_for_test" => $flash_state) if $flash_state;

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

# There is no matching state in the flash:
$t->get_ok('/connect?code=123&state=this-wont-match-the-flash')
  ->status_is(555)
  ->content_like(qr/state missing/);
  
# There is no state in the return url:
$t->get_ok('/connect?code=123&_flash_state=this-is-a-secret')
  ->status_is(555)
  ->content_like(qr/state missing/);

# Matching states:
$t->get_ok('/connect?code=123&_flash_state=this-is-a-secret&state=this-is-a-secret')
  ->status_is(200)
  ->content_like(qr/Token /); 

done_testing;
