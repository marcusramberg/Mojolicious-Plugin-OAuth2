package t::Helper;
use Mojo::Base -strict;
use Mojolicious;
use Test::Mojo;
use Test::More;

sub make_app {
  my $app = Mojolicious->new;

  $app->plugin(
    OAuth2 => {
      fix_get_token => 1,
      test          => {
        authorize_url => '/oauth/authorize',
        token_url     => '/oauth/token',
        key           => 'fake_key',
        secret        => 'fake_secret',
        scope         => 'a,b,c',
      }
    }
  );

  $app->routes->get(
    '/oauth/authorize' => sub {
      my $c = shift;
      if ($c->param('client_id') and $c->param('redirect_uri') and $c->param('scope')) {
        my $return = Mojo::URL->new($c->param('redirect_uri'));
        $return->query->append(code => 'fake_code');
        $c->redirect_to($return);
      }
      else {
        $c->render(status => 404, text => 'REJECTED');
      }
    }
  );

  $app->routes->post(
    '/oauth/token' => sub {
      my $c = shift;
      if ($c->param('client_secret') and $c->param('redirect_uri') and $c->param('code')) {
        my $qp = Mojo::Parameters->new(access_token => 'fake_token', lifetime => 3600);
        $c->render(text => $qp->to_string);
      }
      else {
        $c->render(status => 404, text => 'FAIL OVERFLOW');
      }
    }
  );

  return $app;
}

sub import {
  my $class  = shift;
  my $caller = caller;

  strict->import;
  warnings->import;

  eval <<"HERE" or die;
package $caller;
use Test::Mojo;
use Test::More;
1;
HERE

}

1;
