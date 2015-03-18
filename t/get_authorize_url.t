use Mojo::Base -strict;
use Test::Mojo;
use Test::More;

my $authorize_args = {};

use Mojolicious::Lite;
plugin 'OAuth2' => {fix_get_token => 1, facebook => {key => 'KEY'}};
get '/test123', sub { $_[0]->render(text => $_[0]->get_authorize_url('facebook', $authorize_args)); };

my $t = Test::Mojo->new;

eval { $t->app->get_authorize_url };
like $@, qr{Unknown OAuth2 provider}, 'provider_id is required';

$t->get_ok('/test123')->status_is(200);
my $url = Mojo::URL->new($t->tx->res->body);
like $url, qr{^https://graph\.facebook\.com/oauth/authorize}, 'base url';
is $url->query->param('client_id'),      'KEY',         'client_id';
like $url->query->param('redirect_uri'), qr{/test123$}, 'redirect_uri';

$authorize_args = {
  scope           => 'email,age',
  redirect_uri    => 'https://example.com',
  host            => 'oauth2.example.com',
  state           => '42',
  authorize_query => {foo => 123},
};

$t->get_ok('/test123')->status_is(200);
$url = Mojo::URL->new($t->tx->res->body);
like $url, qr{^https://oauth2\.example\.com/oauth/authorize}, 'custom.host';
is $url->query->param('foo'),          '123',                 'foo';
is $url->query->param('client_id'),    'KEY',                 'client_id';
is $url->query->param('redirect_uri'), 'https://example.com', 'custom.redirect_uri';
is $url->query->param('scope'),        'email,age',           'scope';
is $url->query->param('state'),        '42',                  'state';

done_testing;
