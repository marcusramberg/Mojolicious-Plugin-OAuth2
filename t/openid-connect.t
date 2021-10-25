use Mojo::Base -strict;
use Test::More;
use Test::Mojo;
use MIME::Base64 qw(encode_base64url);
use Mojo::JSON qw(decode_json encode_json);
use Mojo::URL;
use Mojolicious::Plugin::OAuth2;

plan skip_all => "Mojo::JWT, Crypt::OpenSSL::RSA and Crypt::OpenSSL::Bignum required for openid tests"
  unless Mojolicious::Plugin::OAuth2::MOJO_JWT;

use Mojolicious::Lite;

plugin OAuth2 => {mocked =>
    {key => 'c0e71b99-2c66-42e7-8589-6502153a7e3', well_known_url => '/mocked/oauth2/.well-known/configuration'}};

get '/' => sub { shift->render('index') };

any "/connect" => sub {
  my $c = shift;
  $c->render_later;

  my $get_token_args = {
    redirect_uri    => $c->req->url->to_abs,
    authorize_query => {
      response_mode => $ENV{'OAUTH2_MOCK_RESPONSE_MODE'} // 'form_post',
      response_type => 'code',
      state         => $c->param('oauth2.state') // 'test'
    }
  };

  $c->oauth2->get_token_p(mocked => $get_token_args)->then(sub {
    return unless my $provider_res = shift;    # Redirect to IdP
    $c->session(token => $provider_res->{access_token}, refresh_token => $provider_res->{refresh_token});
    my $user = $c->oauth2->jwt_decode(mocked => data => $provider_res->{id_token});
    $c->signed_cookie(id_token => $provider_res->{id_token});
    return $c->redirect_to($c->param('state')) if $c->param('state') ne 'test';
    $c->render(json => $user);
  })->catch(sub {
    $c->render(text => "Error $_[0]", status => 500);
  });
};

# exercise end_session_endpoint
get '/end_session' => sub {
  my $c    = shift;
  my $home = $c->req->url->base->clone->tap(path => '/');

  # require id_token to calculate logout_url
  return $c->redirect_to($home) unless my $id_token = $c->signed_cookie('id_token');
  my $end_session_url = $c->oauth2->logout_url(
    mocked => {post_logout_redirect_uri => $c->req->url->to_abs, id_token_hint => $id_token, state => time});

  return $c->redirect_to($end_session_url) unless $c->param('id_token_hint') and my $state = $c->param('state');
  $c->signed_cookie('id_token' => $id_token, {expires => time - 1});
  delete $c->session->{$_} for (qw(token refresh_token));
  return $c->redirect_to($home);
};

# refresh access token using refresh_token
get '/refresh' => sub {
  my $c = shift;
  $c->render_later;
  $c->oauth2->get_refresh_token_p(mocked => {refresh_token => $c->session('refresh_token') . "+"})->then(sub {
    my $res = shift;
    $c->session(refresh_token => $res->{refresh_token});
    $c->render(json => $res);
  })->catch(sub { $c->render(text => "Error $_[0]", status => 500); });
};

group {
  under '/protect' => sub {
    my $c = shift;
    Mojo::IOLoop->timer(
      0.1 => sub {
        $c->redirect_to($c->url_for('connect')->query({'oauth2.state' => $c->req->url}));
      }
    );
    return undef unless $c->session('token');
    return 1;
  };

  get '/next' => sub { shift->render(text => 'ok') };
};

my $t = Test::Mojo->new;

subtest 'warmup of provvider data' => sub {
  my $provider_conf = $t->app->oauth2->providers->{mocked};

  is $provider_conf->{scope},        'openid', 'scope';
  is $provider_conf->{userinfo_url}, undef,    'userinfo_url';
  ok $provider_conf->{jwt},          'resolved from configuration';
  ok +Mojo::URL->new($provider_conf->{$_})->scheme, $_ for qw(authorize_url end_session_url issuer token_url);
};

subtest 'Authorize and obtain token - form_post response_mode' => sub {
  $t->get_ok('/connect')->status_is(302);
  my $location = Mojo::URL->new($t->tx->res->headers->location);
  is $location->query->param('scope'),         'openid',    'scope set';
  is $location->query->param('response_mode'), 'form_post', 'response mode set';

  my ($action, $form);
  $t->get_ok($location)->status_is(200)->tap(sub {
    my $dom = shift->tx->res->dom;
    $action = $dom->at('form')->attr('action');
    $form
      = {code => $dom->at('input[name=code]')->attr('value'), state => $dom->at('input[name=state]')->attr('value')};
    $t->test(is => Mojo::URL->new($action)->is_abs, 1, 'absolute url');
  });
  $t->post_ok($action, form => $form)->status_is(200)->json_is('/aud' => 'c0e71b99-2c66-42e7-8589-6502153a7e3')
    ->json_is('/email' => 'foo.bar@example.com')
    ->json_is('/iss'   => $t->app->oauth2->providers->{mocked}{issuer}, 'OIDC valid (MUST)')
    ->json_is('/name'  => 'foo bar')->json_is('/preferred_username' => 'foo.bar@example.com')
    ->json_is('/sub'   => 'foo.bar')->json_has('/iat')->json_has('/exp');
};

subtest 'Refresh token' => sub {
  $t->get_ok('/refresh')->status_is(200)->json_is('/refresh_token', 'refresh-token+');
  $t->get_ok('/refresh')->status_is(200)->json_is('/refresh_token', 'refresh-token++');
  $t->get_ok('/refresh?error=bad')->status_is(500)->content_is('Error bad');
};

subtest 'Authorize and obtain token - query response_mode' => sub {
  local $ENV{OAUTH2_MOCK_RESPONSE_MODE} = 'query';
  local $t->app->oauth2->providers->{mocked}{scope} = 'openid email profile';
  $t->get_ok('/connect')->status_is(302);
  my $location = Mojo::URL->new($t->tx->res->headers->location);
  is $location->query->param('scope'),         'openid email profile', 'scope set';
  is $location->query->param('response_mode'), 'query',                'response mode set';
  is $location->query->param('state'),         'test',                 'state propagates';

  my ($action, $form);
  $t->get_ok($location)->status_is(302);
  $location = Mojo::URL->new($t->tx->res->headers->location);
  is $location->path, '/connect', 'redirect_uri';
  is $location->query->param('code'),  'authorize-code', 'code set';
  is $location->query->param('state'), 'test',           'state returned';
  $t->get_ok("$location")->status_is(200)->json_is('/aud' => 'c0e71b99-2c66-42e7-8589-6502153a7e3')
    ->json_is('/email' => 'foo.bar@example.com')
    ->json_is('/iss'   => $t->app->oauth2->providers->{mocked}{issuer}, 'OIDC valid (MUST)')
    ->json_is('/name'  => 'foo bar')->json_is('/preferred_username' => 'foo.bar@example.com')
    ->json_is('/sub'   => 'foo.bar')->json_has('/iat')->json_has('/exp');
};

subtest 'Logout' => sub {
  my $end_session_url = $t->ua->server->url->clone->tap(path => '/end_session');

  # obtain signed cookie from user agent
  my $c        = $t->app->build_controller->tap(sub { $_->tx->req->cookies(@{$t->ua->cookie_jar->all}) });
  my $id_token = $c->signed_cookie('id_token');
  ok $id_token, 'Have a current id token';

  $t->get_ok($end_session_url)->status_is(302);
  my $op_location = Mojo::URL->new($t->tx->res->headers->location);
  is $op_location->path, '/mocked/oauth2/logout', 'correct';
  is $op_location->query->param('id_token_hint'),            $id_token,        'correct id token';
  is $op_location->query->param('post_logout_redirect_uri'), $end_session_url, 'post_logout_redirect_uri set';
  is $op_location->query->param('state'),                    time, 'state set';

  $t->get_ok($op_location)->status_is(302);
  my $rp_location = Mojo::URL->new($t->tx->res->headers->location);
  is $rp_location->path, '/end_session', 'correct';
  is $rp_location->query->param('id_token_hint'), $id_token, 'correct id token';
  is $rp_location->query->param('state'), time, 'state set';

  $t->get_ok($rp_location)->status_is(302);
  my $logged_out = Mojo::URL->new($t->tx->res->headers->location);
  is $logged_out->path, '/', 'home';
  my @cookies = grep { $_->name eq 'id_token' } @{$t->ua->cookie_jar->find($end_session_url) || []};
  is_deeply \@cookies, [], 'removed';

  $t->get_ok($end_session_url)->status_is(302);
  $logged_out = Mojo::URL->new($t->tx->res->headers->location);
  is $logged_out->path, '/', 'home';
};

subtest 'Redirects with under' => sub {
  local $ENV{OAUTH2_MOCK_RESPONSE_MODE} = 'query';
  my $max = $t->ua->max_redirects;
  my $url = $t->ua->server->url->clone->tap(path => '/protect/next');
  $t->reset_session->ua->max_redirects($max + 5);
  $t->get_ok('/protect/next')->status_is(200)->content_is('ok');
  is_deeply [map { $_->name } grep { $_->name eq 'id_token' } @{$t->ua->cookie_jar->find($url) || []}], ['id_token'],
    'set cookie';
  is_deeply [map { $_->req->url->path } @{$t->tx->redirects}],
    [qw(/protect/next /connect /mocked/oauth2/authorize /connect)], 'login chain';
  $t->ua->max_redirects($max);
};

done_testing;

__DATA__
@@ index.html.ep
%= link_to 'Connect', $c->url_for('connect');
