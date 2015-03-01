use Test::More;
use Mojolicious::Lite;
use Test::Mojo;
use Test::More;

unless ($ENV{OAUTH_FB_KEY} && $ENV{OAUTH_FB_SECRET}) {
  plan skip_all => 'OAUTH_FB_KEY and OAUTH_FB_SECRET must be set for oauth tests';
}

plugin 'OAuth2', facebook => {key => $ENV{OAUTH_FB_KEY}, secret => $ENV{OAUTH_FB_SECRET}};

my ($token, $tx);

get '/connect' => sub {
  my $self = shift;
  $self->delay(
    sub {
      my ($delay) = @_;
      $self->oauth2->get_token(facebook => $delay->begin);
    },
    sub {
      (my $delay, $token, $tx) = @_;

      if ($token) {
        $self->render(json => $self->ua->get('https://graph.facebook.com/me?access_token=' . $token)->res->json);
      }
      else {
        $self->render(json => $tx->res->json || $tx->error);
      }
    }
  );
};

my $t = Test::Mojo->new;

$t->get_ok('/connect')->status_is(302)->header_like(Location => qr|https://graph\.facebook\.com/oauth/authorize|)
  ->header_like(Location => qr|\bclient_id=$ENV{OAUTH_FB_KEY}\b|)
  ->header_like(Location => qr|\bredirect_uri=https?://[^/]+/connect\b|);

# This i a bit ugly. Maybe it should be factored out in a different test?
if ($ENV{OAUTH_FB_KEY} eq 'fail') {
  $t->get_ok('/connect?code=123')->json_is('/error/code', 101)->json_is('/error/type', 'OAuthException')
    ->json_has('/error/message');
}

done_testing;
