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
  $self->oauth2->get_token_p('facebook')->then(
    sub {
      return unless my $provider_res = shift;    # Redirect
      $self->render(
        json => $self->ua->get("https://graph.facebook.com/me?access_token=$provider_res->{access_token}")->res->json);
    }
  )->catch(
    sub {
      $self->render(json => {message => shift, status => 500});
    }
  );
};

my $t = Test::Mojo->new;

$t->get_ok('/connect')->status_is(302)->header_like(Location => qr|https://graph\.facebook\.com/oauth/authorize|)
  ->header_like(Location => qr|\bclient_id=$ENV{OAUTH_FB_KEY}\b|)
  ->header_like(Location => qr|\bredirect_uri=https?://[^/]+/connect\b|);

# This i a bit ugly. Maybe it should be factored out in a different test?
if ($ENV{OAUTH_FB_KEY} eq 'fail') {
  $t->get_ok('/connect?code=123')->status_is(500)->json_has('/message');
}

done_testing;
