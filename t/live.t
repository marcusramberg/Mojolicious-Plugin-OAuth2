use Test::More;
use Mojolicious::Lite;
use Test::Mojo;
use Test::More;

unless($ENV{OAUTH_FB_KEY} && $ENV{OAUTH_FB_SECRET}) {
    plan skip_all => 'OAUTH_FB_KEY and OAUTH_FB_SECRET must be set for oauth tests';
}

plugin 'o_auth2', facebook => {
    key    => $ENV{OAUTH_FB_KEY},
    secret => $ENV{OAUTH_FB_SECRET}
};

get '/oauth' => sub { 
    my $self=shift;
    if(my $token=$self->get_token('facebook')) {
        my $me=$self->client->get('https://graph.facebook.com/me?access_token='.$token)->res->json;
        $self->render(text=>'Hello '.$me->{name});
    }};

my $t=Test::Mojo->new;

$t->get_ok('/oauth')->status_is(301); # ->content_like(qr/bar/);

done_testing;