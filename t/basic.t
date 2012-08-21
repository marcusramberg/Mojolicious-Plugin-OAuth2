use Mojolicious::Lite;
use Test::Mojo;
use Test::More;

my $t=Test::Mojo->new;
my $host = $t->ua->app_url->host;
my $port = $t->ua->app_url->port;

plugin 'OAuth2', test => {
    authorize_url => Mojo::URL->new("http://$host:$port/fake_auth"),
    token_url => Mojo::URL->new("http://$host:$port/fake_token"),
    key    => 'fake_key',
    secret => 'fake_secret',
    scope => 'a,b,c',
};

get '/auth_url' => sub {
    my $self=shift;
    $self->render_text($self->get_authorize_url('test'));
};
get '/auth_url_with_custom_redirect' => sub {
    my $self=shift;
    $self->render_text($self->get_authorize_url('test', redirect_uri => 'http://mojolicio.us/foo'));
};

get '/oauth-original' => sub { 
    my $self=shift;
    $self->get_token('test', callback => sub {
        my $token=shift;
        $self->render(text=>'Token '.$token);
    },
    error_handler => sub { status=>500,$self->render(text=>'oauth failed to get'.shift->req->uri)},
    async => 1,
    scope => 'fakescope',
    authorize_query => { extra => 1 });
} => 'foo';

get '/oauth-delayed' => sub { 
    my $self = shift;
    Mojo::IOLoop->delay(
        sub {
            my $delay = shift;
            $self->get_token(test => $delay->begin)
        },
        sub {
            my($delay, $token, $tx) = @_;
            return $self->render_text($tx->res->error) unless $token;
            return $self->render_text("delayed:$token");
        },
    );
} => 'delay';

get '/oauth-sync' => sub { 
    my $self = shift;
    $self->render_text("sync:" .$self->get_token('test'));
} => 'sync';

get 'fake_auth' => sub {
    my $self=shift;
    if ($self->param('client_id') && $self->param('redirect_uri') && $self->param('scope') && $self->param('extra')) {
        my $return=Mojo::URL->new($self->param('redirect_uri'));
        $return->query->append(code=>'fake_code');
        $self->redirect_to($return);
    }
    else {
        $self->render(status=>404,text=>'REJECTED');
    }
};

post 'fake_token' => sub {
    my $self=shift;
    if($self->param('client_secret') && 
        $self->param('redirect_uri') && 
        $self->param('code')) {
        my $qp=Mojo::Parameters->new(access_token=>'fake_token',lifetime=>3600);
        $self->render(text=>$qp->to_string);
    }
    else {
        $self->render(status=>404,text=>"FAIL OVERFLOW");
    }
};

$t->get_ok('/oauth-original')->status_is(302); # ->content_like(qr/bar/);
my $location=Mojo::URL->new($t->tx->res->headers->location);
my $callback_url=Mojo::URL->new($location->query->param('redirect_uri'));
is($location->query->param('client_id'),'fake_key', 'got client_id');
$t->get_ok($location)->status_is(302);
my $res=Mojo::URL->new($t->tx->res->headers->location);
is($res->path,$callback_url->path,'Returns to the right place');
is($res->query->param('code'),'fake_code','Includes fake code');
$t->get_ok($res)->status_is(200)->content_like(qr/fake_token/);

$res =~ s!/oauth-\w+!/oauth-delayed!;
$t->get_ok($res)->status_is(200)->content_is("delayed:fake_token");

TODO: {
    todo_skip 'Cannot run sync request on $t->ua?', 1;
    $res =~ s!/oauth-\w+!/oauth-sync!;
    $t->get_ok($res)->status_is(200)->content_is("sync:fake_token");
}

$t->get_ok('/auth_url')->status_is(200);
my $url = Mojo::URL->new($t->tx->res->body);
like($url, qr{^http://$host:$port/fake_auth}, 'got correct base url');
is($url->query->param('scope'), 'a,b,c', 'get_authorize_url has correct scope');
is($url->query->param('client_id'), 'fake_key', 'get_authorize_url has correct client_id');
is($url->query->param('redirect_uri'), "http://$host:$port/auth_url", 'get_authorize_url has correct redirect_uri');

$t->get_ok('/auth_url_with_custom_redirect')->status_is(200);
$url = Mojo::URL->new($t->tx->res->body);
is($url->query->param('redirect_uri'), 'http://mojolicio.us/foo', 'get_authorize_url with custom redirect_uri');

done_testing;
