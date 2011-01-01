package Mojolicious::Plugin::OAuth2;

use base qw/Mojolicious::Plugin/;
use Carp qw/croak/;

our $VERSION='0.01';

__PACKAGE__->attr(providers=>sub {
    return {
        facebook => {
            authorize_url => "https://graph.facebook.com/oauth/authorize",
            token_url => "https://graph.facebook.com/oauth/access_token",
        },
        twitter => {},
    };
});

sub register {
    my ($self,$app,$config)=@_;
    my $providers=$self->providers;
    foreach my $provider (keys %$config) {
        if(exists $providers->{$provider}) {
            foreach my $key (keys %{$config->{$provider}}) {
                $providers->{$provider}->{$key}=$config->{$provider}->{$key};
            }
        } else {
            $providers->{$provider}=$config->{$provider};
        }
    }
    $self->providers($providers);
    
    $app->renderer->add_helper(
        get_token => sub {
            my ($c,$provider_id,$callback)= @_;
            croak "Unknown provider $provider_id" 
                unless (my $provider=$self->providers->{$provider_id});
            if($c->param('code')) {
                my $fb_url=Mojo::URL->new($provider->{token_url});
                $fb_url->query->append(
                    client_secret=> $provider->{secret},
                    code => $c->param('code'),
                );
                warn "Doing the async, getting ".$fb_url;
                $c->client->async->get($fb_url,sub {
                    my ($client,$tx)=@_;
                    if ($res=$tx->success) {
                        my $qp=Mojo::Parameters->new($tx->body);
			warn "Doing callback call";
                        $callback_url->($qp->param('access_token') );
                    }
                    else {
                        my ($error,$code)=$tx->error;
                        croak "Failed to get access token: $error ($code)";
                    }
                })->start;
            } else {
                my $fb_url=Mojo::URL->new($provider->{authorize_url});
                $fb_url->query->append(
                    scope => 'user_events',
                    client_id=> $provider->{key},
                    redirect_uri=>$c->url_for->to_abs->to_string,
                );
                $c->redirect_to($fb_url);
             }
    });
}

1;

=head1 NAME

Mojolicious::Plugin::OAuth2 - Auth against OAUth2 APIs

=head1 SYNOPSIS 

   plugin 'oauth2',
       facebook => {
          key => 'foo',
          secret => 'bar' 
       };
   
   get '/auth' => sub {
      my $self=shift;
      $self->get_token('facebook',sub {
         ...
      });
   };

=head1 DESCRIPTION

This Mojolicious plugin allows you to easily authenticate against a OAuth2 
provider. It includes configurations for a few popular providers, but you 
can add your own easily as well.

Note that OAuth2 requires https, so you need to have the optional Mojolicious 
dependency required to support it. Call

   $ mojo version

to check if it is installed. 

=head1 HELPERS

=head2 get_token <$provider>, <$callback>

Will redirect to the provider to allow for authorization, then fetch the 
token. The token gets provided as a parmeter to the callback function. 
Usually you want to store the token in a session or similar to use for 
API requests. 

=head1 CONFIGURATION

=head2 providers 

Takes a hashref of providers, each one with a hashref of options. For instance:

    plugin 'oauth2', {
       iusethis => {
          authorize_url => 'iut.com/auth',
          token_url => 'iut.com/token',
          key => 'foo',
          secret => 'bar',
    }};

The plugin includes configurations a few providers, to use those, just set the key and secret. The currently supported providers are:

=over 4

=item facebook

OAuth for facebook's graph API, L<http://graph.facebook.com/>.

=item Twitter

Twitter OAuth2 support is not official yet, but this endpoint is in use by the twitter anywhere API.

=back

=head2 AUTHOR

Marcus Ramberg L<mailto:mramberg@cpan.org>

=head2 LICENSE

This software is licensed under the same terms as Perl itself.

=cut
