package Mojolicious::Plugin::OAuth2;

use base qw/Mojolicious::Plugin/;
use Carp qw/croak/;
use strict; 

our $VERSION='0.5';

__PACKAGE__->attr(providers=>sub {
    return {
        facebook => {
            authorize_url => "https://graph.facebook.com/oauth/authorize",
            token_url => "https://graph.facebook.com/oauth/access_token",
        },
        dailymotion => {
            authorize_url => "https:/api.dailymotion.com/oauth/authorize",
            token_url => "https:/api.dailymotion.com/oauth/token"
        },
        gowalla => {
            authorize_url => "https://gowalla.com/api/oauth/new",
            token_url     => "https://api.gowalla.com/api/oauth/token",
        },
        google => {
            authorize_url => "https://accounts.google.com/o/oauth2/auth?response_type=code",
            token_url     => "https://accounts.google.com/o/oauth2/token",
        },
        
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
            my ($c,$provider_id,%args)= @_;
            $args{callback} ||= $args{on_success};
            $args{error_handler} ||= $args{on_failure};
            croak "Unknown provider $provider_id" 
                unless (my $provider=$self->providers->{$provider_id});
            if($c->param('code')) {
                my $fb_url=Mojo::URL->new($provider->{token_url});
                my $params={
                    client_secret => $provider->{secret},
                    client_id     => $provider->{key},
                    code          => $c->param('code'),
                    redirect_uri  => $c->url_for->to_abs->to_string,
                    grant_type    => 'authorization_code',
                };
                if ($args{async}) {
                    $c->ua->post_form($fb_url->to_abs, $params => sub {
                        my ($client,$tx)=@_;
                        if (my $res=$tx->success) {
                          &{$args{callback}}($self->_get_auth_token($res));
                        }
                        else {
                            my ($err)=$tx->error;
                            &{$args{error_handler}}($tx) if(exists $args{error_handler});
                        }
                        });
                        $c->render_later;
                }
                else {
                    my $tx=$c->ua->post_form($fb_url->to_abs,$params);
                    if (my $res=$tx->success) {
                         &{$args{callback}}($self->_get_auth_token($res));
                     }
                     else {
                         my ($err)=$tx->error;
                         &{$args{error_handler}}($tx) if(exists $args{error_handler});
                     }
                }
            } else {
                my $fb_url=Mojo::URL->new($provider->{authorize_url});
                $fb_url->query->append(
                    client_id=> $provider->{key},
                    redirect_uri=>$c->url_for->to_abs->to_string,
                );
                $fb_url->query->append(scope => $args{scope}) 
                    if exists $args{scope};
                $c->redirect_to($fb_url);
             }
    });
}

sub _get_auth_token {
  my ($self,$res)=@_;
  if($res->headers->content_type eq 'application/json') {
    return $res->json->{access_token};
  }
  my $qp=Mojo::Parameters->new($res->body);
  return $qp->param('access_token');
}

1;

=head1 NAME

Mojolicious::Plugin::OAuth2 - Auth against OAUth2 APIs

=head1 SYNOPSIS 

   plugin 'OAuth2',
       facebook => {
          key => 'foo',
          secret => 'bar' 
       };
   
   get '/auth' => sub {
      my $self=shift;
      $self->get_token('facebook',on_success=>sub {
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

=head2 get_token <$provider>, <%args>

Will redirect to the provider to allow for authorization, then fetch the 
token. The token gets provided as a parmeter to the callback function. 
Usually you want to store the token in a session or similar to use for 
API requests. Supported arguments:

=over 4

=item on_success

Callback method to handle the provided token. Gets the token as it's only argument

=item on_failure

Callback method to handle any error. Gets the failed transaction as it's only argument.

=item scope

Scope to ask for credentials to. Should be a space separated list.

=item async

Use async request handling to fetch token.

=back

=head1 CONFIGURATION

=head2 providers 

Takes a hashref of providers, each one with a hashref of options. For instance:

    plugin 'OAuth2', {
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

=item dailymotion

Authentication for Dailymotion video site.

=item gowalla

Gowalla.com authentication.

=back

=head2 AUTHOR

Marcus Ramberg L<mailto:mramberg@cpan.org>

=head2 LICENSE

This software is licensed under the same terms as Perl itself.

=cut
