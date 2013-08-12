package Mojolicious::Plugin::OAuth2;

use base qw/Mojolicious::Plugin/;
use Mojo::UserAgent;
use Carp qw/croak/;
use strict; 

our $VERSION='0.8';

__PACKAGE__->attr(providers=>sub {
    return {
        facebook => {
            authorize_url => "https://graph.facebook.com/oauth/authorize",
            token_url => "https://graph.facebook.com/oauth/access_token",
        },
        dailymotion => {
            authorize_url => "https://api.dailymotion.com/oauth/authorize",
            token_url => "https://api.dailymotion.com/oauth/token"
        },
        google => {
            authorize_url => "https://accounts.google.com/o/oauth2/auth?response_type=code",
            token_url     => "https://accounts.google.com/o/oauth2/token",
        },
        
    };
});

__PACKAGE__->attr(_ua=>sub { Mojo::UserAgent->new });

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
    
    $app->renderer->add_helper(get_authorize_url => sub { $self->_get_authorize_url(@_) });
    $app->renderer->add_helper(
        get_token => sub {
            my $cb = (@_ % 2 == 1 and ref $_[-1] eq 'CODE') ? pop : undef;
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
                if ($args{async} or $cb) {
                    $self->_ua->post($fb_url->to_abs, form => $params => sub {
                        my ($client,$tx)=@_;
                        if (my $res=$tx->success) {
                            my $token = $self->_get_auth_token($res,$provider->{full_json_response});
                            $cb ? $self->$cb($token, $tx) : $args{callback}->($token);
                        }
                        else {
                            $cb ? $self->$cb(undef, $tx) : $args{callback} ? $args{callback}->($tx) : 'noop';
                        }
                    });
                    $c->render_later;
                }
                else {
                    my $tx=$self->_ua->post($fb_url->to_abs, form => $params);
                    if (my $res=$tx->success) {
                        my $token = $self->_get_auth_token($res,$provider->{full_json_response});
                        $args{callback}->($token) if $args{callback};
                        return $token;
                    }
                    elsif($args{error_handler}) {
                        $args{error_handler}->($tx);
                    }
                }
            } else {
                $c->redirect_to($self->_get_authorize_url($c, $provider_id, %args));
             }
    });
}

sub _get_authorize_url {
    my ($self,$c,$provider_id,%args)= @_;
    my $fb_url;

    croak "Unknown provider $provider_id"
        unless (my $provider=$self->providers->{$provider_id});

    $args{scope} ||= $self->providers->{$provider_id}{scope};
    $args{redirect_uri} ||= $c->url_for->to_abs->to_string;
    $fb_url=Mojo::URL->new($provider->{authorize_url});
    $fb_url->query->append(
        client_id=> $provider->{key},
        redirect_uri=>$args{'redirect_uri'},
    );
    $fb_url->query->append(scope => $args{scope})
        if exists $args{scope};
    $fb_url->query($args{authorize_query})
        if exists $args{authorize_query};

    return $fb_url;
}

sub _get_auth_token {
  my ($self,$res,$full_json_response)=@_;
  if($res->headers->content_type eq 'application/json') {
        return $full_json_response ? $res->json : $res->json->{access_token};
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

   get '/auth' => sub {
      my $self = shift;
      Mojo::IOLoop->delay(
          sub {
              my $delay = shift;
              $self->get_token(facebook => $delay->begin)
          },
          sub {
              my($delay, $token, $tx) = @_;
              return $self->render_text($tx->res->error) unless $token;
              return $self->render_text($token);
          },
      );
   };

   my $token = $self->get_token('facebook'); # synchronous request

=head1 DESCRIPTION

This Mojolicious plugin allows you to easily authenticate against a OAuth2 
provider. It includes configurations for a few popular providers, but you 
can add your own easily as well.

Note that OAuth2 requires https, so you need to have the optional Mojolicious 
dependency required to support it. Call

   $ mojo version

to check if it is installed. 

=head1 HELPERS

=head2 get_authorize_url <$provider>, <%args>

Returns a L<Mojo::URL> object which contain the authorize URL. This is
useful if you want to add the authorize URL as a link to your webpage
instead of doing a redirect like C<get_token()> does. C<%args> is optional,
but can contain:

=over 4

=item * authorize_query

Either a hash-ref or an array-ref which can be used to give extra query
params to the URL.

    $url->query($authorize_url);

=item * redirect_uri

Useful if you want to go back to a different page than what you came from.
The default is:

    $c->url_for->to_abs->to_string

=item * scope

Scope to ask for credentials to. Should be a space separated list.

=back

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

=item delay

    $self->get_token($provider => ..., sub {
        my($oauth2, $token, $tx) = @_;
        ...
    })

"delay" is not an key in the C<%args> hash, but rather a callback you can give
at the end of the argument list. This callback will then force "async", and
be used as both a success and error handle: C<$token> will contain a string on
success and undefined on error.

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
