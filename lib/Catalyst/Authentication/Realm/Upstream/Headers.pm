package Catalyst::Authentication::Realm::Upstream::Headers;

use strict;
use warnings;

use base 'Catalyst::Authentication::Realm';

use Catalyst::Authentication::Realm::Upstream::Headers::User;

__PACKAGE__->mk_accessors(qw/user_header role_header/);

sub new
{
	my $class	= shift;
	my $name	= shift;
	my $config	= shift;
	my $app		= shift;

	my $self = $class->next::method($name, {}, $app);

	$config->{user_header} ||= 'X-Catalyst-Auth-Upstream-User';
	$config->{role_header} ||= 'X-Catalyst-Auth-Upstream-Roles';

	$self->user_header($config->{user_header});
	$self->role_header($config->{role_header});

	return $self;
}

sub authenticate
{
	my $self	= shift;
	my $c		= shift;

	# This method is a no-op for the most part.  The work that is done
	# here is mostly marshalling the request headers into user objects
	# that fit the authentication plugin's interface.

	my $user = undef;

	if (my $username = $c->req->headers->header($self->user_header)) {
		my @roles = split /, */, $c->request->headers->header($self->role_header) || '';

		$user = new Catalyst::Authentication::Realm::Upstream::Headers::User
			_username	=> $username,
			_roles		=> \@roles;

		$c->set_authenticated($user, $self->name);
	}

	return $user;
}

1;

__END__

=head1 NAME

Catalyst::Authentication::Realm::Upstream::Headers

=head1 SYNOPSIS

 use Catalyst qw(Authentication);

 __PACKAGE__->config(
     authentication => {
         default_realm => 'upstream',
         realms => {
             upstream => {
                 class => 'Upstream::Headers',
                 user_header => 'X-Header-Containing-Username',
                 role_header => 'X-Header-Containing-Comma-Separated-List-Of-Roles'
             }
         }
     }
 );

=head1 DESCRIPTION

This authentication realm for Catalyst::Plugin::Authentication was
originally implemented to support OpenAM in a way that fit into the
framework provided by C::P::A.

OpenAM (formerly Sun's OpenSSO) is a federated identity management
platform.  It is a complex product supporting SAML and integration
with Microsoft's Active Directory.  OpenAM provides authentication
and authorization services to web applications by utilizing agents
that run alongside the application.  The agents are implemented as
plugins for popular HTTP servers, injecting logic into the request
handler, and applying policy based upon upstream configuration.

One of the methods of passing identity information back down to the
application is by including the information in the request headers.
Thus, this authentication realm implementation was born.

=head1 CAVEATS

I really hope I don't have to say it, but -- don't let users bypass
your authentication mechanisms by passing the headers themselves.

=head1 AUTHOR

Mike Eldridge <diz@cpan.org>

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2012 by Infinity Interactive, Inc.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

