package Catalyst::Authentication::Credential::Upstream::Headers;

use Moose;

has user_header =>
	isa		=> 'Str',
	is		=> 'ro',
	default	=> 'X-Catalyst-Credential-Upstream-User';

has role_header =>
	isa		=> 'Str',
	is		=> 'ro',
	default	=> 'X-Catalyst-Credential-Upstream-Roles';

has realm =>
	isa			=> 'Catalyst::Authentication::Realm',
	is			=> 'ro',
	required	=> 1;

sub BUILDARGS
{
	my $class	= shift;
	my $config	= shift;
	my $app		= shift;
	my $realm	= shift;

	return { %$config, realm => $realm };
}

sub authenticate
{
	my $self	= shift;
	my $c		= shift;

	# This method is a no-op for the most part.  The work that is done
	# here is mostly marshalling the request headers into user objects
	# that fit the authentication plugin's interface.

	my $info = undef;

	if (my $username = $c->req->headers->header($self->user_header)) {
		my @roles = split /, */, $c->req->headers->header($self->role_header) || '';

		$info = { id => $username, roles => \@roles };
	}

	return $info ? $self->realm->find_user($info) : undef;
}

1;

__END__

=head1 NAME

Catalyst::Authentication::Credential::Upstream::Headers

=head1 SYNOPSIS

 use Catalyst qw(Authentication);

 __PACKAGE__->config(
     authentication => {
         default_realm => 'upstream',
         realms => {
             upstream => {
                 credential => {
                     class => 'Upstream::Headers',
                     user_header => 'X-Header-Containing-Username',
                     role_header => 'X-Header-Containing-Comma-Separated-List-Of-Roles'
                 }
             }
         }
     }
 );

=head1 DESCRIPTION

This authentication credential for Catalyst::Plugin::Authentication
was originally implemented to support OpenAM in a way that fit into
the framework provided by C::P::A.

OpenAM (formerly Sun's OpenSSO) is a federated identity management
platform.  It is a complex product supporting SAML and integration
with Microsoft's Active Directory.  OpenAM provides authentication
and authorization services to web applications by utilizing agents
that run in front of the application.  The agents are implemented as
plugins for popular HTTP servers, injecting logic into the request
handler and applying policy based upon upstream configuration.

One of the methods of passing identity information back down to the
application is by including the information in the request headers.
This is similar in scope to the Credential::Remote implementation,
but using headers instead of environment variables.

=head1 CAVEATS

=over 2

=item

I really hope I don't have to say it, but don't let users bypass
your authentication mechanisms by passing the headers themselves.

=item

This is a pretty crappy way of passing identity metadata around.

=back

=head1 AUTHOR

Mike Eldridge <diz@cpan.org>

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2012 by Infinity Interactive, Inc.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

