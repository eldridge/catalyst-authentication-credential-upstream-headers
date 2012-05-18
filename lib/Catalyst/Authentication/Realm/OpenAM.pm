package Catalyst::Authentication::Realm::OpenAM;

use strict;
use warnings;

use base 'Catalyst::Authentication::Realm';

__PACKAGE__->mk_accessors(qw/user_header/);

sub new
{
	my $class	= shift;
	my $name	= shift;
	my $config	= shift;
	my $app		= shift;

	# XXX: set HTTP headers that we're looking for

	my $self = $self->next::method($name, {}, $app);

	$self->user_header($config->{user_header});

	return $self;
}

sub authenticate
{
	my $self	= shift;
	my $c		= shift;

	# XXX: this method should be a no-op for the most part (since
	# authentication is done prior to the request handling phase),
	# but it should return a boolean value based upon the presence
	# of the required headers.

}

sub prepare_request
{
	my $self	= shift;
	my $c		= shift;

	my $req = $c->request;

	if ($req->headers->header('x-catalyst-auth-openam-user')) {
		warn '
	}
}

1;
