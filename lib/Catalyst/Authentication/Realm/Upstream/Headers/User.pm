package Catalyst::Authentication::Realm::Upstream::Headers::User;

use Moose;

use base 'Catalyst::Authentication::User';

has _username =>
	isa			=> 'Str',
	is			=> 'ro',
	required	=> 1;

has _roles	=>
	isa			=> 'ArrayRef',
	is			=> 'ro',
	required	=> 1;

sub supported_features	{ { roles => 1 } }
sub id					{ shift->_username }
sub roles				{ @{ shift->_roles } }

1;
