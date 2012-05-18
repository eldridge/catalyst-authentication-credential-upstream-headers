package TestApp;

use strict;
use warnings;

use base 'Catalyst';

use Catalyst 'Authentication', 'Authentication::Realm::OpenAM';

#__PACKAGE__->config(
__PACKAGE__->setup;

1;
