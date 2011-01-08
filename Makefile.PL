#!/usr/bin/env perl

use 5.008007;

use strict;
use warnings;

# Son, when you participate in sporting events,
# it's not whether you win or lose, it's how drunk you get.
use ExtUtils::MakeMaker;

my ($mm) = $ExtUtils::MakeMaker::VERSION =~ /^([^_]+)/;

# We only use core modules, so you shouldn't have to install anything besides
# Perl 5.8.7!
WriteMakefile(
    NAME         => 'Mojolicious::Plugin::OAuth2',
    VERSION_FROM => 'lib/Mojolicious/Plugin/OAuth2.pm',
    ABSTRACT     => 'Authenticate against OAuth2 providers',
    AUTHOR       => 'Marcus Ramberg <mramberg@cpan.org>',

    ($mm < 6.3002 ? () : ('LICENSE' => 'artistic_2')),

    (   $mm < 6.46
        ? ()
        : ( META_MERGE => {
                requires  => {perl => '5.008007'},
                resources => {
                    license  => 'http://dev.perl.org/licenses/',
                    repository => 'http://github.com/kraih/mojolicious-plugin-oauth2',
                    bugtracker => 'http://github.com/kraih/mojolicious-plugin-oauth2/issues'
                },
                no_index => {directory => [qw/t/]}
            },
            META_ADD => {
                build_requires     => {},
                configure_requires => {}
            },
        )
    ),

    PREREQ_PM => {
        'Mojolicious'           => '1.01',
    },
    test => {TESTS => 't/*.t t/*/*.t t/*/*/*.t t/*/*/*/*.t'}
);
