# You can install this projct with curl -L http://cpanmin.us | perl - https://github.com/marcusramberg/Mojolicious-Plugin-OAuth2/archive/master.tar.gz
requires "Mojolicious" => "7.53";
requires "IO::Socket::SSL" => "1.94";
test_requires "Test::More" => "0.88";

recommends "Mojo::JWT"              => "0.09";
recommends "Crypt::OpenSSL::Bignum" => "0.09";
recommends "Crypt::OpenSSL::RSA"    => "0.31";
