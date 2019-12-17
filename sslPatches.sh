#!/bin/bash

export LD_LIBRARY_PATH=/usr/local/pqpki-openssl1.0.2o/lib:$LD_LIBRARY_PATH

git clone https://github.com/isaracorp/test-pqpki-patches.git
git clone https://github.com/isaracorp/openssl.git -b test-pqpki-v1.0.0
cd openssl
git apply ~/test-pqpki-patches/v1.0.0/test-pqpki-openssl.patch
cd ..
git clone https://github.com/cisco/libest.git -b rel-2.1.0
cd libest
git apply ~/test-pqpki-patches/v1.0.0/test-pqpki-libest.patch
cd ..
cd openssl
./config --prefix=/usr/local/pqpki-openssl1.0.2o \
    --openssldir=/usr/local/pqpki-openssl1.0.2o shared
make
make install
cd ..

cd libest
./configure --with-ssl-dir=/usr/local/pqpki-openssl1.0.2o
make
cd ..


cd libest
export
export PATH=/usr/local/pqpki-openssl1.0.2o/bin:$PATH
./mpkac_test.sh
