#!/bin/bash
BUILD_DIR=../build
if [ ! -d "$BUILD_DIR" ]; then
    mkdir $BUILD_DIR
fi

FILE=../build/crypto_test
if test -f "$FILE"; then
    rm $FILE
fi

cd ../src

gcc -ggdb \
    -I/usr/include \
    ecdh.c md5.c aes.c crypto.c crypto_test.c -o ../build/crypto_test

../build/crypto_test