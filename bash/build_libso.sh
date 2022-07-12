#!/bin/bash
BUILD_DIR=../build
if [ ! -d "$BUILD_DIR" ]; then
    mkdir $BUILD_DIR
fi

FILE=../build/libcrypto.so
if test -f "$FILE"; then
    rm $FILE
fi

cd ../src

gcc -shared -fPIC -O3 \
    -I/usr/include \
    ecdh.c md5.c aes.c crypto.c -o $BUILD_DIR/libcrypto.so

