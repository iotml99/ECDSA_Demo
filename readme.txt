Date : 06-01-2021

Title : ECDSA Demo Using OPENSSL library

Platform:
    1. Code has been developed and tested on Ubuntu 18.04 LTS
    2. GCC version 7.5
    3. OpenSSL version 1.1.1

Installation Instructions:
    sudo apt-get install gcc openssl

Build Command
    gcc -g -lssl -UOPENSSL_NO_EC ecdsa_main.c -lcrypto -o ecdsa_demo

Run Command
    ./ecdsa_demo

Demo Details:
    The demo covers following aspects of ECDSA
    1. EC Key generation
    2. ECDSA Signature of message hash
    3. EDCSA Verification using generated signature - verify OK
    4. Alter message hash and run verification - reject

