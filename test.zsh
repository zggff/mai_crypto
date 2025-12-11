#!/bin/zsh

KEY=1234567887654321
in=$1
enc="enc.$in"
dec="dec.$in"

swift run CryptoCmd encrypt -p=zeros -t=aes -b=ecb $KEY $in $enc
swift run CryptoCmd decrypt -p=zeros -t=aes -b=ecb $KEY $enc $dec
