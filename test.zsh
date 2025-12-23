#!/bin/zsh

in=$1
enc="enc.$in"
dec="dec.$in"

ENC=des
PAD=zeros
BLM=ecb
KEY=12345678
# KEY=1234567887654321
# ENC_KEY=123456788765432112345678
# ENC_KEY=12345678876543211234567887654321


swift run -c release CryptoCmd encrypt -p=$PAD -t=$ENC -b=$BLM $KEY $in $enc
swift run -c release CryptoCmd decrypt -p=$PAD -t=$ENC -b=$BLM $KEY $enc $dec
diff $in $dec
