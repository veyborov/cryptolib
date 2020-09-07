# Crypto-service

## Installation
1. clone repository
2. docker build -t crypto-service .
3. docker run -d -p <local-port>:3010 crypto-service

## Environment variables
```
CRYPTO_PORT=3010
A=0
B=7
P=115792089237316195423570985008687907853269984665640564039457584007908834671663
Q=115792089237316195423570985008687907852837564279074904382605163141518161494337
X_BASE=55066263022277343669578718895168534326250603453777594175500187360389116729240
Y_BASE=32670510020758816978083085130507043184471273380659243275938904335757337482424
SEED=randomstring
HASH_LENGTH=256
RSA_LENGTH=4096
```
### Optional
```
WEB_CONCURRENCY=4 
WORKERS_PER_CORE=2
```

# Changelog
2020-09-04 v0.12.0
- RSA blind signature support
- migrated to python3
- validate commission private key method

2020-08-20 v0.10.0
- addCommissionKey method
- verifyEqualityOfDl method
- calculateVotingResultRTK method

2020-08-12 v0.9.4-RC4
- catch exception if mainkey is not valid
- catch exception on verifying invalid bulletin 
- blindSigKey validate

2020-08-06 RT-2
- fixed blind signature generation 

