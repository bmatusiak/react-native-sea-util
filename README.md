# react-native-sea-util

SEA crypto graphic utilities, for react native

* Android Suppot: YES
* iOS Support: NO



## Installation

```sh
npm install github:bmatusiak/react-native-sea-util
```

## Usage

```js
import 'react-native-sea-util';
import Gun from 'gun';
import SEA from 'gun/sea'
```

## References

Inspired by: https://github.com/tectiv3/react-native-aes

KeyType is specified in [RFC 6090](https://datatracker.ietf.org/doc/html/rfc6090)

### Signature

https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/sign#ecdsa

https://datatracker.ietf.org/doc/html/rfc4754#section-3

### work

PBKDF2 is specified in [RFC 2898](https://datatracker.ietf.org/doc/html/rfc2898).

SHA-256 is specified in [NIST.FIPS.180-4.pdf](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)

### spongycastle references

https://github.com/rtyley/spongycastle

[ECTest.java](https://github.com/rtyley/spongycastle/blob/spongy-master/core/src/test/java/org/spongycastle/crypto/test/ECTest.java)


```

#dev setup

npx react-native@0.70.6 init SEATest --version 0.70.6
cd ./SEATest

git clone https://github.com/bmatusiak/react-native-sea-util.git
npm install github:amark/gun github:bmatusiak/gun-rebuild github:bmatusiak/gun-rebuild-sea #new

npm install buffer text-encoding react-native-webview react-native-webview-crypto react-native-get-random-values #old

rm ./App.js #remove app.js
cp ./react-native-sea-util/example/App.js ./App.js #copy dev file

# remove pretty and eslint configs if needed 



```