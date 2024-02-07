import { NativeModules } from 'react-native';
window.NativeModules = NativeModules;
const SeaUtil = NativeModules.SeaUtil;
import React, { useEffect } from 'react';
import {
  Button,
  View,
} from 'react-native';

// this script need to check VS crypto lib.

//enable this area to test vs webcrypto .
// import PolyfillCrypto from 'react-native-webview-crypto';
// import 'react-native-get-random-values';
// import 'gun/lib/mobile';

import 'react-native-sea-util';

import Gun from 'gun';
import 'gun/sea';

var SEA = Gun.SEA;

export default function App() {
  useEffect(() => console.log("SEA.RN", SEA.RN), []);
  useEffect(() => {
    (async function () {
      await runTest();
      await runTest3();
      await runTest2();
    })();
  }, []);
  return (
    <View>
      <Button title="start" onPress={() => runTest()}></Button>
      {/* <Button title="gun" onPress={() => runTest_gun()}></Button> */}
      {typeof PolyfillCrypto == "undefined" ? null : (<PolyfillCrypto />)}
    </View>
  )
}

var TEST_PAIR = {
  epriv: "EpOMnime8UQ9Z7EeI2TdQyzyZSJyx9XoyJwR1FQBCRU",
  epub: "xPieZ1m3DSaMxagysQTv7xf78iAAtOsD5vGj1nDycCg.bxBfyvtmBiTRsqsfgenC4NdVyJ9RwWpH5dsu3hyEizQ",
  priv: "TS2BPXbfbagNoTlhSj8Yon0Qmgdg3_xPldPI-Sv3aOI",
  pub: "kW0BHu2NpBvEArX8fr3zwaMObWVLAO8_tcH0UVbzBJk.GzIiFxT2t4lpf34zrDKm_nvi_HmLXxI9cUM2pzICo3E"
};

async function runTest3() {
  console.log("-------START-----runTest3");
  console.log("sign and verify")
  var ECDSA_pair = await SeaUtil.pair();
  var TEST_DATA_d = await hash256(TEST_DATA);

  var sig = await SeaUtil.sign(ECDSA_pair.priv, TEST_DATA_d);
  // console.log(sig);

  var verify = await SeaUtil.verify(ECDSA_pair.pub, TEST_DATA_d, sig);
  console.log(verify ? "WORKS" : "FAILS");

  var d = { m: TEST_DATA, s: sig };
  d = 'SEA' + JSON.stringify(d)
  // console.log(d)
  var sig = await SEA.verify(d, ECDSA_pair.pub);
  // console.log(d);
  // console.log(ECDSA_pair.pub);
  console.log(sig && sig == TEST_DATA ? "WORKS" : "FAILS");


  var sig = (await SEA.sign(TEST_DATA, ECDSA_pair, null, { raw: 1 })).s;
  // console.log(sig)
  var verifyed = await SeaUtil.verify(ECDSA_pair.pub, TEST_DATA_d, sig);
  console.log(verifyed ? "WORKS" : "FAILS");


  // console.log("test sign")
  // var TEST_DATA_d = await hash256(TEST_DATA);
  // var TEST_DATA_dd = await hash256(TEST_DATA_d);
  // var ECDSA_pair = await NativeModules.SeaUtil.pair();
  // ECDSA_pair = TEST_PAIR;
  // // console.log(ECDSA_pair);
  // var sig = (await SEA.sign(TEST_DATA, ECDSA_pair, null, { raw: 1 })).s;
  // // console.log(sig)
  // // var verifyed = await NativeModules.SeaUtil.verify(ECDSA_pair.pub, TEST_DATA_dd, sig);
  // // console.log(verifyed)
  // sig = await NativeModules.SeaUtil.test(ECDSA_pair.priv, TEST_DATA_dd);
  // // console.log(sig)
  // var d = { m: TEST_DATA, s: sig };
  // d = 'SEA' + JSON.stringify(d)
  // // console.log(d)
  // var sig = await SEA.verify(d, ECDSA_pair.pub);
  // console.log(sig && sig == TEST_DATA ? "WORKS" : "FAILS");

  console.log("--------END------");
}

function runTest_gun() {
  console.log("-------START-----");
  (async function () {
    var gun = Gun({ peers: ["http://localhost:8765/gun"] })
    gun.user().auth(TEST_PAIR, function (o) {
      gun.user().get("hi").put(new Date().getTime()).once(() => cb(pair));
    })
    console.log("--------END------");
  })();
}

var TEST_DATA = "Hello World"


async function runTest() {
  console.log("-------START-----runTest");
  await runTest_random();
  await runTest_hash();
  await runTest_pbkdf2();
  await runTest_secret();
  await runTest_verify();
  await runTest_sign();
  await runTest_decrypt();
  await runTest_encrypt();
  console.log("--------END------");
}

async function runTest2() {
  console.log("-------START-----runTest2");
  var fail = false;

  await SEA.pair(function (pair) {
    if (!pair) fail = true
  });
  if (fail) { console.log("failed:randomPair callback"); return }

  var pub = await SeaUtil.publicFromPrivate(TEST_PAIR.priv);
  if (!(pub == TEST_PAIR.pub)) fail = true;
  if (fail) { console.log("failed:publicFromPrivate"); return }

  var epub = await SeaUtil.publicFromPrivate(TEST_PAIR.epriv);
  if (!(epub == TEST_PAIR.epub)) fail = true;
  if (fail) { console.log("failed:publicFromPrivate"); return }

  var theTestA = (await SEA.pair()).priv == (await SEA.pair()).priv;
  if (theTestA) fail = true;
  if (fail) { console.log("failed:theTestA-should not match"); return }

  var theTesB = (await SEA.pair("deterministic", TEST_PAIR.priv, [TEST_PAIR.epriv, "more data"])).priv == (await SEA.pair("deterministic", TEST_PAIR.priv, TEST_PAIR.epriv)).priv;
  if (theTesB) fail = true;
  if (fail) { console.log("failed:theTesB-should not match"); return }

  var theTesC = (await SEA.pair("deterministic", TEST_PAIR.priv, TEST_PAIR.epriv)).priv == (await SEA.pair("deterministic", TEST_PAIR.priv, TEST_PAIR.epriv)).priv;
  if (!theTesC) fail = true;
  if (fail) { console.log("failed:theTesC-no match"); return }

  var theTest = (await SEA.pair.pubFromPrivate(TEST_PAIR.epriv)) == TEST_PAIR.epub;
  if (theTest)
    console.log("WORKS")

  console.log("--------END------");
}

function runTest_sign() {
  return (async function () {
    console.log("test sign")
    var TEST_DATA_d = await hash256(TEST_DATA);
    var TEST_DATA_dd = await hash256(TEST_DATA_d);
    var ECDSA_pair = await NativeModules.SeaUtil.pair();
    ECDSA_pair = TEST_PAIR;
    // console.log(ECDSA_pair);
    var sig = (await SEA.sign(TEST_DATA, ECDSA_pair, null, { raw: 1 })).s;
    // console.log(sig)
    // var verifyed = await NativeModules.SeaUtil.verify(ECDSA_pair.pub, TEST_DATA_dd, sig);
    // console.log(verifyed)
    sig = await NativeModules.SeaUtil.sign(ECDSA_pair.priv, TEST_DATA_d);
    // console.log(sig)
    var d = { m: TEST_DATA, s: sig };
    d = 'SEA' + JSON.stringify(d)
    // console.log(d)
    var sig = await SEA.verify(d, ECDSA_pair.pub);
    console.log(sig && sig == TEST_DATA ? "WORKS" : "FAILS");
    console.log("-----------------");
  })();
}

function runTest_verify() {
  return (async function () {
    console.log("test verify")
    var TEST_DATA_d = await hash256(TEST_DATA);
    var TEST_DATA_dd = await hash256(TEST_DATA_d);
    var ECDSA_pair = await NativeModules.SeaUtil.pair();
    ECDSA_pair = TEST_PAIR;
    // console.log(ECDSA_pair);
    var sig = (await SEA.sign(TEST_DATA, ECDSA_pair, null, { raw: 1 })).s;
    // console.log(sig)
    var verifyed = await NativeModules.SeaUtil.verify(ECDSA_pair.pub, TEST_DATA_d, sig);
    console.log(verifyed ? "WORKS" : "FAILS");
    console.log("-----------------");
  })();
}

function runTest_secret() {
  return (async function () {
    console.log("test secret");
    var ECDH_pair = await NativeModules.SeaUtil.pair();
    var secret = await NativeModules.SeaUtil.secret(TEST_PAIR.epub, ECDH_pair.epriv);
    var secret2 = await SEA.secret(ECDH_pair.epub, TEST_PAIR);
    console.log(secret == secret2 ? "WORKS" : "FAILS");
    console.log("-----------------");
  })();
}

function runTest_pbkdf2() {
  return (async function () {
    console.log("test work-pbkdf2")
    var salt = Buffer.from(await NativeModules.SeaUtil.randomBytesSync(16)).toString("hex");
    var S = { pbkdf2: { hash: { name: 'SHA-256' }, iter: 100000, ks: 64 } };
    var work = await SeaUtil.pbkdf2(TEST_DATA, salt, S.pbkdf2.iter, S.pbkdf2.ks * 8);
    var sea_work = await SEA.work(TEST_DATA, salt);
    console.log(work == sea_work ? "WORKS" : "FAILS");
    console.log("-----------------");
  })();
}

function runTest_hash() {
  return (async function () {
    console.log("test hash");
    var hash1 = await hash256(TEST_DATA);
    var hash2 = await hash256(hash1);
    var hash2_hex_t = "42a873ac3abd02122d27e80486c6fa1ef78694e8505fcec9cbcc8a7728ba8949";
    var hash2_hex = Buffer.from(hash2).toString('hex');
    console.log(hash2_hex == hash2_hex_t ? "WORKS" : "FAILS")
    console.log("-----------------");
  })();
}

function runTest_random() {
  return (async function () {

    console.log("test random");

    var rand;
    rand = await NativeModules.SeaUtil.randomBytes(16);
    console.log("randomBytes:", rand);

    rand = await NativeModules.SeaUtil.randomBytes(16);
    console.log("randomBytes:", rand);

    rand = await NativeModules.SeaUtil.randomBytesSync(16);
    console.log("randomBytesSync:", rand);

    rand = NativeModules.SeaUtil.randomBytesSync(16);
    console.log("randomBytesSync:", rand);

    console.log("-----------------");
  })();
}

function runTest_decrypt() {
  return (async function () {
    console.log("decrypt test");
    var encrypted = await SEA.encrypt(TEST_DATA, TEST_PAIR, null, { raw: 1 });
    var key = TEST_PAIR.epriv;
    var tkey = key + bytes2string(Buffer.from(encrypted.s, "base64"))
    var pKey = Array.from(await NativeModules.SeaUtil.sha256_utf8(tkey));
    var ctx = Uint8Array.from(Buffer.from(encrypted.ct, "base64"));
    var tag = ctx.slice(ctx.length - 16, ctx.length);
    var ct = ctx.slice(0, ctx.length - 16);
    var decrypted = await NativeModules.SeaUtil.decrypt(
      Buffer.from(ct).toString("base64"),
      Buffer.from(pKey).toString("base64"),
      encrypted.iv,
      Buffer.from(tag).toString("base64"),
    )
    console.log(decrypted == TEST_DATA ? "WORKS" : "FAILS");
    console.log("-----------------");
  })();
}

function runTest_encrypt() {
  var random = (len) => Buffer.from(window.crypto.getRandomValues(new Uint8Array(Buffer.alloc(len))));
  return (async function () {
    console.log("encrypt test");
    var key = TEST_PAIR.epriv;
    var msg = TEST_DATA;
    var iv = Buffer.from(random(15)).toString("base64");
    var salt = Buffer.from(random(9));
    var tkey = key + bytes2string(salt)
    var pKey = Array.from(await NativeModules.SeaUtil.sha256_utf8(tkey));
    msg = Buffer.from(msg).toString("base64");
    pKey = Buffer.from(pKey).toString("base64");
    var ct = await SeaUtil.encrypt(msg, pKey, iv);
    var r = {
      ct,
      s: salt.toString("base64"),
      iv: iv
    }
    var encrypted = 'SEA' + JSON.stringify(r);
    var decrypted = await SEA.decrypt(encrypted, TEST_PAIR);
    console.log(decrypted == TEST_DATA ? "WORKS" : "FAILS");
    console.log("-----------------");
  })();
}

//------------------------------
function hash256(s) {
  return sha256_native(s);
  async function sha256_native(s) {
    return await SeaUtil.sha256(string2bytes(s));
  }
}
function bytes2string(bytes) {
  return Array.from(bytes).map(function chr(c) {
    return String.fromCharCode(c);
  }).join('');
}
function string2bytes(s) {
  if (!(typeof s == "string"))
    s = bytes2string(s);
  var len = s.length;
  var bytes = [];
  for (var i = 0; i < len; i++) bytes.push(0);
  for (var j = 0; j < len; j++) bytes[j] = s.charCodeAt(j);
  return bytes;
}
window.crypto.getRandomValues = function getRandomValues(typedArray) {
  var Type;
  if (typedArray instanceof Int8Array) { Type = Int8Array }
  if (typedArray instanceof Uint8Array) { Type = Uint8Array }
  if (typedArray instanceof Uint8ClampedArray) { Type = Uint8ClampedArray }
  if (typedArray instanceof Int16Array) { Type = Int16Array }
  if (typedArray instanceof Uint16Array) { Type = Uint16Array }
  if (typedArray instanceof Int32Array) { Type = Int32Array }
  if (typedArray instanceof Uint32Array) { Type = Uint32Array }
  if (typedArray instanceof BigInt64Array) { Type = BigInt64Array }
  if (typedArray instanceof BigUint64Array) { Type = BigUint64Array }
  var rnd = new Type(Int8Array.from(SeaUtil.randomBytesSync(typedArray.length)));
  for (let i = 0; i < typedArray.length; i++) {
    typedArray[i] = rnd[i];
  }
  return rnd;
}
