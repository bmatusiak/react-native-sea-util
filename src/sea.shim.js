module.exports = function shim(SeaUtil) {
    const Buffer = (() => require("buffer").Buffer)();
    const { TextEncoder, TextDecoder } = (() => require("text-encoding"))();
    (function () {
        window = global || window;
        global.Buffer = global.Buffer || Buffer;
        global.TextEncoder = TextEncoder;
        global.TextDecoder = TextDecoder;
        window.crypto = window.crypto || {};
        window.localStorage = () => { };
        window.crypto.getRandomValues = function getRandomValues(typedArray) {
            console.log("need to get rid of this")
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
    })();
    const elliptic = require("elliptic");//pair/secret/sign/verify
    const SEA = (function (window) {
        var SEA = window.SEA || {};
        SEA.RN = true;
        var EC = elliptic.ec;
        var ECDH = new EC('p256');
        var ECDSA = new EC('p256');

        // setTimeout(function () {
        //     (async () => {
        //         var $msg = await doWork("data", null, function () { }, { name: "sha" })
        //         // if ($msg) 
        //         console.log("doWork-sha", $msg)
        //         var gun_pair;
        //         // gun_pair = await doPair();
        //         // gun_pair = await doPair(true,"a",["b","c"]);
        //         gun_pair = {
        //             "epriv": "kzFOKjHTcHzjHhhDq-2yRVSeuPDL_bcm6BYFAeMXa6c",
        //             "epub": "V9PSJ-SZJ4RiuKzs1pkTmgiJfehfrngjWwJzKKZwIQ8.L5smkg1kXidIZtA2bXBzun_ylX-DWv4Wf7xanuFVsMM",
        //             "priv": "Pkl3X-2dOgbplyhQLIpbbV-pUgjhyjUxPL942j9kCSc",
        //             "pub": "BX1AbGMWavegl_37goBJYlNEt18X9TE5a3IZL5yj1mw.on7CNrmgB0JRx9yiHi1-SCPvDlmsVGBdFQ2cxnziGI4"
        //         };
        //         // console.log("doPair", gun_pair);
        //         $msg = await doWork($msg, "salty");
        //         if ($msg) console.log("doWork", $msg)
        //         var aeskey = await doDerive(gun_pair.epub, gun_pair);
        //         if (aeskey) console.log("doDerive", aeskey);
        //         var sig = await doSign($msg, gun_pair);
        //         if (sig) console.log("doSign", sig);
        //         var ver = await doVerify(sig, gun_pair.pub);
        //         if (ver) console.log("doVerify", ver);
        //         var enc = await doEncrypt($msg, aeskey);
        //         if (enc) console.log("doEncrypt", enc);
        //         var dec = await doDecrypt(enc, aeskey);
        //         if (dec) console.log("doDecrypt", dec);


        //         var sig = await doSign({ test: "some_object" }, gun_pair);
        //         if (sig) console.log("doSign", sig);

        //         var ver = await doVerify(sig, gun_pair.pub);
        //         if (ver) console.log("doVerify", typeof ver, ver.test == "some_object");

        //     })()
        // }, 1000);

        function hash_key(data, additional_data) {
            var ec = new EC('p256');
            var h = ec.hash().update(data)
            if (additional_data) {
                if (!(additional_data instanceof Array)) additional_data = [additional_data];
                for (let i = 0; i < additional_data.length; i++) {
                    if (!additional_data[i]) continue;
                    h.update(additional_data[i]);
                }
            }
            return h.digest();
        }

        function genKeyPair(private_key, additional_data) {
            var ec = new EC('p256');
            if (additional_data && !(additional_data instanceof Array))
                additional_data = [additional_data];
            var pair;
            if (private_key) {
                pair = ec.keyFromPrivate(hash_key(private_key, additional_data))
            }
            else
                pair = ec.genKeyPair();
            var pub = pair.getPublic();
            var x = pub.getX().toBuffer();
            var y = pub.getY().toBuffer();
            var priv = pair.getPrivate().toBuffer();
            if (!arrayBufToBase64UrlDecode(x = arrayBufToBase64UrlEncode(x)).length == 32 ||//have a bug where x value was 31 and not 32 ... but i cant produce it.. 
                !arrayBufToBase64UrlDecode(y = arrayBufToBase64UrlEncode(y)).length == 32)
                return genKeyPair(1, priv);
            pub = x + "." + y;
            priv = arrayBufToBase64UrlEncode(priv);
            return { pub: pub, priv: priv };
        }

        async function doPair(deterministic, data, add_data) {
            var pair;
            if (deterministic) {
                pair = (() => {
                    var { pub, priv } = genKeyPair(data, ["s"].concat(add_data));
                    var { pub: epub, priv: epriv } = genKeyPair(data, ["d"].concat(add_data));
                    return { pub, priv, epub, epriv };
                })();
            } else
                pair = (() => {
                    var { pub, priv } = genKeyPair();
                    var { pub: epub, priv: epriv } = genKeyPair();
                    return { pub, priv, epub, epriv };
                })();
            return pair;
        }
        SEA.pair = doPair;

        async function doWork(data, pair, cb, opt) {
            var u;
            var salt = (pair || {}).epub || pair; // epub not recommended, salt should be random!
            opt = opt || {};
            if (salt instanceof Function) {
                cb = salt;
                salt = u;
            }
            data = (typeof data == 'string') ? data : await shim.stringify(data);
            if ('sha' === (opt.name || '').toLowerCase().slice(0, 3)) {
                var rsha = shim.Buffer.from(await hash256(data), 'binary').toString(opt.encode || 'base64')
                if (cb) { try { cb(rsha) } catch (e) { console.log(e) } }
                return rsha;
            }
            salt = salt || (await shim.random(9));
            var S = { pbkdf2: { hash: { name: 'SHA-256' }, iter: 100000, ks: 64 } };
            var r = await SeaUtil.pbkdf2(data, salt, S.pbkdf2.iter, S.pbkdf2.ks * 8);
            data = (await shim.random(data.length))  // Erase data in case of passphrase
            if (cb) { try { cb(r) } catch (e) { console.log(e) } }
            return r;
        }
        SEA.work = doWork;

        async function doDerive(key, pair, cb, opt) {
            opt = opt || {};
            if (!pair || !pair.epriv || !pair.epub) {
                if (!SEA.I) { throw 'No secret mix.' }
                pair = await SEA.I(null, { what: key, how: 'secret', why: opt.why });
            }
            var pub = key.epub || key;
            // var epub = pair.epub;
            var epriv = pair.epriv || pair;
            var r = await SeaUtil.secret(pub, epriv);
            if (cb) { try { cb(r) } catch (e) { console.log(e) } }
            return r;
        }
        SEA.secret = doDerive;

        async function doVerify(data, pair, cb, opt) {
            var u;
            var json = await shim.S.parse(data);
            if (false === pair) { // don't verify!
                var raw = await shim.S.parse(json.m);
                if (cb) { try { cb(raw) } catch (e) { console.log(e) } }
                return raw;
            }
            opt = opt || {};
            opt.ok = "?";
            // SEA.I // verify is free! Requires no user permission.
            var pub = pair.pub || pair;
            var json_dd = await hash256(json.m);
            var check = await SeaUtil.verify(pub, json_dd, json.s);
            if (!check) { throw "Signature did not match." }
            var r = check ? await shim.S.parse(json.m) : u;
            if (cb) { try { cb(r) } catch (e) { console.log(e) } }
            return r;
        }
        SEA.verify = doVerify;

        async function doSign(data, pair, cb, opt) {
            var u;
            opt = opt || {};
            if (!(pair || opt).priv) {
                if (!SEA.I) { throw 'No signing key.' }
                pair = await SEA.I(null, { what: data, how: 'sign', why: opt.why });
            }
            if (u === data) { throw '`undefined` not allowed.' }
            var json = await shim.S.parse(data);
            var check = opt.check = opt.check || json;
            if (SEA.verify && (SEA.opt.check(check) || (check && check.s && check.m))
                && u !== await SEA.verify(check, pair)) { // don't sign if we already signed it.
                var r = await shim.S.parse(check);
                if (!opt.raw) { r = 'SEA' + await shim.stringify(r) }
                if (cb) { try { cb(r) } catch (e) { console.log(e) } }
                return r;
            }
            var priv = pair.priv;
            var json_dd = await hash256(json);
            var siged = await SeaUtil.sign(priv, json_dd);
            var sig = { m: json, s: siged };
            if (!opt.raw) { sig = 'SEA' + await shim.stringify(sig) }
            if (cb) { try { cb(sig) } catch (e) { console.log(e) } }
            return sig;
        }
        SEA.sign = doSign;

        async function doEncrypt(data, pair, cb, opt) {
            var u;
            opt = opt || {};
            var key = (pair || opt).epriv || pair;
            if (u === data) { throw '`undefined` not allowed.' }
            if (!key) {
                if (!SEA.I) { throw 'No encryption key.' }
                pair = await SEA.I(null, { what: data, how: 'encrypt', why: opt.why });
                key = pair.epriv || pair;
            }
            var msg = (typeof data == 'string') ? data : await shim.stringify(data);
            var iv = Buffer.from(await shim.random(15)).toString("base64");
            var salt = Buffer.from(await shim.random(9));
            var tkey = key + bytes2string(salt)
            var pKey = Array.from(await hash256_utf8(tkey));
            msg = Buffer.from(msg).toString("base64");
            pKey = Buffer.from(pKey).toString("base64");
            var ct = await SeaUtil.encrypt(msg, pKey, iv);
            var r = {
                ct,
                s: salt.toString("base64"),
                iv: iv
            }
            if (!opt.raw) { r = 'SEA' + await shim.stringify(r) }
            if (cb) { try { cb(r) } catch (e) { console.log(e) } }
            return r;
        }
        SEA.encrypt = doEncrypt;

        async function doDecrypt(data, pair, cb, opt) {
            opt = opt || {};
            var key = (pair || opt).epriv || pair;
            if (!key) {
                if (!SEA.I) { throw 'No decryption key.' }
                pair = await SEA.I(null, { what: data, how: 'decrypt', why: opt.why });
                key = pair.epriv || pair;
            }
            var json = await shim.S.parse(data);
            var tkey = key + bytes2string(Buffer.from(json.s, "base64"))
            var pKey = Array.from(await hash256_utf8(tkey));
            var ctx = u8(Buffer.from(json.ct, "base64"));
            var tag = ctx.slice(ctx.length - 16, ctx.length);
            var ct = ctx.slice(0, ctx.length - 16);
            var r = await SeaUtil.decrypt(
                Buffer.from(ct).toString("base64"),
                Buffer.from(pKey).toString("base64"),
                json.iv,
                Buffer.from(tag).toString("base64"),
            )

            if (cb) { try { cb(r) } catch (e) { console.log(e) } }
            return r;
        }
        SEA.decrypt = doDecrypt;

        //------------

        function u8(a) {
            return Uint8Array.from(a);
        }
        async function hash256(d) {
            var t = (typeof d == 'string') ? d : await shim.stringify(d);
            return await hash256_utf8(t);
        }
        function hash256_utf8(s) {
            return sha256_native(s);
            async function sha256_native(s) {
                if (!(typeof s == "string")) s = bytes2string(s);
                return await SeaUtil.sha256_utf8(s)
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
        function hexStrToDec(hexStr) {
            return ~~(new Number('0x' + hexStr).toString(10));
        }
        async function sha256_n1(s) {
            sha256_n2(s);
            var b2s = !(typeof s == "string");
            s = new TextEncoder().encode(b2s ? bytes2string(s) : s);
            var r = await SeaUtil.sha256bytes(Buffer.from(s).toString("base64"));
            var x = Buffer.from(r, "hex");
            console.log("n1", Array.from(x))
            return u8(x)
        }
        // async function sha256_n(s) {
        //     var r = await SeaUtil.sha256_bytes(string2bytes(s));
        //     return new Uint8Array(Buffer.from(r));
        // }
        // async function sha256_utf8_n(s) {
        //     const digest = await SeaUtil.sha256(s);
        //     const hash = Buffer.from(digest.match(/.{2}/g).map(hexStrToDec));
        //     return hash;
        // }
        function u2f_unb64(s) {
            s = s.replace(/-/g, '+').replace(/_/g, '/');
            return atob(s + '==='.slice((s.length + 3) % 4));
        }
        // function u2f_b64(s) {
        //     return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        // }
        function arrayBufToBase64UrlEncode(buf) {
            var binary = '';
            var bytes = new Uint8Array(buf);
            for (var i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary).replace(/\//g, '_').replace(/=/g, '').replace(/\+/g, '-');
        }
        function arrayBufToBase64UrlDecode(ba64) {
            var binary = u2f_unb64(ba64);
            var bytes = [];
            for (var i = 0; i < binary.length; i++) {
                bytes.push(binary.charCodeAt(i));
            }

            return new Uint8Array(bytes);
        }
        async function getRandomValues(len) {
            return Uint8Array.from(await SeaUtil.randomBytes(len));
        }
        var shim = { Buffer }
        // shim.crypto = window.crypto || window.msCrypto
        // shim.subtle = (shim.crypto || o).subtle || (shim.crypto || o).webkitSubtle;
        shim.TextEncoder = TextEncoder;
        shim.TextDecoder = TextDecoder;
        shim.random = async (len) => shim.Buffer.from(await getRandomValues(len));
        shim.parse = function (t, r) {
            return new Promise(function (res, rej) {
                JSON.parseAsync(t, function (err, raw) { err ? rej(err) : res(raw) }, r);
            })
        }
        shim.stringify = function (v, r, s) {
            return new Promise(function (res, rej) {
                JSON.stringifyAsync(v, function (err, raw) { err ? rej(err) : res(raw) }, r, s);
            })
        }
        shim.S = {};
        shim.S.parse = async function p(t) {
            try {
                var yes = (typeof t == 'string');
                if (yes && 'SEA{' === t.slice(0, 4)) { t = t.slice(3) }
                return yes ? await shim.parse(t) : t;
            } catch (e) { null; }
            return t;
        }

        window.SEA = SEA;
    })(window);

    return SEA;
}
