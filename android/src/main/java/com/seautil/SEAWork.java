package com.seautil;

import android.util.Base64;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.WritableArray;

import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.params.KeyParameter;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SEAWork {
    public static String pbkdf2(String pwd, String salt, Integer iter, Integer bitSize)
            throws UnsupportedEncodingException
    {
        Digest algorithmDigest = new SHA256Digest();
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(algorithmDigest);
        gen.init(pwd.getBytes(StandardCharsets.UTF_8), salt.getBytes(StandardCharsets.UTF_8), iter);
        byte[] key = ((KeyParameter) gen.generateDerivedParameters(bitSize)).getKey();
        return Base64.encodeToString(key, Base64.NO_WRAP);
    }

    public static byte[] digestBytes(String algo, byte[] data) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algo);
        md.update(data);
        return  md.digest();
    }

    public static byte[] digestString(String algo, String data) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algo);
        md.update(data.getBytes());
        return md.digest();
    }

    public static void sha256_bytes(final ReadableArray toHash, Promise promise) {
        String algo = "SHA-256";
        try {
            byte[] digest = SEAWork.digestBytes(algo, SEAUtil.readableArrayToByteArray(toHash) );
            promise.resolve(SEAUtil.byteArrayToWritableNativeArray(digest));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            promise.reject(algo, e.getMessage());
        }
    }
}
