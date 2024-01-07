package com.seautil;

import android.util.Base64;

import androidx.annotation.NonNull;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableNativeArray;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.module.annotations.ReactModule;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.digests.SHA512Digest;
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.params.KeyParameter;

@ReactModule(name = SeaUtilModule.NAME)
public class SeaUtilModule extends ReactContextBaseJavaModule {
  public static final String NAME = "SeaUtil";

  private static final String KEY_ALGORITHM = "AES";;
  private static final int GCM_TAG_LENGTH = 16;
  public SeaUtilModule(ReactApplicationContext reactContext) {
    super(reactContext);
  }

  @Override
  @NonNull
  public String getName() {
    return NAME;
  }

  @ReactMethod
  public void encrypt_aes_gcm(String data, String key, String iv, Promise promise) {
    try {
      String result = encrypt_aes_gcm(data, key, iv);
      promise.resolve(result);
    } catch (Exception e) {
      promise.reject("-1", e.getMessage());
    }
  }

  @ReactMethod
  public void decrypt_aes_gcm(String data, String pwd, String iv, String tag, Promise promise) {
    try {
      String strs = decrypt_aes_gcm(data, pwd, iv, tag);
      promise.resolve(strs);
    } catch (Exception e) {
      promise.reject("-1", e.getMessage());
    }
  }

  @ReactMethod
  public void pbkdf2(String pwd, String salt, Integer cost, Integer length, String algorithm, Promise promise) {
    try {
      String strs = pbkdf2(pwd, salt, cost, length, algorithm);
      promise.resolve(strs);
    } catch (Exception e) {
      promise.reject("-1", e.getMessage());
    }
  }

  @ReactMethod
  public void sha256(String data, Promise promise) {
    try {
      String result = shaX(data, "SHA-256");
      promise.resolve(result);
    } catch (Exception e) {
      promise.reject("-1", e.getMessage());
    }
  }

  @ReactMethod
  public void sha256bytes(String data, Promise promise) {
    try {
      String result = shaXbytes(data, "SHA-256");
      promise.resolve(result);
    } catch (Exception e) {
      promise.reject("-1", e.getMessage());
    }
  }

  @ReactMethod
  public void sha1(String data, Promise promise) {
    try {
      String result = shaX(data, "SHA-1");
      promise.resolve(result);
    } catch (Exception e) {
      promise.reject("-1", e.getMessage());
    }
  }

  @ReactMethod
  public void sha512(String data, Promise promise) {
    try {
      String result = shaX(data, "SHA-512");
      promise.resolve(result);
    } catch (Exception e) {
      promise.reject("-1", e.getMessage());
    }
  }

  @ReactMethod
  public void randomUuid(Promise promise) {
    try {
      String result = UUID.randomUUID().toString();
      promise.resolve(result);
    } catch (Exception e) {
      promise.reject("-1", e.getMessage());
    }
  }

  @ReactMethod
  public void randomBytes(Integer length, Promise promise) {
    try {
      byte[] key = new byte[length];
      SecureRandom rand = new SecureRandom();
      rand.nextBytes(key);
      String keyHex = bytesToHex(key);
      promise.resolve(keyHex);
    } catch (Exception e) {
      promise.reject("-1", e.getMessage());
    }
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray randomBytesSync( Integer length) {
    byte[] key = new byte[length];
    SecureRandom rand = new SecureRandom();
    rand.nextBytes(key);
    WritableArray map = new WritableNativeArray();
    for ( int j = 0; j < key.length; j++ ) {
      map.pushInt(key[j]);
    }
    return map;
  }

  private String shaX(String data, String algorithm) throws Exception {
    MessageDigest md = MessageDigest.getInstance(algorithm);
    md.update(data.getBytes());
    byte[] digest = md.digest();
    return bytesToHex(digest);
  }

  private String shaXbytes(String data, String algorithm) throws Exception {
    MessageDigest md = MessageDigest.getInstance(algorithm);
    md.update(Base64.decode(data, Base64.NO_WRAP));
    byte[] digest = md.digest();
    return bytesToHex(digest);
  }


  private static String pbkdf2(String pwd, String salt, Integer cost, Integer length, String algorithm)
          throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException
  {
    Digest algorithmDigest = new SHA512Digest();
    if (algorithm.equalsIgnoreCase("sha1")){
      algorithmDigest = new SHA1Digest();
    }
    if (algorithm.equalsIgnoreCase("sha256")){
      algorithmDigest = new SHA256Digest();
    }
    if (algorithm.equalsIgnoreCase("sha512")){
      algorithmDigest = new SHA512Digest();
    }
    PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(algorithmDigest);
    gen.init(pwd.getBytes("UTF_8"), salt.getBytes("UTF_8"), cost);
    byte[] key = ((KeyParameter) gen.generateDerivedParameters(length)).getKey();
    return bytesToHex(key);
  }

  private static String encrypt_aes_gcm(String text, String keyData, String ivData) throws Exception {
    SecretKey secretKey = new SecretKeySpec(Base64.decode(keyData, Base64.NO_WRAP), KEY_ALGORITHM);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    byte[] iv = Base64.decode(ivData, Base64.NO_WRAP);
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv));
    byte[] _text = Base64.decode(text, Base64.NO_WRAP);
    return Base64.encodeToString(cipher.doFinal(_text), Base64.NO_WRAP);
  }

  private static String decrypt_aes_gcm(String ciphertextData, String keyData, String ivData, String tagData) throws Exception {
    SecretKey secretKey = new SecretKeySpec(Base64.decode(keyData, Base64.NO_WRAP), KEY_ALGORITHM);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH * 8, Base64.decode(ivData, Base64.NO_WRAP)));
    byte[] ciphertext = Base64.decode(ciphertextData, Base64.NO_WRAP);
    byte[] tag = Base64.decode(tagData, Base64.NO_WRAP);
    byte[] combined = new byte[ciphertext.length + tag.length];
    for (int i = 0; i < combined.length; ++i)
    {
      combined[i] = i < ciphertext.length ? ciphertext[i] : tag[i - ciphertext.length];
    }
    return new String(cipher.doFinal(combined), StandardCharsets.UTF_8);
  }

  public static String bytesToHex(byte[] bytes) {
    final char[] hexArray = "0123456789abcdef".toCharArray();
    char[] hexChars = new char[bytes.length * 2];
    for ( int j = 0; j < bytes.length; j++ ) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }
  public static long getUnsignedInt(int x) {
    return x & (-1L >>> 32);
  }
}
