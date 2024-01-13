package com.seautil;

import android.util.Base64;

import androidx.annotation.NonNull;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeArray;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableNativeMap;
import com.facebook.react.module.annotations.ReactModule;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.UUID;


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
  public void encrypt(final String data, final String key, final String iv, Promise promise) {
    try {
      String result = SEACrypto.encrypt_aes_gcm(data, key, iv);
      promise.resolve(result);
    } catch (Exception e) {
      promise.reject("-1", e.getMessage());
    }
  }
  @ReactMethod
  public void decrypt(final String data, final String pwd, final String iv, final String tag, Promise promise) {
    try {
      String strs = SEACrypto.decrypt_aes_gcm(data, pwd, iv, tag);
      promise.resolve(strs);
    } catch (Exception e) {
      promise.reject("-1", e.getMessage());
    }
  }
  @ReactMethod
  public void pbkdf2(final String pwd, final String salt, final Integer iter, final Integer bitSize, Promise promise) {
    try {
      String strs = SEAWork.pbkdf2(pwd, salt, iter, bitSize);
      promise.resolve(strs);
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
  public void randomBytes(final Integer length, Promise promise) {
    try {
      byte[] key = new byte[length];
      SecureRandom rand = new SecureRandom();
      rand.nextBytes(key);
      WritableArray map = new WritableNativeArray();
      for ( int j = 0; j < key.length; j++ ) {
        map.pushInt(key[j]);
      }
      promise.resolve(map);
    } catch (Exception e) {
      promise.reject("-1", e.getMessage());
    }
  }
  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray randomBytesSync(final Integer length) {
    WritableArray map = new WritableNativeArray();
    try {
      byte[] key = new byte[length];
      SecureRandom rand = new SecureRandom();
      rand.nextBytes(key);
      for ( int j = 0; j < key.length; j++ ) {
        map.pushInt(key[j]);
      }
    } catch (Exception e) {
      throw new RuntimeException(e);//break runtime if RNG is bad
    }
    return map;
  }
  @ReactMethod
  public void sha256(final ReadableArray toHash, Promise promise) {
    String algo = "SHA-256";
    try {
      byte[] digest = SEAWork.digestBytes(algo, SEAUtil.readableArrayToByteArray(toHash) );
      promise.resolve(SEAUtil.byteArrayToWritableNativeArray(digest));
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      promise.reject(algo, e.getMessage());
    }
  }
  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray sha256Sync( final ReadableArray toHash) {
    String algo = "SHA-256";
    WritableArray map;
    try {
      byte[] digest = SEAWork.digestBytes(algo, SEAUtil.readableArrayToByteArray(toHash));
      map = SEAUtil.byteArrayToWritableNativeArray(digest);
    } catch (Exception e) {
      throw new RuntimeException(e);//break runtime if RNG is bad
    }
    return map;
  }
  @ReactMethod
  public void sha256_utf8(final String toHash, Promise promise) {
    String algo = "SHA-256";
    try {
      byte[] digest = SEAWork.digestBytes(algo, toHash.getBytes() );
      promise.resolve(SEAUtil.byteArrayToWritableNativeArray(digest));
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      promise.reject(algo, e.getMessage());
    }
  }
  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray sha256Sync_utf8(final String toHash) {
    String algo = "SHA-256";
    WritableArray map;
    try {
      byte[] digest = SEAWork.digestBytes(algo, toHash.getBytes() );
      map = SEAUtil.byteArrayToWritableNativeArray(digest);
    } catch (Exception e) {
      throw new RuntimeException(e);//break runtime if RNG is bad
    }
    return map;
  }
  @ReactMethod
  public void pair(Promise promise) {
    String[] pair = SEAPair.pair("secp256r1");
    String[] epair = SEAPair.pair("prime256v1");
    WritableMap r = new WritableNativeMap();
    r.putString("priv",pair[0]);
    r.putString("pub",pair[1]);
    r.putString("epriv",epair[0]);
    r.putString("epub",epair[1]);
    promise.resolve(r);
  }
  @ReactMethod
  public void sign(final String _privkey, final ReadableArray toHash, Promise promise) {
    byte[] M = SEAUtil.readableArrayToByteArray(toHash);
    String sig = SEASign.sign(SEAPair.fromPrivate("secp256r1",_privkey), M);
      promise.resolve(sig);
  }
  @ReactMethod
  public void verify(final String _pubKey, final ReadableArray toHash, String b64_sig, Promise promise) {
    byte[] M = SEAUtil.readableArrayToByteArray(toHash);
    if(SEASign.verify(SEAPair.fromPublic("secp256r1",_pubKey), M, b64_sig)){
      promise.resolve(true);
      return;
    }
    promise.resolve(false);
  }
  @ReactMethod
  public void secret(final String _pubKey, final String _privKey, Promise promise) {
    byte[] secret = SEASecret.derive( SEAPair.fromPrivate("prime256v1",_privKey), SEAPair.fromPublic("prime256v1",_pubKey));
    promise.resolve(Base64.encodeToString(secret,Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP));
  }

}
