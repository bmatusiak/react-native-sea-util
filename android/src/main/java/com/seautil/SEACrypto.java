package com.seautil;

import android.util.Base64;

import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SEACrypto {

    private static final String KEY_ALGORITHM = "AES";;
    private static final int GCM_TAG_LENGTH = 16;
    public static String encrypt_aes_gcm(String text, String keyData, String ivData) throws Exception {
        SecretKey secretKey = new SecretKeySpec(Base64.decode(keyData, Base64.NO_WRAP), KEY_ALGORITHM);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = Base64.decode(ivData, Base64.NO_WRAP);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv));
        byte[] _text = Base64.decode(text, Base64.NO_WRAP);
        return Base64.encodeToString(cipher.doFinal(_text), Base64.NO_WRAP);
    }
    public static String decrypt_aes_gcm(String ciphertextData, String keyData, String ivData, String tagData) throws Exception {
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
}
