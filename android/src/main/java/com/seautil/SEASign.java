package com.seautil;

import android.util.Base64;

import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.ASN1OutputStream;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.BigIntegers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

public class SEASign {
    public static byte[] encodeRS(byte[] sigBlob) throws IOException {
        byte[] r = new BigInteger(1, Arrays.copyOfRange(sigBlob, 0, 32)).toByteArray();
        byte[] s = new BigInteger(1, Arrays.copyOfRange(sigBlob, 32, sigBlob.length)).toByteArray();
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(r));
        vector.add(new ASN1Integer(s));
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ASN1OutputStream asnOS = new ASN1OutputStream(baos);
        asnOS.writeObject(new DERSequence(vector));
        asnOS.flush();
        return baos.toByteArray();
    }

    public static byte[] decodeRS(byte[] sigBlob) throws IOException {
        ASN1Sequence as = (ASN1Sequence) ASN1Primitive.fromByteArray(sigBlob);
        BigInteger r_bi = ((ASN1Integer) as.getObjectAt(0)).getValue();
        BigInteger s_bi = ((ASN1Integer) as.getObjectAt(1)).getValue();
        byte[] r = BigIntegers.asUnsignedByteArray(r_bi);
        byte[] s = BigIntegers.asUnsignedByteArray(s_bi);
        return Arrays.concatenate(r, s);
    }

    public static KeyPair GenerateKeys()
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "SC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        return keyGen.generateKeyPair();
    }

    public static String sign(String _privKey, byte[] strByte)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IOException, SignatureException, InvalidParameterSpecException, InvalidKeySpecException {
        ECPrivateKey priv = (ECPrivateKey) importKey("secp256r1", _privKey, true);
        Signature ecdsa = Signature.getInstance("SHA256withECDSA", "SC");
        ecdsa.initSign(priv);
        ecdsa.update(strByte);
        byte[] signature = ecdsa.sign();
        byte[] rs = decodeRS(signature);

        return Base64.encodeToString(rs, Base64.NO_WRAP);
    }

    public static boolean verify(String _pubKey, byte[] strByte, String _sigRS)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IOException, SignatureException, InvalidParameterSpecException, InvalidKeySpecException {
        byte[] sigRS = Base64.decode(_sigRS, Base64.NO_WRAP);
        ECPublicKey pub = (ECPublicKey) importKey("secp256r1", _pubKey, false);
        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "SC");
        ecdsaVerify.initVerify(pub);
        ecdsaVerify.update(strByte);
        boolean result = ecdsaVerify.verify(encodeRS(sigRS));
        return result;
    }

    public static ECKey importKey(String curve, String inputKey, boolean isPrivate) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidParameterSpecException, InvalidKeySpecException {
        ECKey outputKey;
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", "SC");
        parameters.init(new ECGenParameterSpec(curve));
        ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
        KeyFactory kf = KeyFactory.getInstance("EC", "SC");
        if (isPrivate) {
            byte[] privateKeyS = Base64.decode(inputKey, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
            ECPrivateKeySpec privateSpec = new ECPrivateKeySpec(BigIntegers.fromUnsignedByteArray(privateKeyS), ecParameters);
            outputKey = (ECPrivateKey) kf.generatePrivate(privateSpec);
        } else {
            String[] xy = inputKey.split("\\.");
            byte[] publicKeyX = Base64.decode(xy[0], Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
            byte[] publicKeyY = Base64.decode(xy[1], Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
            ECPoint pubPoint = new ECPoint(BigIntegers.fromUnsignedByteArray(publicKeyX), BigIntegers.fromUnsignedByteArray(publicKeyY));
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(pubPoint, ecParameters);
            outputKey = (ECPublicKey) kf.generatePublic(pubSpec);
        }
        return outputKey;
    }

}
