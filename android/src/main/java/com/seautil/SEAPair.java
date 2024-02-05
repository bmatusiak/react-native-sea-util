package com.seautil;

import android.util.Base64;

import org.spongycastle.asn1.nist.NISTNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.generators.ECKeyPairGenerator;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECKeyGenerationParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.SecureRandom;

public class SEAPair {
    public  static String[] pair(String curve){
        X9ECParameters p = NISTNamedCurves.getByName("P-256");
        ECDomainParameters params = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
//        ECNamedCurveParameterSpec p = ECNamedCurveTable.getParameterSpec(curve);
//        ECDomainParameters params = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
        SecureRandom random = new SecureRandom();
        ECKeyPairGenerator pGen = new ECKeyPairGenerator();
        ECKeyGenerationParameters genParam = new ECKeyGenerationParameters(
                params,
                random);
        pGen.init(genParam);
        AsymmetricCipherKeyPair pair = pGen.generateKeyPair();
        ECPrivateKeyParameters priv =  (ECPrivateKeyParameters)pair.getPrivate();
        ECPublicKeyParameters pub =  (ECPublicKeyParameters)pair.getPublic();
        BigInteger d = priv.getD();
        ECPoint ecPoint = pub.getQ();
        BigInteger x = ecPoint.getAffineXCoord().toBigInteger();
        BigInteger y = ecPoint.getAffineYCoord().toBigInteger();
        byte[]  X = BigIntegers.asUnsignedByteArray(x);
        byte[]  Y = BigIntegers.asUnsignedByteArray(y);
        byte[]  D = BigIntegers.asUnsignedByteArray(d);
        String[] __out = new String[2];
        __out[0] =  Base64.encodeToString(D, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
        __out[1] =
                Base64.encodeToString(X, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP)
                +"."+
                Base64.encodeToString(Y, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
        return __out;
    }

    public  static ECPublicKeyParameters fromPublic(String curve, String pub){
        X9ECParameters p = NISTNamedCurves.getByName("P-256");
        ECDomainParameters params = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
//        ECNamedCurveParameterSpec p = ECNamedCurveTable.getParameterSpec(curve);
//        ECDomainParameters params = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
        String[] xy = pub.split("\\.");
        byte[] X = Base64.decode(xy[0], Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
        byte[] Y = Base64.decode(xy[1], Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
        BigInteger x = BigIntegers.fromUnsignedByteArray(X);
        BigInteger y = BigIntegers.fromUnsignedByteArray(Y);
        ECPoint Q = p.getCurve().createPoint(x, y);
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(Q, params);
        return pubKey;
    }
    public  static ECPrivateKeyParameters fromPrivate(String curve, String priv){
        X9ECParameters p = NISTNamedCurves.getByName("P-256");
        ECDomainParameters params = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
//        ECNamedCurveParameterSpec p = ECNamedCurveTable.getParameterSpec(curve);
//        ECDomainParameters params = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
        byte[] D = Base64.decode(priv, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
        BigInteger d = BigIntegers.fromUnsignedByteArray(D);
        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters( d, params);
        return privKey;
    }
}
