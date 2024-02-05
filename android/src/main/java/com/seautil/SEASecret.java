package com.seautil;

import org.spongycastle.crypto.BasicAgreement;
import org.spongycastle.crypto.agreement.ECDHBasicAgreement;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.util.BigIntegers;

public class SEASecret {

//    public static byte[] derive2(String curve,String _pubKey, String _privKey) {
//        try {
//            String[] xy = _pubKey.split("\\.");
//            byte[] privateKeyS = Base64.decode(_privKey, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
//            byte[] publicKeyX = Base64.decode(xy[0], Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
//            byte[] publicKeyY = Base64.decode(xy[1], Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
//            ECPoint pubPoint = new ECPoint(BigIntegers.fromUnsignedByteArray(publicKeyX), BigIntegers.fromUnsignedByteArray(publicKeyY));
//            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
//            parameters.init(new ECGenParameterSpec(curve));
//            ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
//            ECPublicKeySpec pubSpec = new ECPublicKeySpec(pubPoint, ecParameters);
//            ECPrivateKeySpec privateSpec = new ECPrivateKeySpec(BigIntegers.fromUnsignedByteArray(privateKeyS), ecParameters);
//            KeyFactory kf = KeyFactory.getInstance("EC");
//            ECPrivateKey privateKey = (ECPrivateKey) kf.generatePrivate(privateSpec);
//            ECPublicKey publicKey = (ECPublicKey) kf.generatePublic(pubSpec);
//            KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH","SC");
//            keyAgree.init(privateKey);
//            keyAgree.doPhase(publicKey, true);
//            return keyAgree.generateSecret();
//        }catch (InvalidParameterSpecException | NoSuchAlgorithmException | InvalidKeySpecException |NoSuchProviderException | InvalidKeyException  e) {
//            throw new RuntimeException(e);
//        }
//    }
    public static byte[] derive(ECPrivateKeyParameters priKey, ECPublicKeyParameters pubKey)
    {
        BasicAgreement keyAgree = new ECDHBasicAgreement();
        keyAgree.init(priKey);
        return BigIntegers.asUnsignedByteArray(keyAgree.calculateAgreement(pubKey));
    }
}
