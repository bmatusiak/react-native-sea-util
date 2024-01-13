package com.seautil;

import android.util.Base64;

import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.crypto.params.ParametersWithRandom;
import org.spongycastle.crypto.signers.ECDSASigner;
import org.spongycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class SEASign {
    public static String sign(ECPrivateKeyParameters priKey, byte[] M)
    {
        SecureRandom k = new SecureRandom();
        ECDSASigner dsa = new ECDSASigner();
        dsa.init(true, new ParametersWithRandom(priKey, k));
        BigInteger[] sig = dsa.generateSignature(M);
        byte[] rs_sig = org.spongycastle.util.Arrays.concatenate(
                BigIntegers.asUnsignedByteArray(sig[0]),
                BigIntegers.asUnsignedByteArray(sig[1])
        );
        return Base64.encodeToString(rs_sig, Base64.NO_WRAP);
    }
    public static boolean verify(ECPublicKeyParameters pubKey, byte[] M, String b64_sig)
    {
        byte[] rsb = Base64.decode(b64_sig, Base64.NO_WRAP);
        byte[] rb = Arrays.copyOfRange(rsb,0,32);
        byte[] sb = Arrays.copyOfRange(rsb,32,32*2);
        BigInteger r = BigIntegers.fromUnsignedByteArray(rb);
        BigInteger s = BigIntegers.fromUnsignedByteArray(sb);
        ECDSASigner dsa = new ECDSASigner();
        dsa.init(false, pubKey);
        if (!dsa.verifySignature(M, r, s))
        {
            return false;
        }
        return true;
    }
}
