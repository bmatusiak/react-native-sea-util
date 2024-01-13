package com.seautil;

import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableNativeArray;

public class SEAUtil {
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
    public static byte[] readableArrayToByteArray(ReadableArray readableArray) {
        byte[] arr = new byte[readableArray.size()];
        for (int i = 0; i < readableArray.size(); ++i) {
            arr[i] = (byte) readableArray.getInt(i);
        }
        return arr;
    }

    public static WritableArray byteArrayToWritableNativeArray(byte[] bytes) {
        WritableArray arr = new WritableNativeArray();
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            arr.pushInt(v);
        }
        return arr;
    }
}
