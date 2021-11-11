package com.cilys.utils.secret.aes;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AESTools implements EncryptStringImpl, DecryptStringImpl, EncryptByteImpl, DecryptByteImpl {
    public static String CHARSET = "UTF-8";

    protected boolean debug = false;

    public AESTools() {
        debug = false;
    }

    public AESTools(boolean debug) {
        this.debug = debug;
    }

    @Override
    public String decrypt(String data, String pwd) {
        if (data == null) {
            if (debug) {
                System.out.println("解密内容为null：" + data);
            }
            return null;
        }

        try {
            return new String(decrypt(parseHexStr2Byte(data), pwd), CHARSET);
        } catch (UnsupportedEncodingException e) {
            if (debug){
                e.printStackTrace();
            }
            return null;
        }
    }

    @Override
    public String encrypt(String data, String pwd) {
        if (data == null) {
            if (debug) {
                System.out.println("加密内容为null：" + data);
            }
            return null;
        }
        try {
            return parseByte2HexStr(encrypt(data.getBytes(CHARSET), pwd));
        } catch (Exception e) {
            if (debug) {
                e.printStackTrace();
            }
            return null;
        }
    }

    @Override
    public byte[] encrypt(byte[] dataBytes, String pwd) {
        if (pwd == null) {
            pwd = "1234567890123456";
        }
        if (pwd.length() > 16) {
            pwd = pwd.substring(0, 16);
        }
        while (pwd.length() < 16) {
            pwd = pwd + "0";
        }
        if (debug) {
            System.out.println("加密内容：" + Arrays.toString(dataBytes));
            System.out.println("加密密钥：" + pwd);
        }
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128, new SecureRandom(pwd.getBytes()));
            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
            Cipher cipher = Cipher.getInstance("AES");// 创建密码器
            cipher.init(Cipher.ENCRYPT_MODE, key);// 初始化
            byte[] result = cipher.doFinal(dataBytes);
            return result; // 加密
        } catch (Exception e) {
            if (debug) {
                e.printStackTrace();
            }
        }
        return null;
    }

    @Override
    public byte[] decrypt(byte[] byteDatas, String pwd) {
        if (pwd == null) {
            pwd = "1234567890123456";
        }
        if (pwd.length() > 16) {
            pwd = pwd.substring(0, 16);
        }
        while (pwd.length() < 16) {
            pwd = pwd + "0";
        }
        if (debug) {
            System.out.println("解密内容：" + Arrays.toString(byteDatas));
            System.out.println("解密密钥：" + pwd);
        }
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128, new SecureRandom(pwd.getBytes()));
            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
            Cipher cipher = Cipher.getInstance("AES");// 创建密码器
            cipher.init(Cipher.DECRYPT_MODE, key);// 初始化
            byte[] result = cipher.doFinal(byteDatas);
            return result; // 加密
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public String parseByte2HexStr(byte buf[]) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < buf.length; i++) {
            String hex = Integer.toHexString(buf[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            sb.append(hex.toUpperCase());
        }
        return sb.toString();
    }


    /**
     * 将16进制转换为二进制
     *
     * @param hexStr
     * @return
     */
    public byte[] parseHexStr2Byte(String hexStr) {
        if (hexStr.length() < 1)
            return null;
        byte[] result = new byte[hexStr.length() / 2];
        for (int i = 0; i < hexStr.length() / 2; i++) {
            int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
            int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2), 16);
            result[i] = (byte) (high * 16 + low);
        }
        return result;
    }

//    public static void main(String[] args) {
//        AESTools aesTools = new AESTools(true);
//        AESTools aesSortTools = new AESSortTools(true);
//        String str = "Hello，中国";
//        String e = aesSortTools.encrypt(str, null);
//        System.out.println("加密：" + e);
//        String d = aesSortTools.decrypt(e, null);
//        System.out.println("解密：" + d);
//    }
}
