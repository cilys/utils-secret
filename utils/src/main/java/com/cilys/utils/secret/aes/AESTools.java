package com.cilys.utils.secret.aes;

import com.cilys.utils.secret.java.BASE64Decoder;
import com.cilys.utils.secret.java.BASE64Encoder;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
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
            return new String(decrypt(new BASE64Decoder().decodeBuffer(data), pwd), CHARSET);
        } catch (Exception e) {
            if (debug) {
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
            return new BASE64Encoder().encode(encrypt(data.getBytes(CHARSET), pwd));
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
            Cipher cipher = Cipher.getInstance("AES/CBC/NOPadding");   //参数分别代表 算法名称/加密模式/数据填充方式
            int blockSize = cipher.getBlockSize();

            int plaintextLength = dataBytes.length;
            if (plaintextLength % blockSize != 0) {
                plaintextLength = plaintextLength + (blockSize - (plaintextLength % blockSize));
            }

            byte[] plaintext = new byte[plaintextLength];
            System.arraycopy(dataBytes, 0, plaintext, 0, dataBytes.length);

            SecretKeySpec keyspec = new SecretKeySpec(pwd.getBytes(), "AES");
            IvParameterSpec ivspec = new IvParameterSpec(pwd.getBytes());

            cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);
            byte[] encrypted = cipher.doFinal(plaintext);

            return encrypted;
        } catch (Exception e) {
            if (debug) {
                e.printStackTrace();
            }
            return null;
        }
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

            Cipher cipher = Cipher.getInstance("AES/CBC/NOPadding");
            SecretKeySpec keyspec = new SecretKeySpec(pwd.getBytes(), "AES");
            IvParameterSpec ivspec = new IvParameterSpec(pwd.getBytes());

            cipher.init(Cipher.DECRYPT_MODE, keyspec, ivspec);

            byte[] original = cipher.doFinal(byteDatas);
            return original;
        } catch (Exception e) {
            if (debug) {
                e.printStackTrace();
            }
            return null;
        }
    }
}
