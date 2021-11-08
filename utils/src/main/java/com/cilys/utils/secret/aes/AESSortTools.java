package com.cilys.utils.secret.aes;

import java.util.Arrays;

public class AESSortTools extends AESTools {

    public AESSortTools() {
        super();
    }

    public AESSortTools(boolean debug) {
        super(debug);
    }

    @Override
    public String decrypt(String data, String pwd) {
        if (data != null && data.length() > 0) {
            String s0 = data.substring(0, 1);
            String s1 = data.substring(1, 2);
            String s2 = data.substring(2);

            data = s1 + s0 + s2;
        }
        return super.decrypt(data, pwd);
    }

    @Override
    public String encrypt(String data, String pwd) {
        String s = super.encrypt(data, pwd);
        if (s != null && s.length() > 2) {
            String s0 = s.substring(0, 1);
            String s1 = s.substring(1, 2);
            String s2 = s.substring(2);

            s = s1 + s0 + s2;
        }
        return s;
    }

    @Override
    public byte[] encrypt(byte[] dataBytes, String pwd) {
        byte[] rs = super.encrypt(dataBytes, pwd);
        if (rs != null && rs.length > 2) {
            System.out.println("原始加密数据：" + Arrays.toString(rs));
            byte b0 = rs[0];
            byte b1 = rs[1];
            rs[0] = b1;
            rs[1] = b0;
            System.out.println("处理后的加密数据：" + Arrays.toString(rs));
        }
        return rs;
    }

    @Override
    public byte[] decrypt(byte[] byteDatas, String pwd) {
        if (byteDatas != null && byteDatas.length > 2) {
            System.out.println("原始加密数据：" + Arrays.toString(byteDatas));
            byte b0 = byteDatas[0];
            byte b1 = byteDatas[1];
            byteDatas[0] = b1;
            byteDatas[1] = b0;
            System.out.println("处理后的加密数据：" + Arrays.toString(byteDatas));
        }
        return super.decrypt(byteDatas, pwd);
    }
}
