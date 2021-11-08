package com.cilys.utils.secret.aes;

public interface EncryptByteImpl {
    byte[] encrypt(byte[] dataBytes, String pwd);
}