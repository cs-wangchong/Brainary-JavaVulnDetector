package com.example.vulnerable;

import java.io.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;

/**
 * CryptoManager with weak cryptography vulnerabilities
 * CWE-327: Use of Broken or Risky Cryptographic Algorithm
 * CWE-329: Not Using a Random IV with CBC Mode
 */
public class CryptoManager {
    
    // Weak encryption algorithm
    private static final String ALGORITHM = "DES";
    
    // Hardcoded encryption key
    private static final String SECRET_KEY = "MyS3cr3t";
    
    /**
     * Encrypt data using weak DES algorithm
     */
    public byte[] encrypt(String data) throws Exception {
        // Use of weak DES algorithm
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(56); // 56-bit key is too weak
        SecretKey secretKey = keyGen.generateKey();
        
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        
        return cipher.doFinal(data.getBytes());
    }
    
    /**
     * Hash password using weak MD5 algorithm
     */
    public String hashPassword(String password) {
        try {
            // MD5 is cryptographically broken
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());
            
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            
            return hexString.toString();
            
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }
    
    /**
     * Encrypt with AES but without random IV
     */
    public byte[] encryptAES(String data, String key) throws Exception {
        // Static IV - should be random for each encryption
        byte[] iv = new byte[16]; // All zeros
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        return cipher.doFinal(data.getBytes());
    }
    
    /**
     * Generate predictable random numbers
     */
    public int generateToken() {
        // Using insecure Random instead of SecureRandom
        Random random = new Random();
        return random.nextInt(1000000);
    }
    
    /**
     * Weak password check
     */
    public boolean isPasswordStrong(String password) {
        // Weak password policy
        return password.length() >= 6;
    }
}
