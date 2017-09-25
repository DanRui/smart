package com.smart.mvc.util;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.io.*;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author DanRui
 *
 */
public class RSAUtils {

    /**
     * String to hold name of the encryption algorithm.
     */
    public static final String ALGORITHM = "RSA";

    /**
     * String to hold name of the encryption padding.
     */
    public static final String PADDING = "RSA/NONE/NoPadding";

    /**
     * String to hold name of the security provider.
     */
    public static final String PROVIDER = "BC";

    /**
     * String to hold the name of the private key file.
     */
    public static final String PRIVATE_KEY_FILE = "D:/DanRui/work/20150116/private.key";

    /**
     * String to hold name of the public key file.
     */
    public static final String PUBLIC_KEY_FILE = "D:/DanRui/work/20150116/public.key";

    /**
     * Generate key which contains a pair of private and public key using 1024
     * bytes. Store the set of keys in Prvate.key and Public.key files.
     *
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws FileNotFoundException
     */
    public static void generateKey(String publicKeyFile, String privateKeyFile) throws Exception {
            Security.addProvider(new BouncyCastleProvider());
            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(
                    ALGORITHM, PROVIDER);
            // 密钥位数256个字节
            keyGen.initialize(2048);
            final KeyPair keyPair = keyGen.generateKeyPair();

            /** 得到公钥 */
            Key publicKey = keyPair.getPublic();

            /** 得到私钥 */
            Key privateKey = keyPair.getPrivate();

            ObjectOutputStream oos1 = null;
            ObjectOutputStream oos2 = null;
            try {
                /** 用对象流将生成的密钥写入文件 */
                File privateKF = new File(privateKeyFile);
                File publicKF = new File(publicKeyFile);

                // Create files to store public and private key
                if (privateKF.getParentFile() != null) {
                    privateKF.getParentFile().mkdirs();
                }
                privateKF.createNewFile();

                if (publicKF.getParentFile() != null) {
                    publicKF.getParentFile().mkdirs();
                }
                publicKF.createNewFile();

                oos1 = new ObjectOutputStream(new FileOutputStream(publicKF));
                oos2 = new ObjectOutputStream(new FileOutputStream(privateKF));

                oos1.writeObject(publicKey);
                oos2.writeObject(privateKey);
            } catch (Exception e) {
                throw e;
            } finally {
                /** 清空缓存，关闭文件输出流 */
                oos1.close();
                oos2.close();
            }
    }

    /**
     * The method checks if the pair of public and private key has been
     * generated.
     *
     * @return flag indicating if the pair of keys were generated.
     */
    public static boolean areKeysPresent(String publicKeyFile, String privateKeyFile) {
        File privateKey = new File(privateKeyFile);
        File publicKey = new File(publicKeyFile);

        if (privateKey.exists() && publicKey.exists()) {
            return true;
        }
        return false;
    }

    /**
     * Encrypt the plain text using public key.
     *
     * @param text
     *            : original plain text
     * @param key
     *            :The public key
     * @return Encrypted text
     * @throws Exception
     */
    public static byte[] encrypt(String text, PublicKey key) {
        byte[] cipherText = null;
        try {
            // get an RSA cipher object and print the provider
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            final Cipher cipher = Cipher.getInstance(PADDING, PROVIDER);

            // encrypt the plain text using the public key
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipherText = cipher.doFinal(text.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return cipherText;
    }

    /**
     * Decrypt text using private key.
     *
     * @param text
     *            :encrypted text
     * @param key
     *            :The private key
     * @return plain text
     * @throws Exception
     */
    public static String decrypt(byte[] text, PrivateKey key) {
        byte[] dectyptedText = null;
        try {
            // get an RSA cipher object and print the provider
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            final Cipher cipher = Cipher.getInstance(PADDING, PROVIDER);

            // decrypt the text using the private key
            cipher.init(Cipher.DECRYPT_MODE, key);
            dectyptedText = cipher.doFinal(text);

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return new String(dectyptedText);
    }

    /**
     * Test the EncryptionUtil
     */
    public static void main(String[] args) {

        long start = System.currentTimeMillis();
        System.out.println(start);

        try {

            // Check if the pair of keys are present else generate those.
            if (!areKeysPresent(PUBLIC_KEY_FILE, PRIVATE_KEY_FILE)) {
                // Method generates a pair of keys using the RSA algorithm and
                // stores it
                // in their respective files
                generateKey(PUBLIC_KEY_FILE, PRIVATE_KEY_FILE);
            }

//            final String originalText = "12345678901234567890123456789012";
            final String originalText = "http://api.fsafx.cn/jsso/sso/user/ssoLogin?rd=800000&appCode=10001&appId=101001&sign=7fe2225c2dd3bc16f31f5b59afa49b3d&timestamp=1505475770803&unitInfo=QUIyRjNCNzdDREY4MzQ1Mw&backUrl=http://abk.fsafx.cn/&reLogin=true&token=null";
            System.out.println(originalText.getBytes().length);
            ObjectInputStream inputStream = null;

            // Encrypt the string using the public key
            inputStream = new ObjectInputStream(new FileInputStream(
                    PUBLIC_KEY_FILE));
            final PublicKey publicKey = (PublicKey) inputStream.readObject();
            final byte[] cipherText = encrypt(originalText, publicKey);

            // use String to hold cipher binary data
            Base64 base64 = new Base64();
            String cipherTextBase64 = base64.encodeToString(cipherText);

            // get cipher binary data back from Str

            // Decrypt the cipher text using the private key.ing
            byte[] cipherTextArray = base64.decode(cipherTextBase64);
            inputStream = new ObjectInputStream(new FileInputStream(
                    PRIVATE_KEY_FILE));
            final PrivateKey privateKey = (PrivateKey) inputStream.readObject();
            final String plainText = decrypt(cipherTextArray, privateKey);

            // Printing the Original, Encrypted and Decrypted Text
            System.out.println("Original=" + originalText);
            System.out.println("Encrypted=" + cipherTextBase64);
            System.out.println(cipherTextBase64.length());
            System.out.println("Decrypted=" + plainText);

            System.out.println("加解密花费时间：" + (System.currentTimeMillis() - start) + " ms");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
