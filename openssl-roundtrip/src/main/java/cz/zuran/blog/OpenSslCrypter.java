/*
Copyright (c) 2010 Tomas Langer (tomas.langer@gmail.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
 */
package cz.zuran.blog;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.nio.charset.Charset;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Random;

/**
 * Provides a full roundtrip with OpenSSL DES password based encryption.
 * <p/>
 *
 * Open ssl command to encrypt:<br>
 * <code>echo -n 'string to encrypt' | openssl enc -des -a -e -k 'password to use'</code><br>
 * Open ssl command to decrypt:<br>
 * <code>echo 'base64 encoded string to decrypt' | openssl enc -des -a -d -k 'password to use'</code><br>
 *
 * <p/>
 * Date: 13.12.10 Time: 20:22
 *
 * @author Tomas Langer (tomas.langer@google.com)
 */
public final class OpenSslCrypter {
    /**
     * Number of iterations - needs to be set to 1 for our roundtrip to work.
     */
    private static final int ITERATION_COUNT = 1;
    /**
     * "Magic" keyword used by OpenSSL to put at the beginning of the encrypted bytes.
     */
    private static final byte[] MAGIC_SALTED_BYTES = "Salted__".getBytes();
    /**
     * Algorithm to use in java to generate the same encrypted bytes as OpenSSL when using DES with password (hashed) encryption.
     */
    private static final String ALGORITHM = "PBEWithMD5AndDES";

    //prevent instantiation
    private OpenSslCrypter() {
    }

    /**
     * Finds out if the string is encrypted using our method.
     *
     * @param maybeEncrypted String to check.
     *
     * @return true if string is encrypted using our method, false otherwise
     */
    public static boolean isEncrypted(String maybeEncrypted) {
        try {
            byte[] encrypted = Base64.decodeBase64(maybeEncrypted.getBytes());
            if (encrypted.length > 16) {
                byte[] firstBytes = new byte[MAGIC_SALTED_BYTES.length];
                System.arraycopy(encrypted, 0, firstBytes, 0, firstBytes.length);
                return Arrays.equals(firstBytes, MAGIC_SALTED_BYTES);
            }

        } catch (Exception e) {
            //make sure we never fail
            //ignore exception, it means we could not decode base64
        }
        return false;
    }

    /**
     * Decrypts an open SSL encrypted string.
     *
     * @param toDecrypt Base64 encoded string as created by open ssl
     * @param password  Password for decryption
     *
     * @return Decrypted original string
     *
     * @throws Exception In case cryptography initialization fails or cannot decrypt
     */
    public static String decrypt(String toDecrypt, String password) throws Exception {

        byte[] encrypted = Base64.decodeBase64(toDecrypt.getBytes());

        byte[] salt = new byte[8];

        //get the salt information from the input
        System.arraycopy(encrypted, 8, salt, 0, 8);

        //initialize the cipher
        Cipher cipher = initCipher(password, salt, Cipher.DECRYPT_MODE);

        //decrypt the data
        byte[] decrypted = cipher.doFinal(encrypted, 16, encrypted.length - 16);

        return new String(decrypted);
    }

    /**
     * Encrypts a string so open SSL can decrypt it.
     *
     * @param toEncrypt String to encrypt.
     * @param password  Password to use for encryption.
     *
     * @return base64 encoded encrypted bytes
     *
     * @throws Exception When initialization or encryption fails
     */
    public static String encrypt(String toEncrypt, String password) throws Exception {
        byte[] salt = new byte[8];
        new Random().nextBytes(salt);

        Cipher cipher = initCipher(password, salt, Cipher.ENCRYPT_MODE);

        byte[] bytes = toEncrypt.getBytes(Charset.forName("UTF-8"));

        bytes = cipher.doFinal(bytes);

        byte[] result = new byte[bytes.length + 16];

        //add the magic keyword
        System.arraycopy(MAGIC_SALTED_BYTES, 0, result, 0, 8);
        //add the salt information
        System.arraycopy(salt, 0, result, 8, 8);
        //add the encrypted bytes
        System.arraycopy(bytes, 0, result, 16, bytes.length);

        //base64 encode so we can send it around as a string
        bytes = Base64.encodeBase64(result);

        return new String(bytes);
    }

    /**
     * Common cipher initialization steps.
     *
     * @param password The password used to encrypt/decrypt the data
     * @param salt     The salt to use to initialize the cipher
     * @param mode     Mode to use to initialize the ciper, either {@link Cipher#ENCRYPT_MODE} or {@link Cipher#DECRYPT_MODE}
     *
     * @return Cipher initialized with the values defined and with the {@link #ALGORITHM} and {@link #ITERATION_COUNT}
     *
     * @throws Exception Covering all the possible cases when something goes wrong with initialization
     */
    private static Cipher initCipher(String password, byte[] salt, int mode) throws Exception {
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT);

        SecretKey key = SecretKeyFactory.getInstance(ALGORITHM).generateSecret(keySpec);

        Cipher cipher = Cipher.getInstance(key.getAlgorithm());

        AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, ITERATION_COUNT);

        cipher.init(mode, key, paramSpec);

        return cipher;
    }
}
