/**
 * Nimbus JOSE + JWT
 *
 * Copyright 2012-2016, Connect2id Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package org.mozilla.httpece;

import javax.crypto.SecretKey;

import org.spongycastle.crypto.BlockCipher;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.modes.GCMBlockCipher;
import org.spongycastle.crypto.params.AEADParameters;
import org.spongycastle.crypto.params.KeyParameter;

/**
 * Legacy AES/GSM/NoPadding encryption and decryption methods. Uses the
 * BouncyCastle.org API. This class is thread-safe.
 *
 * @author Vladimir Dzhuvinov
 * @author Axel Nennker
 * @author Edouard Oger
 * @version 2016-07-11
 */
class LegacyAESGCM {

    /**
     * The standard authentication tag length (128 bits).
     */
    public static final int AUTH_TAG_BIT_LENGTH = 128;

    /**
     * Creates a new AES cipher.
     *
     * @param secretKey     The AES key. Must not be {@code null}.
     * @param forEncryption If {@code true} creates an AES encryption
     *                      cipher, else creates an AES decryption
     *                      cipher.
     *
     * @return The AES cipher.
     */
    public static AESEngine createAESCipher(final SecretKey secretKey,
                                            final boolean forEncryption) {
        AESEngine cipher = new AESEngine();
        CipherParameters cipherParams = new KeyParameter(secretKey.getEncoded());
        cipher.init(forEncryption, cipherParams);
        return cipher;
    }

    /**
     * Creates a new AES/GCM/NoPadding cipher.
     *
     * @param secretKey     The AES key. Must not be {@code null}.
     * @param forEncryption If {@code true} creates an encryption cipher,
     *                      else creates a decryption cipher.
     * @param iv            The initialisation vector (IV). Must not be
     *                      {@code null}.
     *
     * @return The AES/GCM/NoPadding cipher.
     */
    private static GCMBlockCipher createAESGCMCipher(final SecretKey secretKey,
                                                     final boolean forEncryption,
                                                     final byte[] iv) {
        // Initialise AES cipher
        BlockCipher cipher = createAESCipher(secretKey, forEncryption);
        // Create GCM cipher with AES
        GCMBlockCipher gcm = new GCMBlockCipher(cipher);
        AEADParameters aeadParams = new AEADParameters(new KeyParameter(secretKey.getEncoded()),
                AUTH_TAG_BIT_LENGTH,
                iv);
        gcm.init(forEncryption, aeadParams);
        return gcm;
    }

    /**
     * Encrypts the specified plain text using AES/GCM/NoPadding.
     *
     * @param secretKey The AES key. Must not be {@code null}.
     * @param iv        The initialisation vector (IV). Must not be
     *                  {@code null}.
     *
     * @param plainText The plain text. Must not be {@code null}.
     * @return The authenticated cipher text.
     */
    public static byte[] encrypt(final SecretKey secretKey,
                                 final byte[] iv,
                                 final byte[] plainText) {
        // Initialise AES/GCM cipher for encryption
        GCMBlockCipher cipher = createAESGCMCipher(secretKey, true, iv);
        // Prepare output buffer
        int outputLength = cipher.getOutputSize(plainText.length);
        byte[] output = new byte[outputLength];
        // Produce cipher text
        int outputOffset = cipher.processBytes(plainText, 0, plainText.length, output, 0);
        // Produce authentication tag
        try {
            outputOffset += cipher.doFinal(output, outputOffset);
        } catch (InvalidCipherTextException e) {
            throw new IllegalArgumentException("Couldn't generate GCM authentication tag: " + e.getMessage(), e);
        }
        return output;
    }

    /**
     * Decrypts the specified cipher text using AES/GCM/NoPadding.
     *
     * @param secretKey  The AES key. Must not be {@code null}.
     * @param iv         The initialisation vector (IV). Must not be
     *                   {@code null}.
     * @param cipherText The cipher text. Must not be {@code null}.
     *
     * @return The decrypted plain text.
     */
    public static byte[] decrypt(final SecretKey secretKey,
                                 final byte[] iv,
                                 final byte[] cipherText) {
        // Initialise AES/GCM cipher for decryption
        GCMBlockCipher cipher = createAESGCMCipher(secretKey, false, iv);
        int outputLength = cipher.getOutputSize(cipherText.length);
        byte[] output = new byte[outputLength];
        // Decrypt
        int outputOffset = cipher.processBytes(cipherText, 0, cipherText.length, output, 0);
        // Validate authentication tag
        try {
            outputOffset += cipher.doFinal(output, outputOffset);
        } catch (InvalidCipherTextException e) {
            throw new IllegalArgumentException("Couldn't validate GCM authentication tag: " + e.getMessage(), e);
        }
        return output;
    }

    /**
     * Prevents public instantiation.
     */
    private LegacyAESGCM() { }
}