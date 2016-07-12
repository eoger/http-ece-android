package org.mozilla.httpece;

import android.app.Application;
import android.test.ApplicationTestCase;
import android.test.MoreAsserts;
import android.test.suitebuilder.annotation.Suppress;
import android.util.Base64;

import junit.framework.Assert;

import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.jce.spec.ECPrivateKeySpec;
import org.spongycastle.jce.spec.ECPublicKeySpec;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

// Not a unit test because Spongy Castle is not signed and fails on desktop JREs.
public class ApplicationTest extends ApplicationTestCase<Application> {

    private static final int MAX_LENGTH = 100;
    private static final int TESTS_ITERATIONS = 20;

    private SecureRandom random = new SecureRandom();
    private HttpEce httpEce;

    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    public ApplicationTest() {
        super(Application.class);
    }

    public void useExplicitKey() throws Exception {
        HttpEce.Params params = new HttpEce.Params();
        params.key = randomBytes(16);
        params.salt = randomBytes(16);
        params.recordSize = Math.max(params.padSize, random.nextInt(65535)) + 1;
        encryptDecrypt(random.nextInt(MAX_LENGTH), params);
    }

    public void authenticationSecret() throws Exception {
        HttpEce.Params params = new HttpEce.Params();
        params.key = randomBytes(16);
        params.salt = randomBytes(16);
        params.recordSize = Math.max(params.padSize, random.nextInt(65535)) + 1;
        params.authSecret = randomBytes(16);
        encryptDecrypt(random.nextInt(MAX_LENGTH), params);
    }

    public void exactlyOneRecord() throws Exception {
        int length = random.nextInt(MAX_LENGTH);
        HttpEce.Params params = new HttpEce.Params();
        params.key = randomBytes(16);
        params.salt = randomBytes(16);
        params.recordSize = Math.max(params.padSize, length) + 1;
        encryptDecrypt(length, params);
    }

    public void detectTruncation() throws Exception {
        int length = random.nextInt(MAX_LENGTH);
        HttpEce.Params params = new HttpEce.Params();
        params.key = randomBytes(16);
        params.salt = randomBytes(16);
        params.recordSize = Math.max(params.padSize, length) + 1;
        byte[] input = randomBytes(length);
        byte[] encrypted = httpEce.encrypt(input, params);
        encrypted = Arrays.copyOfRange(encrypted, 0, length + 1 + 16);
        boolean ok = false;
        try {
            httpEce.decrypt(encrypted, params);
        } catch (Exception e) {
            ok = true;
        }
        Assert.assertTrue(ok);
    }

    public void useKeyId() throws Exception {
        HttpEce.Params params = new HttpEce.Params();
        String keyId = new String(randomBytes(16));
        byte[] key = randomBytes(16);
        httpEce.saveKey(keyId, key);
        params.keyId = keyId;
        params.salt = randomBytes(16);
        params.recordSize = Math.max(params.padSize, random.nextInt(65535)) + 1;
        encryptDecrypt(random.nextInt(MAX_LENGTH), params);
    }

    public void useDH() throws Exception {
        ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "SC");
        g.initialize(parameterSpec);

        // The static key is used by the receiver
        KeyPair staticKey = g.generateKeyPair();
        String staticKeyId = new String(randomBytes(16));
        httpEce.saveKey(staticKeyId, staticKey, "P-256");

        // The ephemeral key is used by the sender
        KeyPair ephemeralKey = g.generateKeyPair();
        String ephemeralKeyId = new String(randomBytes(16));
        httpEce.saveKey(ephemeralKeyId, ephemeralKey, "P-256");

        HttpEce.Params encryptParams = new HttpEce.Params();
        encryptParams.keyId = ephemeralKeyId;
        encryptParams.dh = staticKey.getPublic();
        encryptParams.salt = randomBytes(16);
        encryptParams.recordSize = Math.max(encryptParams.padSize, random.nextInt(65535)) + 1;

        HttpEce.Params decryptParams = new HttpEce.Params();
        decryptParams.keyId = staticKeyId;
        decryptParams.dh = ephemeralKey.getPublic();
        decryptParams.salt = encryptParams.salt;
        decryptParams.recordSize = encryptParams.recordSize;

        encryptDecrypt(random.nextInt(MAX_LENGTH), encryptParams, decryptParams);
    }

    public void testAll() throws Exception {
        httpEce = new HttpEce();
        for (int i = 0; i < TESTS_ITERATIONS; i++) {
            useExplicitKey();
            authenticationSecret();
            exactlyOneRecord();
            detectTruncation();
            useKeyId();
            useDH();
        }
    }

    public void testLegacy() throws Exception {
        httpEce = new HttpEce(true);
        for (int i = 0; i < TESTS_ITERATIONS; i++) {
            useExplicitKey();
            authenticationSecret();
            exactlyOneRecord();
            detectTruncation();
            useKeyId();
            useDH();
        }
    }

    private void encryptDecrypt(int length, HttpEce.Params encryptParams) throws Exception {
        encryptDecrypt(length, encryptParams, encryptParams);
    }

    private void encryptDecrypt(int length, HttpEce.Params encryptParams, HttpEce.Params decryptParams) throws Exception {
        byte[] input = randomBytes(length);
        byte[] encrypted = httpEce.encrypt(input, encryptParams);
        byte[] decrypted = httpEce.decrypt(encrypted, decryptParams);
        MoreAsserts.assertEquals(input, decrypted);
    }

    public static PublicKey loadPublicKey (String str) throws Exception {
        byte[] data = Base64.decode(str, Base64.URL_SAFE);
        return loadPublicKey(data);
    }

    public static PrivateKey loadPrivateKey(String str) throws Exception {
        byte[] data = Base64.decode(str, Base64.URL_SAFE);
        return loadPrivateKey(data);
    }

    public static PublicKey loadPublicKey (byte[] data) throws Exception {
        ECParameterSpec params = ECNamedCurveTable.getParameterSpec("prime256v1");
        ECPublicKeySpec pubKey = new ECPublicKeySpec(params.getCurve().decodePoint(data), params);
        KeyFactory kf = KeyFactory.getInstance("ECDH", "SC");
        return kf.generatePublic(pubKey);
    }

    public static PrivateKey loadPrivateKey(byte[] data) throws Exception {
        ECParameterSpec params = ECNamedCurveTable.getParameterSpec("prime256v1");
        ECPrivateKeySpec prvkey = new ECPrivateKeySpec(new BigInteger(data), params);
        KeyFactory kf = KeyFactory.getInstance("ECDH", "SC");
        return kf.generatePrivate(prvkey);
    }

    private byte[] randomBytes(int length) {
        final byte[] randBytes = new byte[length];
        random.nextBytes(randBytes);
        return randBytes;
    }

    // TODO: old tests to remove

    @Suppress
    public void testEncrypt() throws Exception {
        HttpEce.Params params = new HttpEce.Params();
        byte[] payload = Base64.decode("abcdefg", Base64.URL_SAFE);
        params.salt = Base64.decode("5TsHiY5I80Kfn0ar2tnxZA", Base64.URL_SAFE);
        params.dh = loadPublicKey("BLok0OsCEIbaSScDTAgCuccPpsa3pBadeHA-74TZ7ZyxhvcBv_7vdRpyBwJ4jsFCiqiO9brZ0sngbetbGVyDShE");
        PrivateKey senderPrivate = loadPrivateKey("bJGtJt8Q5vjLWNO7zse8UZw_SniZxDnILtcPtGpVhLQ");
        PublicKey senderPublic = loadPublicKey("BC5VuHLKkL86S5OEEOVqJpQGYwbohpjeNLA5cbPevnDVB15iwDnqpAxX7aHO-2_Aa3UM6_i-tKK6xgMvD5UApG0");
        params.authSecret = Base64.decode("testsecret", Base64.URL_SAFE);
        httpEce.saveKey("keyid", new KeyPair(senderPublic, senderPrivate), "P-256");
        params.keyId = "keyid";

        byte[] cipherText = httpEce.encrypt(payload, params);
        Assert.assertEquals("02YXNWs77puOgwO9AXmg97yfbaY98QU", Base64.encodeToString(cipherText,
                Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING));
    }

    @Suppress
    public void testDecrypt() throws Exception {
        HttpEce httpEce = new HttpEce();
        HttpEce.Params params = new HttpEce.Params();
        byte[] payload = Base64.decode("JmE0TL71ezjX2Je_taOT_oXVoa8PaRjC9llzbgj8kDzrnGlv6K2ql6EqIm_xaO3zqxSwedSbYJguffPwZVkxkyzjXAazXQs6uTqvvNc2ZRI-FVGfZaT_LAEgmdNtZaT7LGYJXWk-Zfa055l_unixpjEfw4MIcA", Base64.URL_SAFE);
        params.salt = Base64.decode("GpAKVJgUcQSShwYsHHRLDw", Base64.URL_SAFE);
        params.dh = loadPublicKey("BO5CDlzRLVaEB92cjjw5sOGDw2axvZrLyqcHwzQlRpvztJs4KWq1Uaw-iBb-TpG1xvQN9lPUtt4xMO7ipd6Lvok");
        PrivateKey receiverPrivate = loadPrivateKey("tHoof2dn_yjMtVfa7tYAX2OJ7Qsq_iz3YoqHpcpOZfw");
        PublicKey receiverPublic = loadPublicKey("BEPSKGemw28WxV3ujUe6srgPe4P3JDHQjdJpI5zHSZQss7VODvkrOFQQfiZAdSGxCmnJNzrvgeqixT572MsDJfo");
        httpEce.saveKey("keyid", new KeyPair(receiverPublic, receiverPrivate), "P-256");
        params.keyId = "keyid";

        byte[] cipherText = httpEce.decrypt(payload, params);
        Assert.assertEquals("Zcf3pN2DafDwWkEd6d6k-apzlsqmdw00akYOnh51yD_VbInRi1iF7J6vThuONb75ZrpP65Qkjgab10OwfAqfJP0z7z6DFdjcdgYv-cEIsDuqJgTV7llBHAcUWpCGHxg9eyvNlw", Base64.encodeToString(cipherText,
                Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING));
    }

    @Suppress
    public void testEncryptDecrypt() throws Exception {
        HttpEce httpEce = new HttpEce();

        ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "SC");
        g.initialize(parameterSpec);

        // The static key is used by the receiver
        KeyPair staticKey = g.generateKeyPair();
        httpEce.saveKey("staticKey", staticKey, "P-256");

        // The ephemeral key is used by the sender
        KeyPair ephemeralKey = g.generateKeyPair();
        httpEce.saveKey("ephemeralKey", ephemeralKey, "P-256");

        byte[] payload = "I love crypto".getBytes();
        byte salt[] = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        byte authSecret[] = new byte[16];
        random.nextBytes(authSecret);

        HttpEce.Params params = new HttpEce.Params();
        params.salt = salt;
        params.keyId = "ephemeralKey";
        params.dh = staticKey.getPublic();
        params.authSecret = authSecret;

        byte[] encrypted = httpEce.encrypt(payload, params);

        params.keyId = "staticKey";
        params.dh = ephemeralKey.getPublic();

        byte[] decrypted = httpEce.decrypt(encrypted, params);

        MoreAsserts.assertEquals(payload, decrypted);
    }
}
