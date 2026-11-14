package eu.faircode.netguard;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.AtomicFile;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** ADB uses exportable RSA keys. Only their encrypted representation is persisted. */
final class InternalAdbIdentity {
    private static final String WRAPPING_KEY = "privacy.guard.internal-adb.wrapping.v1";
    private static final int FORMAT_VERSION = 1;
    final PrivateKey privateKey;
    final Certificate certificate;

    private InternalAdbIdentity(PrivateKey privateKey, Certificate certificate) {
        this.privateKey = privateKey;
        this.certificate = certificate;
    }

    static InternalAdbIdentity load(Context context) throws Exception {
        AtomicFile file = new AtomicFile(new File(context.getNoBackupFilesDir(), "internal-adb-identity.bin"));
        SecretKey wrappingKey = wrappingKey();
        if (file.getBaseFile().exists()) {
            byte[] plain;
            try (DataInputStream input = new DataInputStream(file.openRead())) {
                if (input.readInt() != FORMAT_VERSION)
                    throw new java.io.IOException("ADB identity format is unsupported");
                int ivLength = input.readInt();
                if (ivLength != 12)
                    throw new java.io.IOException("ADB identity IV is invalid");
                byte[] iv = new byte[ivLength];
                input.readFully(iv);
                long encryptedLength = file.getBaseFile().length() - 8 - ivLength;
                if (encryptedLength < 16 || encryptedLength > 16 * 1024)
                    throw new java.io.IOException("ADB identity is too large");
                byte[] encrypted = new byte[(int) encryptedLength];
                input.readFully(encrypted);
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, wrappingKey, new GCMParameterSpec(128, iv));
                plain = cipher.doFinal(encrypted);
            }
            try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(plain))) {
                int keyLength = input.readInt();
                if (keyLength < 1 || keyLength > 8192)
                    throw new java.io.IOException("ADB identity key is invalid");
                byte[] encodedKey = new byte[keyLength];
                input.readFully(encodedKey);
                PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encodedKey));
                Certificate cert = CertificateFactory.getInstance("X.509").generateCertificate(input);
                return new InternalAdbIdentity(key, cert);
            } finally {
                java.util.Arrays.fill(plain, (byte) 0);
            }
        }

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
        Certificate certificate = selfSignedCertificate(pair);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(bytes)) {
            byte[] encodedKey = pair.getPrivate().getEncoded();
            output.writeInt(encodedKey.length);
            output.write(encodedKey);
            output.write(certificate.getEncoded());
            java.util.Arrays.fill(encodedKey, (byte) 0);
        }
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey);
        byte[] plain = bytes.toByteArray();
        byte[] encrypted;
        try {
            encrypted = cipher.doFinal(plain);
        } finally {
            java.util.Arrays.fill(plain, (byte) 0);
        }
        FileOutputStream stream = file.startWrite();
        try {
            DataOutputStream output = new DataOutputStream(stream);
            output.writeInt(FORMAT_VERSION);
            output.writeInt(cipher.getIV().length);
            output.write(cipher.getIV());
            output.write(encrypted);
            output.flush();
            file.finishWrite(stream);
        } catch (Exception failure) {
            file.failWrite(stream);
            throw failure;
        }
        return new InternalAdbIdentity(pair.getPrivate(), certificate);
    }

    private static SecretKey wrappingKey() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        if (store.containsAlias(WRAPPING_KEY))
            return (SecretKey) store.getKey(WRAPPING_KEY, null);
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(WRAPPING_KEY,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build());
        return generator.generateKey();
    }

    /** Minimal self-signed X.509 certificate for TLS client authentication. */
    private static Certificate selfSignedCertificate(KeyPair pair) throws Exception {
        byte[] algorithm = der(0x30, join(
                der(0x06, new byte[]{0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x0b}),
                der(0x05, new byte[0])));
        byte[] name = der(0x30, der(0x31, der(0x30, join(
                der(0x06, new byte[]{0x55, 0x04, 0x03}),
                der(0x0c, "Privacy Guard ADB".getBytes(StandardCharsets.UTF_8))))));
        SimpleDateFormat format = new SimpleDateFormat("yyyyMMddHHmmss'Z'", Locale.US);
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        long now = System.currentTimeMillis();
        byte[] validity = der(0x30, join(
                der(0x18, format.format(new Date(now - 86_400_000L)).getBytes(StandardCharsets.US_ASCII)),
                der(0x18, format.format(new Date(now + 3650L * 86_400_000L)).getBytes(StandardCharsets.US_ASCII))));
        byte[] serial = new BigInteger(127, new SecureRandom()).add(BigInteger.ONE).toByteArray();
        byte[] certificate = der(0x30, join(der(0xa0, der(0x02, new byte[]{2})),
                der(0x02, serial), algorithm, name, validity, name, pair.getPublic().getEncoded()));
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(pair.getPrivate());
        signer.update(certificate);
        byte[] encoded = der(0x30, join(certificate, algorithm, der(0x03, join(new byte[]{0}, signer.sign()))));
        return CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(encoded));
    }

    private static byte[] der(int tag, byte[] contents) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(tag);
        if (contents.length < 128) {
            output.write(contents.length);
        } else if (contents.length < 256) {
            output.write(0x81);
            output.write(contents.length);
        } else {
            output.write(0x82);
            output.write(contents.length >>> 8);
            output.write(contents.length);
        }
        output.write(contents, 0, contents.length);
        return output.toByteArray();
    }

    private static byte[] join(byte[]... values) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for (byte[] value : values)
            output.write(value, 0, value.length);
        return output.toByteArray();
    }
}
