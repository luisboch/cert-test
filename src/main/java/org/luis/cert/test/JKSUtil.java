package org.luis.cert.test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;
import java.util.Formatter;

/**
 *
 * @author luis
 */
public class JKSUtil {

    private static final String CERT_BEGIN = "-----BEGIN CERTIFICATE-----\n";
    private static final String END_CERT = "-----END CERTIFICATE-----";

    public static String extractFingerPrintFromPEM(String fileName) throws Throwable {
        File file = loadFile(fileName);

        String readLines = readLines(file);
        readLines = readLines.replace(CERT_BEGIN, "").replace(END_CERT, "").replace("\n", "");

        return fingerprint(Base64.getDecoder().decode(readLines.getBytes()));
    }

    public static String extractFingerPrintFromJKSCert(String jksName, String alias, String passwd) throws Throwable {

        File file = loadFile(jksName);

        KeyStore jks = KeyStore.getInstance(file, passwd.toCharArray());
        KeyPair kp = loadKeyPair(jks, alias, passwd);

        return fingerprint(kp.certificate);

    }

    public static String fingerprint(Certificate cert) {
        try {
            return fingerprint(cert.getEncoded());
        } catch (CertificateEncodingException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static String fingerprint(byte[] array) {
        try {
            return byteToHex(MessageDigest.getInstance("SHA-1")
                    .digest(array)).toLowerCase();
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }

    private static KeyPair loadKeyPair(KeyStore jks, String alias, String password) {
        try {
            if (!jks.containsAlias(alias)) {
                return null;
            }

            KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) jks.getEntry(alias, new KeyStore.PasswordProtection(password.toCharArray()));
            Certificate[] cert = entry.getCertificateChain();
            PrivateKey pvKey = entry.getPrivateKey();
            PublicKey pubKey = entry.getCertificate().getPublicKey();

            return new KeyPair(pubKey, pvKey, cert[0]);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            throw new RuntimeException(e);
        }

    }

    private static File loadFile(String file) {

        URL resource = JKSUtil.class.getClassLoader().getResource(file);

        if (resource == null) {
            throw new IllegalArgumentException("Arquivo não encontrado: " + file);
        }

        return new File(resource.getPath());
    }

    private static String readLines(File file) throws Throwable {
        try (BufferedReader readr = new BufferedReader(new FileReader(file))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = readr.readLine()) != null) {
                sb.append(line).append("\n");
            }

            return sb.toString();
        }
    }

    public static String byteToHex(final byte[] hash) {
        Formatter formatter = new Formatter();
        for (byte b : hash) {
            formatter.format("%02x", b);
        }
        String result = formatter.toString();
        formatter.close();
        return result;
    }
}
