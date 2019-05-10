package ru.sms;

import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import ru.CryptoPro.JCP.JCP;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.HashMap;

/**
 * Hello world!
 *
 */
public class App {
    private static final String STORE_TYPE = JCP.HD_STORE_NAME;
    private static final char[] PASSWORD = "12345".toCharArray();

    private static final String INPUT_FILE_NAME = "C:/Temp/simpleDocument.pdf";
    private static final String OUTPUT_FILE_NAME = "C:/Temp/itext_out.pdf";
    private static final String REASON = "REASON_R";
    private static final String LOCATION = "LOCATION_L";

    public static void main(String[] args) throws Exception {

        KeyStore keyStore = getKeyStore();
        if (keyStore == null) {
            return;
        }
        String alias = getAlias(keyStore);
        PrivateKey key = getKey(keyStore, alias);
        //    private static final String CONTACT = "CONTACT_C";
        Certificate[] chain = getChain(keyStore, alias);
        if (key == null || chain == null) {
            return;
        }

        final HashMap<String, String> signDigestMap = new HashMap<>();
        signDigestMap.put(JCP.GOST_EL_2012_256_NAME, JCP.GOST_DIGEST_2012_256_NAME);
        signDigestMap.put(JCP.GOST_DH_2012_256_NAME, JCP.GOST_DIGEST_2012_256_NAME);
        signDigestMap.put(JCP.GOST_EL_2012_512_NAME, JCP.GOST_DIGEST_2012_512_NAME);
        signDigestMap.put(JCP.GOST_DH_2012_512_NAME, JCP.GOST_DIGEST_2012_512_NAME);

        final String keyAlgorithm = key.getAlgorithm();
        final String hashAlgorithm = signDigestMap.get(keyAlgorithm);

        if (hashAlgorithm == null)
            return;

        sign(key, hashAlgorithm, JCP.PROVIDER_NAME, chain, INPUT_FILE_NAME, OUTPUT_FILE_NAME,
                LOCATION, REASON, true);

    }

    public static void sign(PrivateKey privateKey, String hashAlgorithm,
                            String signProvider, Certificate[] chain, String fileToSign,
                            String signedFile, String location, String reason, boolean append)
            throws Exception {

        PdfReader reader = new PdfReader(fileToSign);
        FileOutputStream fout = new FileOutputStream(signedFile);

        PdfStamper stp = append
                ? PdfStamper.createSignature(reader, fout, '\0', null, true)
                : PdfStamper.createSignature(reader, fout, '\0');

        PdfSignatureAppearance sap = stp.getSignatureAppearance();

        sap.setCertificate(chain[0]);
        sap.setReason(reason);
        sap.setLocation(location);

        PdfSignature dic = new PdfSignature(PdfName.ADOBE_CryptoProPDF,
                PdfName.ADBE_PKCS7_DETACHED);

        dic.setReason(sap.getReason());
        dic.setLocation(sap.getLocation());
        dic.setSignatureCreator(sap.getSignatureCreator());
        dic.setContact(sap.getContact());
        dic.setDate(new PdfDate(sap.getSignDate())); // time-stamp will over-rule this

        sap.setCryptoDictionary(dic);
        int estimatedSize = 8192;

        HashMap<PdfName, Integer> exc = new HashMap<>();
        exc.put(PdfName.CONTENTS, estimatedSize * 2 + 2);

        sap.preClose(exc);

        PdfPKCS7 sgn = new PdfPKCS7(privateKey, chain,
                hashAlgorithm, signProvider, null, false);

        InputStream data = sap.getRangeStream();

        MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
        byte[] hash = DigestAlgorithms.digest(data, md);

        Calendar cal = Calendar.getInstance();

        byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, cal,
                null, null, MakeSignature.CryptoStandard.CMS);

        sgn.update(sh, 0, sh.length);
        byte[] encodedSig = sgn.getEncodedPKCS7(hash, cal);

        if (estimatedSize < encodedSig.length) {
            throw new IOException("Not enough space");
        } // if

        byte[] paddedSig = new byte[estimatedSize];
        System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);

        PdfDictionary dic2 = new PdfDictionary();
        dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));

        sap.close(dic2);
        stp.close();

        fout.close();
        reader.close();

    }

    private static Certificate[] getChain(KeyStore keyStore, String alias) {
        Certificate[] chain = null;
        try {
            chain = keyStore.getCertificateChain(alias);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return chain;
    }

    private static KeyStore getKeyStore() {
        try {
            KeyStore keyStore = KeyStore.getInstance(STORE_TYPE);
            keyStore.load(null, PASSWORD);
            return keyStore;

        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static PrivateKey getKey(KeyStore keyStore, String alias) {
        try {
            return (PrivateKey) keyStore.getKey(alias, PASSWORD);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String getAlias(KeyStore keyStore) {
        String alias = null;
        try {
            alias = keyStore.aliases().nextElement();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return alias;
    }
}
