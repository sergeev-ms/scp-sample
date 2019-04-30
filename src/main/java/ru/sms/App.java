package ru.sms;

import com.itextpdf.io.util.DateTimeUtil;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.*;
import com.sun.istack.internal.Nullable;
import ru.CryptoPro.JCP.JCP;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
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
    private static final String CONTACT = "CONTACT_C";
    private static Certificate[] chain;

    public static void main(String[] args) throws IOException {

        KeyStore keyStore = getKeyStore();
        if (keyStore == null) {
            return;
        }
        String alias = getAlias(keyStore);
        PrivateKey key = getKey(keyStore, alias);
        chain = getChain(keyStore, alias);
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

        final PrivateKeySignature signature = new PrivateKeySignature(key, hashAlgorithm, JCP.PROVIDER_NAME);

        PdfReader pdfReader = getPdfReader();
        if (pdfReader == null)
            return;

        final PdfSigner signer = getSigner(pdfReader);

        try {
            signer.signDetached(new BouncyCastleDigest(), signature, chain, null, null, null, 0, PdfSigner.CryptoStandard.CADES);
            System.out.println("Done");
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }

    }

    private static void setAppearance(PdfSigner signer) {
        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance.setLayer2FontSize(13.8f)
                .setPageRect(new Rectangle(36, 548, 250, 150))
                .setPageNumber(1)
                .setReason(REASON)
                .setLocation(LOCATION)
                .setContact(CONTACT)
                .setCertificate(chain[0])
                .setRenderingMode(PdfSignatureAppearance.RenderingMode.NAME_AND_DESCRIPTION);

    }

    private static PdfSigner getSigner(PdfReader pdfReader) throws IOException {
        PdfSigner signer;
        final PdfSignature dic = new PdfSignature(PdfName.ADOBE_CryptoProPDF, PdfName.Adbe_pkcs7_detached);
        FileOutputStream outputStream = new FileOutputStream(OUTPUT_FILE_NAME);
        signer = new PdfSigner(pdfReader, outputStream, new StampingProperties().useAppendMode(), dic);
        signer.setCertificationLevel(PdfSigner.CERTIFIED_NO_CHANGES_ALLOWED);
        signer.setSignDate(DateTimeUtil.getCurrentTimeCalendar());
        setAppearance(signer);
        return signer;
    }

    private static PdfReader getPdfReader() {
        PdfReader pdfReader = null;
        try {
            pdfReader = new PdfReader(INPUT_FILE_NAME);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return pdfReader;
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

    @Nullable
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
