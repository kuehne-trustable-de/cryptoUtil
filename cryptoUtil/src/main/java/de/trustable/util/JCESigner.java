package de.trustable.util;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JCESigner implements ContentSigner {

  private static final Logger LOGGER = LoggerFactory.getLogger(JCESigner.class);

    private static final AlgorithmIdentifier PKCS1_SHA256_WITH_RSA_OID = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11"));

    private Signature signature;
    private ByteArrayOutputStream outputStream;

    public JCESigner(PrivateKey privateKey ) {

        try {
            this.outputStream = new ByteArrayOutputStream();
            this.signature = Signature.getInstance("SHA256withRSA");
            this.signature.initSign(privateKey);
        } catch (GeneralSecurityException gse) {
          LOGGER.info("creating JCESigner", gse);
            throw new IllegalArgumentException(gse.getMessage()); 
        }
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        if ("SHA256withRSA".equals(signature.getAlgorithm())) {
            return PKCS1_SHA256_WITH_RSA_OID;
        } else {
            return null;
        }
    }

    @Override
    public OutputStream getOutputStream() {
        return outputStream;
    }

    @Override
    public byte[] getSignature() {
        try {
            signature.update(outputStream.toByteArray());
            return signature.sign();
        } catch (GeneralSecurityException gse) { 
          LOGGER.info("getSignature", gse);
        }
        return null;
    }
}
