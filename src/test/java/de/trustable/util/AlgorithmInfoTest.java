package de.trustable.util;

import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;

import static org.junit.Assert.assertEquals;


public class AlgorithmInfoTest {

    static final String PKCS1_CSR = "-----BEGIN CERTIFICATE REQUEST-----\n"+
    "MIICfjCCAWYCAQAwETEPMA0GA1UEAwwGZm9vLmRlMIIBIjANBgkqhkiG9w0BAQEF\n" +
    "AAOCAQ8AMIIBCgKCAQEAkkqr1M6B8pygBunvWYzM2E/DB8jTCJmuP+w4jhbyEQEm\n" +
    "v/eajq494Lmo5SiZoxNBa2t6jkhg4sMfe7RJ2FRpxoTQsvWBBowC+sokYnaHaM4L\n" +
    "FBXMVQp1f6xFHVvipiUPW+XSavGPDlIMbw7Q6QMSVTvZrSuED8JzmqdQIeohRwHL\n" +
    "YsTFbstBg5vHoxIy/Iqd6OeJSSnbsf2Mvu3O2gB0/EzLKcfbgYsogXSd4MHxDR/h\n" +
    "5UfKfEt7spS/qwDBpyz2IC000wmwYsugbZMh52hmAboZoGgXRSe+PYq1BWpMI2Cs\n" +
    "kES1Ofb3BH6GCAbAHrYur5QQx0zyFg0sJ6/y+DKxiwIDAQABoCgwJgYJKoZIhvcN\n" +
    "AQkOMRkwFzAVBgNVHREEDjAMggp3d3cuZm9vLmRlMA0GCSqGSIb3DQEBCwUAA4IB\n" +
    "AQAbU3XxqB2YegtFUqvFdEb7dRH/imlbhYS3tNSHwUSysiNE8JNUFyxDfD6zgrqX\n" +
    "QFNi5uoWAxZvEf3JZ9uc0i0fJjIjjmkpmNeMA6S23le2eeoGKVbjUFrr/sZF9enT\n" +
    "g0R6HRgBTuOURQfPWElcJH64vNQqb3WrWalYrNfDz9OIHbqSHyFTxrqarnviAMJ0\n" +
    "hUR9gGswbTxl9mEKLRwIc5iiF9URoJWEZkcOLBoUbIfmxF2Zru/bjelxhOfAJfEz\n" +
    "GTk8INtpFBc3UWwCDjR1BaXMC/zeAtreQ8vMXugsj8HFGJ9LIiMvRDURfVwT8RzH\n" +
    "NEx4v3u8QXicHHjkbU9d9PAN\n" +
    "-----END CERTIFICATE REQUEST-----\n";

    static final String PSS_CSR = "-----BEGIN CERTIFICATE REQUEST-----\n"+
    "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\n"+
    "RtVncG0Tnfq7TLvSxe9OiQ==\n"+
    "-----END CERTIFICATE REQUEST-----";

    static final String ECDSA256_CSR = "-----BEGIN CERTIFICATE REQUEST-----\n" +
    "MIHXMH8CAQAwHTEbMBkGA1UEAwwSZWNkc2EudHJ1c3RhYmxlLmRlMFkwEwYHKoZI\n" +
    "zj0CAQYIKoZIzj0DAQcDQgAERPk9GfnKXnXIo+NUSP9vZuaQgg+47vwjQPLvxIIe\n" +
    "ZTznghPY8KwjRa8Iqoybn7TOu+D/kAoOeKFv3WiDE6Avx6AAMAoGCCqGSM49BAMC\n" +
    "A0gAMEUCIEgdxXviUEyN45J+2xoYr4h/My5uo1a9xsqXD0CkWe1LAiEA47Rgm3dD\n" +
    "8ZIlGI/P8rCi0SxcEO2DLhUoCPtKnuFrN6g=\n" +
    "-----END CERTIFICATE REQUEST-----";

    static final String ED25519_CSR = "-----BEGIN CERTIFICATE REQUEST-----\n" +
    "MIGeMFICAQAwHzEdMBsGA1UEAwwUZWQyNTUxOS50cnVzdGFibGUuZGUwKjAFBgMr\n" +
    "ZXADIQDJUq95+nHGgOjXszsLWHh23JlOLaQvIYYMoqj3+bwevKAAMAUGAytlcANB\n" +
    "ADQRHsZmIz5OyGNB11Gd/f/adhlxB5Y6hgw8P99jxB/dquqPs7tSriE0oPxZXgEb\n" +
    "JdPLBsVEVFAWs6zt+QNzSwY=\n" +
    "-----END CERTIFICATE REQUEST-----";


    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void getSigAlgPKCS1() throws GeneralSecurityException, IOException {

        CryptoUtil cryptoUtil = new CryptoUtil();

        Pkcs10RequestHolder p10ReqHolder = cryptoUtil.parseCertificateRequest(cryptoUtil.convertPemToPKCS10CertificationRequest(PKCS1_CSR));

        assertEquals("rsa", p10ReqHolder.getPublicKeyAlgorithmShortName());

        AlgorithmInfo algorithmInfo = new AlgorithmInfo(p10ReqHolder.getSigningAlgorithmName());

        System.out.println("input name        : " + p10ReqHolder.getSigningAlgorithmName());
        System.out.println("SigAlgName        : " + algorithmInfo.getSigAlgName());
        System.out.println("HashAlgName       : " + algorithmInfo.getHashAlgName());
        System.out.println("HashAlgName       : " + OidNameMapper.lookupOid(algorithmInfo.getHashAlgName()));
        System.out.println("PaddingAlgName    : " + algorithmInfo.getPaddingAlgName());
        System.out.println("SigAlgFriendlyName: " + algorithmInfo.getSigAlgFriendlyName());

        assertEquals("sha256WithRSAEncryption", p10ReqHolder.getSigningAlgorithmName());
        assertEquals("rsa", algorithmInfo.getSigAlgName());
        assertEquals("rsa", algorithmInfo.getSigAlgFriendlyName());
        assertEquals("sha-256", algorithmInfo.getHashAlgName());
        assertEquals("PKCS1", algorithmInfo.getPaddingAlgName());

    }

    @Test
    public void getSigAlgPSS() throws GeneralSecurityException, IOException {

        CryptoUtil cryptoUtil = new CryptoUtil();

        Pkcs10RequestHolder p10ReqHolder = cryptoUtil.parseCertificateRequest(cryptoUtil.convertPemToPKCS10CertificationRequest(PSS_CSR));

        assertEquals("rsa", p10ReqHolder.getPublicKeyAlgorithmShortName());

        AlgorithmInfo algorithmInfo = new AlgorithmInfo(p10ReqHolder.getSigningAlgorithmName());

        System.out.println("input name        : " + p10ReqHolder.getSigningAlgorithmName());
        System.out.println("SigAlgName        : " + algorithmInfo.getSigAlgName());
        System.out.println("HashAlgName       : " + algorithmInfo.getHashAlgName());
        System.out.println("HashAlgName       : " + OidNameMapper.lookupOid(algorithmInfo.getHashAlgName()));
        System.out.println("PaddingAlgName    : " + algorithmInfo.getPaddingAlgName());
        System.out.println("SigAlgFriendlyName: " + algorithmInfo.getSigAlgFriendlyName());

        assertEquals("rsaPSS", p10ReqHolder.getSigningAlgorithmName());
        assertEquals("rsa", algorithmInfo.getSigAlgName());
        assertEquals("rsa", algorithmInfo.getSigAlgFriendlyName());
        assertEquals("", algorithmInfo.getHashAlgName());
        assertEquals("pss", algorithmInfo.getPaddingAlgName());

    }

    @Test
    public void getSigAlgECDSA() throws GeneralSecurityException, IOException {

        CryptoUtil cryptoUtil = new CryptoUtil();

        Pkcs10RequestHolder p10ReqHolder = cryptoUtil.parseCertificateRequest(cryptoUtil.convertPemToPKCS10CertificationRequest(ECDSA256_CSR));
        assertEquals("ecdsa", p10ReqHolder.getPublicKeyAlgorithmShortName());

        AlgorithmInfo algorithmInfo = new AlgorithmInfo(p10ReqHolder.getSigningAlgorithmName());

        System.out.println("input name        : " + p10ReqHolder.getSigningAlgorithmName());
        System.out.println("SigAlgName        : " + algorithmInfo.getSigAlgName());
        System.out.println("HashAlgName       : " + algorithmInfo.getHashAlgName());
        System.out.println("HashAlgName       : " + OidNameMapper.lookupOid(algorithmInfo.getHashAlgName()));
        System.out.println("PaddingAlgName    : " + algorithmInfo.getPaddingAlgName());
        System.out.println("SigAlgFriendlyName: " + algorithmInfo.getSigAlgFriendlyName());

        assertEquals("ecdsaWithSHA256", p10ReqHolder.getSigningAlgorithmName());
        assertEquals("ecdsa", algorithmInfo.getSigAlgName());
        assertEquals("ecdsa", algorithmInfo.getSigAlgFriendlyName());
        assertEquals("sha-256", algorithmInfo.getHashAlgName());
        assertEquals("", algorithmInfo.getPaddingAlgName());

    }


    @Test
    public void getSigAlgED25519() throws GeneralSecurityException, IOException {

        CryptoUtil cryptoUtil = new CryptoUtil();

        Pkcs10RequestHolder p10ReqHolder = cryptoUtil.parseCertificateRequest(cryptoUtil.convertPemToPKCS10CertificationRequest(ED25519_CSR));
        assertEquals("ed25519", p10ReqHolder.getPublicKeyAlgorithmShortName());

        AlgorithmInfo algorithmInfo = new AlgorithmInfo(p10ReqHolder.getSigningAlgorithmName());

        System.out.println("input name        : " + p10ReqHolder.getSigningAlgorithmName());
        System.out.println("SigAlgName        : " + algorithmInfo.getSigAlgName());
        System.out.println("HashAlgName       : " + algorithmInfo.getHashAlgName());
        System.out.println("HashAlgName       : " + OidNameMapper.lookupOid(algorithmInfo.getHashAlgName()));
        System.out.println("PaddingAlgName    : " + algorithmInfo.getPaddingAlgName());
        System.out.println("SigAlgFriendlyName: " + algorithmInfo.getSigAlgFriendlyName());

        assertEquals("ed25519", p10ReqHolder.getSigningAlgorithmName());
        assertEquals("ed25519", algorithmInfo.getSigAlgName());
        assertEquals("ed25519", algorithmInfo.getSigAlgFriendlyName());
        assertEquals("sha-256", algorithmInfo.getHashAlgName());
        assertEquals("", algorithmInfo.getPaddingAlgName());

    }

    @Test
    public void getSigAlgFriendlyName() throws GeneralSecurityException, IOException {

        CryptoUtil cryptoUtil = new CryptoUtil();

        Pkcs10RequestHolder p10ReqHolder = cryptoUtil.parseCertificateRequest(cryptoUtil.convertPemToPKCS10CertificationRequest(PSS_CSR));
        RSASSAPSSparams rsassapssParams = RSASSAPSSparams.getInstance(p10ReqHolder.getP10Req().getSignatureAlgorithm().getParameters());
        AlgorithmInfo algorithmInfo = new AlgorithmInfo(rsassapssParams);

        System.out.println("input name        : " + p10ReqHolder.getSigningAlgorithmName());
        System.out.println("SigAlgName        : " + algorithmInfo.getSigAlgName());
        System.out.println("HashAlgName       : " + algorithmInfo.getHashAlgName());
        System.out.println("HashAlgName       : " + OidNameMapper.lookupOid(algorithmInfo.getHashAlgName()));

        System.out.println("PaddingAlgName    : " + algorithmInfo.getPaddingAlgName());
        System.out.println("SigAlgFriendlyName: " + algorithmInfo.getSigAlgFriendlyName());

    }
}
