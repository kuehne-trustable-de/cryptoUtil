package de.trustable.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.RevRepContent;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import de.trustable.util.TestData;

public class CryptoUtilTest {

  private CryptoUtil cryptoUtil;

  KeyPair keyPair;
  
  X500Name issuer;

  X509Certificate issuingCertificate;

  final static String nonPEM_CSR = 
      "asdfghjklqwertzuiop";
  
  final static String nonASCII_CSR = 
      "äääasdfghjklqw?ÜÖertzuiop";
  
  @Before
  public void setUp() throws Exception {
    JCAManager.getInstance();
    
    keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    
    issuer = new X500Name("CN=test root " + System.currentTimeMillis() + ", O=trustable Ltd, C=DE");

    issuingCertificate = CryptoUtil.buildSelfsignedCertificate(issuer, keyPair);
    
    cryptoUtil = new CryptoUtil();
  }

  @After
  public void tearDown() throws Exception {
  }

  @Test
  public void testParseCertificateRequest() throws Exception {
    
    try {
      cryptoUtil.parseCertificateRequest(nonPEM_CSR);
      fail( "GeneralSecurityException expected");
    } catch (GeneralSecurityException e) {
      assertEquals("Parsing of CSR failed! Not PEM encoded?", e.getMessage());
    }
    
    try {
      cryptoUtil.parseCertificateRequest(nonASCII_CSR);
      fail( "GeneralSecurityException expected");
    } catch (GeneralSecurityException e) {
      assertEquals("Parsing of CSR failed! Not PEM encoded?", e.getMessage());
    }
    
    try {
      Pkcs10RequestHolder p10Req = cryptoUtil.parseCertificateRequest(TestData.SampleCSRBase64);
      assertTrue( "expect test csr to be valid", p10Req.isCSRValid() );
    } catch (GeneralSecurityException e) {
      fail( "Parsable CSR, no GeneralSecurityException expected: " +e.getMessage());
    }
    
    
  }

  @Test
  public void testGetPublicKeyFromCSR() throws IOException {
    
    try {
      Pkcs10RequestHolder p10ReqHolder = cryptoUtil.parseCertificateRequest(TestData.SampleCSRBase64);
      PublicKey pk = cryptoUtil.getPublicKeyFromCSR(p10ReqHolder.getP10Req());
      assertNotNull( "expect test csr to contain a public key", pk );
    } catch (GeneralSecurityException e) {
      fail( "Parsable valid CSR, no GeneralSecurityException expected: " +e.getMessage());
    }    
    
  }

  @Test
  public void testX509CertToPem() throws IOException {
    
    try {
      X509Certificate cert = cryptoUtil.convertPemToCertificate(TestData.SampleCertificateBase64);
      assertNotNull(cert);
      
      String pemCert = cryptoUtil.x509CertToPem(cert);
      assertNotNull(pemCert);
      
      pemCert = normalizeBase64String( pemCert );
      
      String orgPemCert = normalizeBase64String( TestData.SampleCertificateBase64 );
      assertEquals( "parsed pem must match intial certifcate", orgPemCert, pemCert);
    } catch (GeneralSecurityException e) {
      fail( "Parsable valid Certificate, no GeneralSecurityException expected: " +e.getMessage());
    }    
  }

  String normalizeBase64String(final String inB64){
    
    char[] inArr = inB64.toCharArray();
    StringBuffer sb = new StringBuffer();
    
    for( int i = 0; i < inArr.length; i++){
      if( Character.isWhitespace( inArr[i] )){
        // just ignore
      } else {
        sb.append(inArr[i]);
      }
    }
    return sb.toString();
  }
  
  @Test
  public void testConvertPemToPKCS10CertificationRequest() throws GeneralSecurityException {
    
    PKCS10CertificationRequest p10 = cryptoUtil.convertPemToPKCS10CertificationRequest(TestData.SampleCSRBase64);
    assertNotNull(p10);  
    
    assertTrue(p10.getSubject().toString().contains("C=DE,O=trustable Ltd") );

  }

  @Test
  public void testGetDERObject() throws GeneralSecurityException, IOException {
    
    X509Certificate cert = cryptoUtil.convertPemToCertificate(TestData.SampleCertificateBase64);
    assertNotNull(cert);
    
      final ASN1Primitive derObject = cryptoUtil.getDERObject(cert.getEncoded());
    assertNotNull(derObject);
    
    assertEquals(DLSequence.class.getName(), derObject.getClass().getName() );

  }

  
  @Test
  public void testGetCrlReasonFromString() throws GeneralSecurityException, IOException {
    
    assertEquals(CRLReason.keyCompromise, cryptoUtil.crlReasonFromString("1").getValue().intValue() );
    assertEquals(CRLReason.keyCompromise, cryptoUtil.crlReasonFromString("keyCompromise").getValue().intValue() );
    assertEquals(CRLReason.cACompromise, cryptoUtil.crlReasonFromString("2").getValue().intValue() );
    assertEquals(CRLReason.cACompromise, cryptoUtil.crlReasonFromString("cACompromise").getValue().intValue() );
    assertEquals(CRLReason.affiliationChanged, cryptoUtil.crlReasonFromString("3").getValue().intValue() );
    assertEquals(CRLReason.affiliationChanged, cryptoUtil.crlReasonFromString("affiliationChanged").getValue().intValue() );
    assertEquals(CRLReason.superseded, cryptoUtil.crlReasonFromString("4").getValue().intValue() );
    assertEquals(CRLReason.superseded, cryptoUtil.crlReasonFromString("superseded").getValue().intValue() );
    assertEquals(CRLReason.cessationOfOperation, cryptoUtil.crlReasonFromString("5").getValue().intValue() );
    assertEquals(CRLReason.cessationOfOperation, cryptoUtil.crlReasonFromString("cessationOfOperation").getValue().intValue() );
    assertEquals(CRLReason.privilegeWithdrawn, cryptoUtil.crlReasonFromString("9").getValue().intValue() );
    assertEquals(CRLReason.privilegeWithdrawn, cryptoUtil.crlReasonFromString("privilegeWithdrawn").getValue().intValue() );
    assertEquals(CRLReason.aACompromise, cryptoUtil.crlReasonFromString("10").getValue().intValue() );
    assertEquals(CRLReason.aACompromise, cryptoUtil.crlReasonFromString("aACompromise").getValue().intValue() );
    assertEquals(CRLReason.unspecified, cryptoUtil.crlReasonFromString("").getValue().intValue() );
    assertEquals(CRLReason.unspecified, cryptoUtil.crlReasonFromString("unspecified").getValue().intValue() );
  }
  
  @Test
  public void testGetCrlReasonAsString() throws GeneralSecurityException, IOException {
    assertEquals("unspecified", cryptoUtil.crlReasonAsString(CRLReason.lookup(CRLReason.unspecified)));
    assertEquals("keyCompromise", cryptoUtil.crlReasonAsString(CRLReason.lookup(CRLReason.keyCompromise)));
    assertEquals("cACompromise", cryptoUtil.crlReasonAsString(CRLReason.lookup(CRLReason.cACompromise)));
    assertEquals("affiliationChanged", cryptoUtil.crlReasonAsString(CRLReason.lookup(CRLReason.affiliationChanged)));
    assertEquals("superseded", cryptoUtil.crlReasonAsString(CRLReason.lookup(CRLReason.superseded)));
    assertEquals("cessationOfOperation", cryptoUtil.crlReasonAsString(CRLReason.lookup(CRLReason.cessationOfOperation)));
    assertEquals("privilegeWithdrawn", cryptoUtil.crlReasonAsString(CRLReason.lookup(CRLReason.privilegeWithdrawn)));
    assertEquals("aACompromise", cryptoUtil.crlReasonAsString(CRLReason.lookup(CRLReason.aACompromise)));
  }
  
  /**
   * @throws IOException 
   * @throws GeneralSecurityException 
   * @throws CMPException 
   * @throws CRMFException 
   */
	@Test
	public final void testCMPCertificateRequest() throws IOException,
			GeneralSecurityException, CRMFException, CMPException {

		final ASN1Primitive derObject = cryptoUtil.getDERObject(Base64
				.decode(TestData.ValidCMPCertificateRequestBase64));
		final PKIMessage pkiMessageReq = PKIMessage.getInstance(derObject);

		byte[] cmpResp = cryptoUtil.handleCMPRequest("alias", "",
				Base64.decode(TestData.ValidCMPCertificateRequestBase64),
				issuingCertificate, issuer, keyPair);

		assertNotNull("Expected a byte array as cmp response", cmpResp);
		assertTrue("Expected a byte array as cmp response",
				cmpResp.length > 1234);

	}

  /**
   * @throws IOException 
   * @throws GeneralSecurityException 
   * @throws CMPException 
   * @throws CRMFException 
   */
  @Test
  public final void testCMPRevocationRequest() throws IOException, GeneralSecurityException, CRMFException, CMPException {

    byte[] cmpResp = cryptoUtil.handleCMPRequest("alias", "", Base64.decode(TestData.ValidCMPRevocationRequestBase64), issuingCertificate, issuer, keyPair); 
    
    assertNotNull("Expected a byte array as cmp response", cmpResp);
    assertTrue("Expected a byte array as cmp response", cmpResp.length > 123);
    
    RevRepContent revRep = cryptoUtil.readRevResponse( cmpResp);
    
    assertNotNull("Expected a revocation response", revRep );
    
  }
  
}
