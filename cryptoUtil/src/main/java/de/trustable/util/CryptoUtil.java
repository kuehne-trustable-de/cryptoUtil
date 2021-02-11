package de.trustable.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.GenMsgContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.cmp.RevRepContent;
import org.bouncycastle.asn1.cmp.RevRepContentBuilder;
import org.bouncycastle.asn1.cmp.RevReqContent;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.puppetlabs.ssl_utils.ExtensionsUtils;


public class CryptoUtil {

  private static final String SERIAL_PADDING_PATTERN = "000000000000000000000";

private static final Logger LOGGER = LoggerFactory.getLogger(CryptoUtil.class);


    SecureRandom secRandom = new SecureRandom();
    
    /**
     * 
     */
    public CryptoUtil(){}

    
	/**
	 * Align a serial number to a default length
	 * @param serial the serial number
	 * @return the normalized serial number string
	 */
	public static String getPaddedSerial(final String serial){
	
		int len = serial.length();
		if( len >= SERIAL_PADDING_PATTERN.length() ){
			return serial;
		}
		return SERIAL_PADDING_PATTERN.substring(serial.length()) + serial; 
	}
	
    /**
     * Generate a SHA1 fingerprint from a byte array containing a X.509 certificate
     *
     * @param ba Byte array containing DER encoded X509Certificate.
     * @return Byte array containing SHA1 hash of DER encoded certificate.
     */
    public static byte[] generateSHA1Fingerprint(byte[] ba) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");
            return md.digest(ba);
        } catch (NoSuchAlgorithmException nsae) {
            LOGGER.error("SHA1 algorithm not supported", nsae);
        }
        return null;
    } // generateSHA1Fingerprint


	/**
	 * convert the usage-bits to a readable string
	 * @param usage the array of bits representing the different bits
	 * @return descriptive text representing the key usage
	 */
	public static String usageAsString( boolean[] usage ){

		if( ( usage == null ) || ( usage.length == 0 ) ){
			return( "unspecified usage" );
		}

		String desc = "valid for ";
		if ( (usage.length > 0) && usage[0]) desc += "digitalSignature ";
		if ( (usage.length > 1) && usage[1]) desc += "nonRepudiation ";
		if ( (usage.length > 2) && usage[2]) desc += "keyEncipherment ";
		if ( (usage.length > 3) && usage[3]) desc += "dataEncipherment ";
		if ( (usage.length > 4) && usage[4]) desc += "keyAgreement ";
		if ( (usage.length > 5) && usage[5]) desc += "keyCertSign ";
		if ( (usage.length > 6) && usage[6]) desc += "cRLSign ";
		if ( (usage.length > 7) && usage[7]) desc += "encipherOnly ";
		if ( (usage.length > 8) && usage[8]) desc += "decipherOnly ";

		return (desc);
	}

	
	public Pkcs10RequestHolder parseCertificateRequest( final byte[] csr ) throws IOException, GeneralSecurityException {
		  
		return parseCertificateRequest(new PKCS10CertificationRequest(csr));
	}
	
	public Pkcs10RequestHolder parseCertificateRequest(final PKCS10CertificationRequest p10Request)
			throws IOException, GeneralSecurityException {

		Pkcs10RequestHolder reqHolder = new Pkcs10RequestHolder();
		
		reqHolder.setP10Req(p10Request);

		X500Name subject = reqHolder.getP10Req().getSubject();
		reqHolder.setSubjectRDNs(subject.getRDNs());

		reqHolder.setSubject(subject.toString());

		reqHolder.setReqAttributes(reqHolder.getP10Req().getAttributes());
		
		String signingAlgorithm = reqHolder.getP10Req().getSignatureAlgorithm().getAlgorithm().getId();
		reqHolder.setSigningAlgorithm(signingAlgorithm);
		reqHolder.setSigningAlgorithmName(OidNameMapper.lookupOid(signingAlgorithm));

		PublicKey publicKey = null;
		SubjectPublicKeyInfo subjectPKInfo = reqHolder.getP10Req().getSubjectPublicKeyInfo();

		try {
			X509EncodedKeySpec xspec = new X509EncodedKeySpec(new DERBitString(subjectPKInfo).getBytes());
			reqHolder.setX509KeySpec(xspec.getFormat());

			AlgorithmIdentifier keyAlg = subjectPKInfo.getAlgorithm();

			reqHolder.setPublicKeyAlgorithm(keyAlg.getAlgorithm().getId());
			reqHolder.setPublicKeyAlgorithmName(OidNameMapper.lookupOid(keyAlg.getAlgorithm().getId()));

			publicKey = KeyFactory.getInstance(keyAlg.getAlgorithm().getId(), "BC").generatePublic(xspec);

			reqHolder.setPublicSigningKey(publicKey);

			reqHolder.setSubjectPublicKeyInfoBase64(Base64.toBase64String(subjectPKInfo.getEncoded()));

			reqHolder.setPublicKeyHash(getHashAsBase64(publicKey.getEncoded()));

			ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder().setProvider("BC")
					.build(publicKey);

			reqHolder.setCSRValid(reqHolder.getP10Req().isSignatureValid(contentVerifierProvider));

		} catch (OperatorCreationException e1) {
			LOGGER.info("Problem processing the incoming csr", e1);
			throw new GeneralSecurityException(e1.getMessage());
		} catch (PKCSException e) {
			LOGGER.info("Problem parsing the incoming csr", e);
			throw new GeneralSecurityException(e.getMessage());
		} catch (InvalidKeySpecException e) {
			LOGGER.info("retrieving public key from CSR failed", e);
			throw new GeneralSecurityException("error retrieving public key from CSR: " + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			LOGGER.info("algorithm of CSR unknown", e);
			throw new GeneralSecurityException("algorithm of CSR unknown: " + e.getMessage());
		}

		// if( !isCSRValid){
		// logger.info("Problem verifying the incoming csr");
		// new GeneralSecurityException( "INVALID incoming csr " + p10Req.getSubject() +
		// ", " + p10Req.getSubjectPublicKeyInfo());
		// }

		return reqHolder;
	}


  /**
   * 
   * @param p10Req a structure containing the CSR details
   * @return the public key requesting to be signed
   * @throws IOException problem parsing the csr
   * @throws GeneralSecurityException some security problem occurred
   */
    public PublicKey getPublicKeyFromCSR(PKCS10CertificationRequest p10Req) throws IOException, GeneralSecurityException {
		PublicKey publicKey = null;
		SubjectPublicKeyInfo subjectPKInfo = p10Req.getSubjectPublicKeyInfo();

		try {
		  X509EncodedKeySpec xspec =
			  new X509EncodedKeySpec(new DERBitString(subjectPKInfo).getBytes());
		  AlgorithmIdentifier keyAlg = subjectPKInfo.getAlgorithm();
		  publicKey = KeyFactory.getInstance(keyAlg.getAlgorithm().getId(), "BC").generatePublic(xspec);
		} catch (InvalidKeySpecException e) {
		  LOGGER.info("retrieving public key from CSR failed", e);
		  throw new GeneralSecurityException("error retrieving public key from CSR: " + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
		  LOGGER.info("algorithm of CSR unknown", e);
		  throw new GeneralSecurityException("algorithm of CSR unknown: " + e.getMessage());
		}
		return publicKey;
  	}

  /**
   *
   * @param req a structure containing the CSR details
   * @return a PEM encoded CSR
   * @throws IOException problem parsing the CSR
   */
  public static String pkcs10RequestToPem( PKCS10CertificationRequest req) throws IOException{
    
    StringWriter stringWriter = new StringWriter();
    JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
      pemWriter.writeObject(req);
      pemWriter.close();
      
      return stringWriter.toString();
  }

  /**
   *
   * @param cert a certificate object
   * @return a PEM encoded certificate
   * @throws IOException problem serializing the certificate
   */
  public String x509CertToPem( X509Certificate cert) throws IOException{
    
    StringWriter stringWriter = new StringWriter();
    JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
      pemWriter.writeObject(cert);
      pemWriter.close();
      
      return stringWriter.toString();
  }

  /**
   *
   * @param pk a public key object
   * @return a PEM encoded public key
   * @throws IOException problem serializing the public key
   */
  public String publicKeyToPem(PublicKey pk) throws IOException{
    
    StringWriter stringWriter = new StringWriter();
    JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
      pemWriter.writeObject(pk);
      pemWriter.close();
      
      return stringWriter.toString();
  }

	/**
	 * parse a PEM encoded csr, verify it and return the P10 request holder
	 *
	 * @param csr a certificate signing request as base64 string
	 * @return a holder object containing the CSR details
	 * @throws IOException problem parsing the csr
	 * @throws GeneralSecurityException some security problem occurred
	 */
	public Pkcs10RequestHolder parseCertificateRequest( final String csr ) throws IOException, GeneralSecurityException{

		return parseCertificateRequest(convertPemToPKCS10CertificationRequest(csr));
	}


	/**
	 * parse a PEM encoded csr, verify it and return the P10 request object
	 *
	 * @param pem a certificate signing request as base64 string
	 * @return an object containing the CSR
	 * @throws GeneralSecurityException some security problem occurred
	 */
  	public PKCS10CertificationRequest convertPemToPKCS10CertificationRequest(final String pem) throws GeneralSecurityException {

        PKCS10CertificationRequest csr = null;
        ByteArrayInputStream pemStream = null;
        try {
            pemStream = new ByteArrayInputStream(pem.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException ex) {
            LOGGER.error("UnsupportedEncodingException, convertPemToPublicKey", ex);
            throw new GeneralSecurityException("Parsing of CSR failed due to encoding problem! Not PEM encoded?");
        }

        Reader pemReader = new InputStreamReader(pemStream);
        PEMParser pemParser = new PEMParser(pemReader);

        try {
            Object parsedObj = pemParser.readObject();

            if( parsedObj == null ){
                throw new GeneralSecurityException("Parsing of CSR failed! Not PEM encoded?");
            }
            
//            LOGGER.debug("PemParser returned: " + parsedObj);
            
            if (parsedObj instanceof PKCS10CertificationRequest) {
                csr = (PKCS10CertificationRequest) parsedObj;

            }
        } catch (IOException ex) {
          	LOGGER.error("IOException, convertPemToPublicKey", ex);
      		throw new GeneralSecurityException("Parsing of CSR failed! Not PEM encoded?");
        }finally{
            try {
        	    pemParser.close();
      		} catch (IOException e) {
                // just ignore
                LOGGER.debug("IOException on close()", e);
            }
        }

        return csr;
    }


  /**
   *
   * @param pem a PEM encoded public key
   * @return  a public key object
   * @throws GeneralSecurityException some security problem occurred
   */
  public PublicKey convertPemToPublicKey (final String pem) throws GeneralSecurityException {
    
    PublicKey pubKey = null;
        ByteArrayInputStream pemStream = null;
        try {
            pemStream = new ByteArrayInputStream(pem.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException ex) {
            LOGGER.error("UnsupportedEncodingException, convertPemToPublicKey", ex);
            throw new GeneralSecurityException("Parsing of PublicKey failed due to encoding problem! Not PEM encoded?");
        }

        Reader pemReader = new InputStreamReader(pemStream);
        PEMParser pemParser = new PEMParser(pemReader);

        try {
            Object parsedObj = pemParser.readObject();

            if( parsedObj == null ){
                throw new GeneralSecurityException("Parsing of PublicKey failed! Not PEM encoded?");
            }
            
//            LOGGER.info("PemParser returned: " + parsedObj);
            
            if (parsedObj instanceof PublicKey ) {
                pubKey = (PublicKey) parsedObj;
            }
        } catch (IOException ex) {
            LOGGER.error("IOException, convertPemToPublicKey", ex);
            throw new GeneralSecurityException("Parsing of PublicKey  failed! Not PEM encoded?");
        }finally{
            try {
                pemParser.close();
            } catch (IOException e) {
                // just ignore
                LOGGER.debug("IOException on close()", e);
            }
        }

        return pubKey;
    }

  
  /**
   *
   * @param pem a PEM encoded certificate
   * @return a certificate details holder object
   * @throws GeneralSecurityException some security problem occurred
   */
  public X509CertificateHolder convertPemToCertificateHolder (final String pem) throws GeneralSecurityException {
	  
	X509Certificate x509Cert = convertPemToCertificate (pem);
	try {
		return new X509CertificateHolder(x509Cert.getEncoded());
	} catch (IOException e) {
		throw new GeneralSecurityException(e);
	}
	
  }
  
	/**
	 *
     * @param pem a PEM encoded certificate
     * @return a X509 certificate
     * @throws GeneralSecurityException some security problem occurred
	 */
	public static X509Certificate convertPemToCertificate(final String pem)
			throws GeneralSecurityException {

		X509Certificate cert = null;
		ByteArrayInputStream pemStream = null;
		try {
			pemStream = new ByteArrayInputStream(pem.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException ex) {
			LOGGER.error("UnsupportedEncodingException, convertPemToPublicKey",
					ex);
			throw new GeneralSecurityException(
					"Parsing of PublicKey failed due to encoding problem! Not PEM encoded?");
		}

		Reader pemReader = new InputStreamReader(pemStream);
		PEMParser pemParser = new PEMParser(pemReader);

		try {
			Object parsedObj = pemParser.readObject();

			if (parsedObj == null) {
				throw new GeneralSecurityException(
						"Parsing of certificate failed! Not PEM encoded?");
			}

			LOGGER.debug("PemParser returned: " + parsedObj);

			if (parsedObj instanceof X509CertificateHolder) {
				cert = new JcaX509CertificateConverter().setProvider("BC")
						.getCertificate((X509CertificateHolder) parsedObj);

			} else {
				throw new GeneralSecurityException(
						"Unexpected parsing result: "
								+ parsedObj.getClass().getName());
			}
		} catch (IOException ex) {
			LOGGER.error("IOException, convertPemToCertificate", ex);
			throw new GeneralSecurityException(
					"Parsing of certificate failed! Not PEM encoded?");
		} finally {
			try {
				pemParser.close();
			} catch (IOException e) {
				// just ignore
				LOGGER.debug("IOException on close()", e);
			}
		}

		return cert;
	}

	/**
	 *
     * @param pem a PEM encoded private key
     * @return a private key object
     * @throws GeneralSecurityException some security problem occurred
	 */
	public PrivateKey convertPemToPrivateKey(final String pem)
			throws GeneralSecurityException {

		PrivateKey privKey = null;
		ByteArrayInputStream pemStream = null;
		try {
			pemStream = new ByteArrayInputStream(pem.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException ex) {
			LOGGER.error("UnsupportedEncodingException, PrivateKey", ex);
			throw new GeneralSecurityException(
					"Parsing of PEM file failed due to encoding problem! Not PEM encoded?");
		}

		Reader pemReader = new InputStreamReader(pemStream);
		PEMParser pemParser = new PEMParser(pemReader);

		try {
			Object parsedObj = pemParser.readObject();

			if (parsedObj == null) {
				throw new GeneralSecurityException(
						"Parsing of certificate failed! Not PEM encoded?");
			}

//			LOGGER.debug("PemParser returned: " + parsedObj);

			if (parsedObj instanceof PrivateKeyInfo) {
				privKey = new JcaPEMKeyConverter().setProvider("BC")
						.getPrivateKey((PrivateKeyInfo) parsedObj);
			} else {
				throw new GeneralSecurityException(
						"Unexpected parsing result: "
								+ parsedObj.getClass().getName());
			}

		} catch (IOException ex) {
			LOGGER.error("IOException, convertPemToCertificate", ex);
			throw new GeneralSecurityException(
					"Parsing of certificate failed! Not PEM encoded?");
		} finally {
			try {
				pemParser.close();
			} catch (IOException e) {
				// just ignore
				LOGGER.debug("IOException on close()", e);
			}
		}

		return privKey;
	}

	/**
   * 
   * @param ba a byte array containg an ASN.1 object
   * @return the basic ASN.1 object
   * @throws IOException problem parsing the ASN.1 structure
   */
    public ASN1Primitive getDERObject(byte[] ba) throws IOException {
        ASN1InputStream ins = new ASN1InputStream(ba);
        try {
            ASN1Primitive obj = ins.readObject();
            return obj;
        } finally {
            ins.close();
        }
    }
  
  String getHashAsBase64( byte[] content ) throws GeneralSecurityException{
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(content); 
    byte[] digest = md.digest();
    return( Base64.toBase64String(digest));
  }
  
  /**
   * build a sample csr 
   * 
   * @param subject the subject of the certificate
   * @param pubKey the public ky to be signed
   * @param priKey the corresponding private key
   * @param password the PKCS#10 password
   * @return PEM encoded CSR
   * @throws IOException problem creating the csr
   * @throws GeneralSecurityException some security problem occurred
   */
    public static String getCsrAsPEM(X500Principal subject,
            PublicKey pubKey, 
            PrivateKey priKey, 
            char[] password)
            throws GeneralSecurityException, IOException {
      
        PKCS10CertificationRequest req = getCsr(subject,
                pubKey, 
                priKey, 
                password);
        
      return pkcs10RequestToPem(req);

    }

    /**
     *
     * @param subject the subject of the certificate as X500Principal
     * @param pubKey the public ky to be signed
     * @param priKey the corresponding private key
     * @param password the PKCS#10 password
     * @return CSR content as PKCS#10 object
     * @throws IOException problem creating the csr
     * @throws GeneralSecurityException some security problem occurred
     */
    public static PKCS10CertificationRequest getCsr(X500Principal subject,
            PublicKey pubKey, 
            PrivateKey priKey, 
            char[] password)
            throws GeneralSecurityException, IOException {
    	
    	return getCsr(subject,pubKey, priKey, password,null, null);
    }

    /**
     *
     * @param subject the subject of the certificate as X500Principal
     * @param pubKey the public ky to be signed
     * @param priKey the corresponding private key
     * @param password the PKCS#10 password
     * @param extensions a list of attributes
     * @return CSR content as PKCS#10 object
     * @throws IOException problem creating the csr
     * @throws GeneralSecurityException some security problem occurred
     */
    public static PKCS10CertificationRequest getCsr(X500Principal subject,
            PublicKey pubKey, 
            PrivateKey priKey, 
            char[] password,
            List<Map<String, Object>> extensions)
            throws GeneralSecurityException, IOException {
    	
    	return getCsr(subject,pubKey, priKey, password,extensions, null);
    }

    /**
     *
     * @param subject the subject of the certificate as X500Principal
     * @param pubKey the public ky to be signed
     * @param priKey the corresponding private key
     * @param password the PKCS#10 password
     * @param extensions a list of attributes
     * @param sanArray list of SANs
     * @return CSR content as PKCS#10 object
     * @throws IOException problem creating the csr
     * @throws GeneralSecurityException some security problem occurred
     */
    public static PKCS10CertificationRequest getCsr(X500Principal subject,
                PublicKey pubKey, 
                PrivateKey priKey, 
                char[] password,
                List<Map<String, Object>> extensions,
                GeneralName[] sanArray)
                throws GeneralSecurityException, IOException {
      
        SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(pubKey
                .getEncoded());

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA1withRSA");
        ContentSigner signer;
        try {
            signer = signerBuilder.build(priKey);
        } catch (OperatorCreationException e) {
            IOException ioe = new IOException();
            ioe.initCause(e);
            throw ioe;
        }

        PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(
                X500Name.getInstance(subject.getEncoded()), pkInfo);
        if( password != null) {
	        DERPrintableString cpSet = new DERPrintableString(new String(password));
	        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, cpSet);
        }
        
        if ((extensions != null) && (extensions.size() > 0)) {
            Extensions parsedExts = ExtensionsUtils.getExtensionsObjFromMap(extensions);
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, parsedExts);
        }

        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();

        if( sanArray != null) {
            GeneralNames subjectAltNames = new GeneralNames(sanArray);
            extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
            LOGGER.debug("added #" + sanArray.length + " sans");

            for(GeneralName gn: sanArray) {
                LOGGER.debug("san :" + gn);
            }
        }
        
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());

        return builder.build(signer);

    }

  /**
   * Build a descriptive text for certificate
   *
   * @param x509Certificate X509Certificate
   * @return String describing the certificate
   */
  public String getDescription(X509Certificate x509Certificate) {

    String subject = "noSubject";
    String issuer = "noIssuer";
    String serial = "noSerial";

    if (x509Certificate != null) {
      if (x509Certificate.getSubjectDN() != null) {
        subject = x509Certificate.getSubjectDN().getName();
      }
      if (x509Certificate.getIssuerDN() != null) {
        issuer = x509Certificate.getIssuerDN().getName();
      }
      serial = String.valueOf(x509Certificate.getSerialNumber());
    }

    if (subject == null || subject.length() == 0) {
      return issuer + " / #" + serial;
    }
    return subject + " (#" + serial + ")";
  }

    /**
     *
     * @param revocationReasonStr a string describing the revocation reason
     * @return CRL reason object
     */
  public CRLReason crlReasonFromString(final String revocationReasonStr) {

    int revReason = CRLReason.unspecified;
    try {
      revReason = Integer.parseInt(revocationReasonStr);
    } catch (NumberFormatException nfe) {

//		LOGGER.info("crlReasonFromString for '" + revocationReasonStr + "'", nfe);

      if ("keyCompromise".equalsIgnoreCase(revocationReasonStr)) {
        revReason = CRLReason.keyCompromise;
      } else if ("cACompromise".equalsIgnoreCase(revocationReasonStr)) {
        revReason = CRLReason.cACompromise;
      } else if ("affiliationChanged".equalsIgnoreCase(revocationReasonStr)) {
        revReason = CRLReason.affiliationChanged;
      } else if ("superseded".equalsIgnoreCase(revocationReasonStr)) {
        revReason = CRLReason.superseded;
      } else if ("cessationOfOperation".equalsIgnoreCase(revocationReasonStr)) {
        revReason = CRLReason.cessationOfOperation;
      } else if ("privilegeWithdrawn".equalsIgnoreCase(revocationReasonStr)) {
        revReason = CRLReason.privilegeWithdrawn;
      } else if ("aACompromise".equalsIgnoreCase(revocationReasonStr)) {
          revReason = CRLReason.aACompromise;
      } else if ("certificateHold".equalsIgnoreCase(revocationReasonStr)) {
          revReason = CRLReason.certificateHold;
      } else if ("removeFromCRL".equalsIgnoreCase(revocationReasonStr)) {
          revReason = CRLReason.removeFromCRL;
      } else if ("unspecified".equalsIgnoreCase(revocationReasonStr)) {
        revReason = CRLReason.unspecified;
      }
    }
    return CRLReason.lookup(revReason);
  }

    /**
     *
     * @param crlReason a CRL reason object to be stringified
     * @return a string describing the revocation reason
     */
  public String crlReasonAsString(final CRLReason crlReason) {

    switch( crlReason.getValue().intValue() ){
    case CRLReason.keyCompromise:
      return "keyCompromise";
    case CRLReason.cACompromise:
      return "cACompromise";
    case CRLReason.affiliationChanged:
      return "affiliationChanged";
    case CRLReason.superseded:
      return "superseded";
    case CRLReason.cessationOfOperation:
      return "cessationOfOperation";
    case CRLReason.privilegeWithdrawn:
      return "privilegeWithdrawn";
    case CRLReason.aACompromise:
        return "aACompromise";
    case CRLReason.certificateHold:
        return "certificateHold";
    case CRLReason.removeFromCRL:
        return "removeFromCRL";
    default:
      return "unspecified";
    }      
  }

    /**
     *
     * @param in an input string
     * @param maxLength the maximum length
     * @return the truncated string
     */
    public static String limitLength( String in , int maxLength ){
      int len = in.length() > maxLength ? maxLength : in.length();
      return in.substring( 0, len );
    }


    /**
     * find or calculate an SKI from a certificate
     *  
     * @param x509Cert the x509 certificate
     * 
     * @return the subject key identifier object
     * 
     * @throws NoSuchAlgorithmException X509 extension problem
     */
    	public static SubjectKeyIdentifier[] getSKI( final X509Certificate x509Cert ) throws NoSuchAlgorithmException
        {

    		SubjectKeyIdentifier skiArr[] = new SubjectKeyIdentifier[2];
    		
    		JcaX509ExtensionUtils util = new JcaX509ExtensionUtils();
    		
    		SubjectKeyIdentifier skiCalculated = util.createSubjectKeyIdentifier(x509Cert.getPublicKey());
    		skiArr[0] = skiCalculated;
    		
    		SubjectKeyIdentifier skiTruncated = util.createTruncatedSubjectKeyIdentifier(x509Cert.getPublicKey());
    		skiArr[1] = skiTruncated;
    		
    		return( skiArr );
    	}

    	public String getSHA256DigestAsString(byte[] bInArr) throws NoSuchAlgorithmException {
    		return Base64.toBase64String(getSHA256Digest(bInArr));
    	}
    	
   		public byte[] getSHA256Digest(byte[] bInArr) throws NoSuchAlgorithmException {

			MessageDigest md = MessageDigest.getInstance("SHA-256");
	
			md.update(bInArr);
			return md.digest();
		}
    	
    /* ######################################################################
     * 
     * CMP Section
     * 
     * ######################################################################
     */
    public ProtectedPKIMessageBuilder getPKIBuilder(final X500Name recipientDN, final X500Name senderDN) {
        
        long millis = System.currentTimeMillis();
        
        // senderNonce
        byte[] senderNonce = ("nonce" + millis).getBytes();
        // TransactionId
        byte[] transactionId = ("transactionId" + millis).getBytes();
        byte[] keyId = ("keyId" + millis).getBytes();
        
        return getPKIBuilder(recipientDN, senderDN,
        		senderNonce,
        		null,
        		transactionId,
        		keyId,
        		null);
    }

    /**
     * 
     * @param recipientDN the recipient of the message
     * @param senderDN the sender of the message
     * @param pkiHeader the message header
     * @return a builder for a ProtectedPKIMessage
     */
    public ProtectedPKIMessageBuilder getPKIResponseBuilder(final X500Name recipientDN, final X500Name senderDN, final PKIHeader pkiHeader) {

        byte[] senderNonce = null;
        if( pkiHeader.getSenderNonce() != null){
        	senderNonce = pkiHeader.getSenderNonce().getOctets();
        }
        
        byte[] transactionId = null;
        if( pkiHeader.getTransactionID() != null){
        	transactionId = pkiHeader.getTransactionID().getOctets();
        }
        
        byte[] keyId = null;
        if( pkiHeader.getRecipKID() != null){
        	keyId = pkiHeader.getRecipKID().getOctets();
        }

        return getPKIBuilder(recipientDN, senderDN,
        		null,
        		senderNonce,
        		transactionId,
        		null,
        		keyId);
    }

    public ProtectedPKIMessageBuilder getPKIBuilder(final X500Name recipientDN, final X500Name senderDN,
    		final byte[] senderNonce,
    		final byte[] recipNonce,
    		final byte[] transactionId,
    		final byte[] keyId,
    		final byte[] recipKeyId) {
        
        // Message protection and final message
        GeneralName sender = new GeneralName(senderDN);
        GeneralName recipient = new GeneralName(recipientDN);
        ProtectedPKIMessageBuilder pbuilder = new ProtectedPKIMessageBuilder(sender, recipient);
        pbuilder.setMessageTime(new Date());
      
        if( senderNonce != null){
	        // senderNonce
	        pbuilder.setSenderNonce(senderNonce);
        }
      
        if( recipNonce != null){
	        // recipNonce
	        pbuilder.setRecipNonce(recipNonce);
        }
      
        if( transactionId != null){
        	pbuilder.setTransactionID(transactionId);
        }   
        
        // Key Id used (required) by the recipient to do a lot of stuff
        if( keyId != null){
        	pbuilder.setSenderKID(keyId);
        }
        
        if( recipKeyId != null){
        	pbuilder.setRecipKID(recipKeyId);
        }
        
        return pbuilder;
      }


    /**
     * 
     * @param hmacSecret the secret the HMAC
     * @return an initialized MAC calculator
     * @throws CRMFException a message related exception
     */
	public MacCalculator getMacCalculator(final String hmacSecret)
            throws CRMFException {
		
		JcePKMACValuesCalculator jcePkmacCalc = new JcePKMACValuesCalculator();
		final AlgorithmIdentifier digAlg = new AlgorithmIdentifier(
				new ASN1ObjectIdentifier("1.3.14.3.2.26")); // SHA1
		final AlgorithmIdentifier macAlg = new AlgorithmIdentifier(
				new ASN1ObjectIdentifier("1.2.840.113549.2.7")); // HMAC/SHA1
		jcePkmacCalc.setup(digAlg, macAlg);
		PKMACBuilder macbuilder = new PKMACBuilder(jcePkmacCalc);
		MacCalculator macCalculator = macbuilder .build(hmacSecret.toCharArray());
		return macCalculator;
	}

	/**
	 * @deprecated
	 * 
	 */
	public X509Certificate buildSelfsignedCertificate(
			final X500Name issuer, final KeyPair keyPair)
			throws NoSuchAlgorithmException, IOException, CertificateException {

		X509Certificate certificate = issueCertificate(issuer, keyPair, issuer, keyPair.getPublic().getEncoded(), Calendar.YEAR, 1, PKILevel.ROOT);

		return certificate;
	}

	/**
	 * 
	 * @param alias
	 * @param hmacSecret
	 * @param requestBytes
	 * @param issuingCertificate
	 * @param issuer
	 * @param keyPair
	 * @return
	 * @throws IOException
	 * @throws GeneralSecurityException
	 * @throws CRMFException
	 * @throws CMPException
	 */
	public byte[] handleCMPRequest(final String alias, String hmacSecret,
			final byte[] requestBytes,
			java.security.cert.Certificate issuingCertificate, X500Name issuer,
			KeyPair keyPair) throws IOException, GeneralSecurityException,
			CRMFException, CMPException {

		if( LOGGER.isDebugEnabled()){
			LOGGER.debug("incoming CMP request: " + Base64.toBase64String(requestBytes));
		}
		
		final ASN1Primitive derObject = getDERObject(requestBytes);
		final PKIMessage pkiMessage = PKIMessage.getInstance(derObject);
		if (pkiMessage == null) {
			throw new GeneralSecurityException( "No CMP message could be parsed from received Der object.");
		}

		printPKIMessageInfo(pkiMessage);

		final PKIBody requestBody = pkiMessage.getBody();

		int type = requestBody.getType();

		switch (type) {
		case PKIBody.TYPE_INIT_REQ:
		case PKIBody.TYPE_CERT_REQ:
			LOGGER.debug("incoming CMP certificate request");

			CertReqMessages certReqMsgs = (CertReqMessages) requestBody.getContent();
			CertReqMsg[] certReqMsgArr = certReqMsgs.toCertReqMsgArray();

			if ("fail".equals(alias)) {
				return buildErrorResponse(pkiMessage, hmacSecret, issuer);
			} else {
				return buildCertificateResponse(pkiMessage, certReqMsgArr,
						hmacSecret, issuingCertificate, issuer, keyPair);
			}
			
		case PKIBody.TYPE_REVOCATION_REQ:
			LOGGER.debug("incoming CMP revocation request");
			return buildRevocationResponse(pkiMessage, hmacSecret, issuer);
			
		case PKIBody.TYPE_GEN_MSG:
			LOGGER.debug("incoming CMP general message");
			return this.buildErrorResponse(pkiMessage, hmacSecret, issuer);
			
		default:
			throw new CMPException("unexpected request type '"
					+ requestBody.getType() + "'");
		}

	}

  /**
   * 
   * @param requestBytes
   * @return
   * @throws IOException
   * @throws CRMFException
   * @throws CMPException
   * @throws GeneralSecurityException
   */
  PKIBody readPKIBodyFromRequest( final byte[] requestBytes ) 
    throws IOException, CRMFException,
    CMPException, GeneralSecurityException {

  final ASN1Primitive derObject = getDERObject(requestBytes);
  
  final PKIMessage pkiMessage = PKIMessage.getInstance(derObject);
  if ( pkiMessage == null ) {
    throw new GeneralSecurityException("No CMP message could be parsed from received Der object.");
  }

  printPKIMessageInfo(pkiMessage);
  
  final PKIBody body = pkiMessage.getBody();
		  
  return body;
}


/**
 * @param pkiMessage
 * @return
 */
private void printPKIMessageInfo(final PKIMessage pkiMessage) {
	
	final PKIHeader header = pkiMessage.getHeader();
	  final PKIBody body = pkiMessage.getBody();
	  
	  int tagno = body.getType();
	  if( LOGGER.isDebugEnabled()){
		  LOGGER.debug("Received CMP message with pvno=" + header.getPvno()
		      + ", sender=" + header.getSender().toString() + ", recipient="
		      + header.getRecipient().toString());
		  LOGGER.debug("Body is of type: " + tagno);
		  LOGGER.debug("Transaction id: " + header.getTransactionID());
	  }
}
  
  /**
   * 
   * @param requestBytes
   * @return
   * @throws IOException
   * @throws CRMFException
   * @throws CMPException
   * @throws GeneralSecurityException
   */
	PKIMessage readPKIMessageFromRequest(final byte[] requestBytes)
			throws IOException, CRMFException, CMPException,
			GeneralSecurityException {

		final ASN1Primitive derObject = getDERObject(requestBytes);

		final PKIMessage pkiMessage = PKIMessage.getInstance(derObject);
		if (pkiMessage == null) {
			throw new GeneralSecurityException(
					"No CMP message could be parsed from received Der object.");
		}

		return pkiMessage;
	}
  
    /**
     * 
     * @param pkiMessageIn 
     * @param certReqMsgArr
     * @param hmacSecret
     * @param issuingCertificate
     * @param issuer
     * @param keyPair
     * @return
     * @throws IOException
     * @throws CRMFException
     * @throws CMPException
     * @throws GeneralSecurityException
     */
  public byte[] buildCertificateResponse( 
      PKIMessage pkiMessageIn, CertReqMsg[] certReqMsgArr,
      final String hmacSecret, java.security.cert.Certificate issuingCertificate, X500Name issuer, KeyPair keyPair) 
          throws IOException, CRMFException,
          CMPException, GeneralSecurityException {

    CMPCertificate[] caPubs = new CMPCertificate[1];    
    caPubs[0] = new CMPCertificate( org.bouncycastle.asn1.x509.Certificate.getInstance(getDERObject(issuingCertificate.getEncoded())));
    

    CertReqMsg certReqMsg = certReqMsgArr[0];
    CertRequest certReq = certReqMsg.getCertReq();
    CertTemplate certTemplate = certReq.getCertTemplate();
    
    
    AttributeTypeAndValue[] atavArr = certReqMsg.getRegInfo();
    
    if (atavArr != null) {
      for (AttributeTypeAndValue atav : atavArr) {
    	  if( LOGGER.isDebugEnabled()){
    		  	LOGGER.debug("certificate request AttributeTypeAndValue: "
    		  		+ atav.getType().getId() + " -> "
    		  		+ atav.toASN1Primitive());
    	  }
      }
    }

//    X500Name subject = new X500Name("CN=test cert " + System.currentTimeMillis() + ", O=trustable Ltd, C=DE");

    X509Certificate issuedCertificate = issueCertificate(issuer, keyPair, 
    		certTemplate.getSubject(), 
    		certTemplate.getPublicKey().getEncoded(),
    		Calendar.YEAR, 1);

    
    CMPCertificate cmpCert = new CMPCertificate( org.bouncycastle.asn1.x509.Certificate.getInstance(getDERObject(issuedCertificate.getEncoded())));

    CertifiedKeyPair certifiedKeyPair = new CertifiedKeyPair(new CertOrEncCert(cmpCert));
    ASN1OctetString rspInfo = null;
    
    CertResponse certResponse = new CertResponse( certReq.getCertReqId(),
        new PKIStatusInfo(PKIStatus.granted),
                 certifiedKeyPair,
                 rspInfo);
    
    CertResponse[] certResponseArr = new CertResponse[1];
    certResponseArr[0] = certResponse;
    
    CertRepMessage certRepMessage = new CertRepMessage(caPubs, certResponseArr);
    
    // get a builder
	ProtectedPKIMessageBuilder pbuilder = getPKIResponseBuilder(issuer, certTemplate.getSubject(), pkiMessageIn.getHeader());

    // create the body
    PKIBody pkiBody = new PKIBody(PKIBody.TYPE_CERT_REP, certRepMessage); // certificate response
    pbuilder.setBody(pkiBody);
    
    X509CertificateHolder certHolder = new X509CertificateHolder(caPubs[0].getX509v3PKCert());
    pbuilder.addCMPCertificate(certHolder);
    
    // get the MacCalculator
    MacCalculator macCalculator = getMacCalculator(hmacSecret);
    ProtectedPKIMessage message = pbuilder.build(macCalculator);
    
    org.bouncycastle.asn1.cmp.PKIMessage pkiMessage = message.toASN1Structure();

    return pkiMessage.getEncoded();
  }


    /**
     *
     * @param issuer
     * @param issuerKeyPair
     * @param subject
     * @param issuerPKByteArr
     * @param validityPeriodType
     * @param validityPeriod
     * @return
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     */
	public X509Certificate issueCertificate(X500Name issuer, KeyPair issuerKeyPair, final X500Name subject, final byte[] issuerPKByteArr, int validityPeriodType, int validityPeriod)
			throws NoSuchAlgorithmException, CertificateException, IOException {
		
		return issueCertificate(issuer, issuerKeyPair, subject, SubjectPublicKeyInfo.getInstance(issuerPKByteArr), validityPeriodType, validityPeriod, PKILevel.END_ENTITY);

	}

	/**
	 * 
	 * @param issuer
	 * @param issuerKeyPair
	 * @param subject
	 * @param issuerPKByteArr
	 * @param validityPeriodType
	 * @param validityPeriod
	 * @param pkiLevel
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 */
	public X509Certificate issueCertificate(X500Name issuer, KeyPair issuerKeyPair, final X500Name subject, final byte[] issuerPKByteArr, int validityPeriodType, int validityPeriod, PKILevel pkiLevel)
			throws NoSuchAlgorithmException, CertificateException, IOException {
		
		return issueCertificate(issuer, issuerKeyPair, subject, SubjectPublicKeyInfo.getInstance(issuerPKByteArr), validityPeriodType, validityPeriod, pkiLevel);

	}


	/**
	 * 
	 * @param issuer
	 * @param issuerKeyPair
	 * @param subject
	 * @param spkInfo
	 * @param validityPeriodType
	 * @param validityPeriod
	 * @return
     * @throws NoSuchAlgorithmException X509 extension problem
	 * @throws CertificateException
	 * @throws IOException
	 */
	public X509Certificate issueCertificate(X500Name issuer, KeyPair issuerKeyPair, final X500Name subject, SubjectPublicKeyInfo spkInfo, int validityPeriodType, int validityPeriod, PKILevel pkiLevel)
			throws NoSuchAlgorithmException, CertificateException, IOException {
		
		Date dateOfIssuing = new Date();              // time from which certificate is valid
		Calendar expiryCal = Calendar.getInstance();
		expiryCal.add(validityPeriodType, validityPeriod);             // time after which certificate is not valid
		Date dateOfExpiry = expiryCal.getTime();
		

		BigInteger serialNumber = BigInteger.valueOf( new Random().nextLong()).abs();
		
		LOGGER.debug("certification request for subject '" + subject + "'");
		
		X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuer, 
		    serialNumber, 
		    dateOfIssuing, dateOfExpiry,
		    subject,
		    spkInfo);

		// Key usage for end entity
		KeyUsage usage = new KeyUsage( KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment );

		if( PKILevel.ROOT.equals(pkiLevel) || PKILevel.INTERMEDIATE.equals(pkiLevel)) {
			certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
			usage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign);
		}
		
		certBuilder.addExtension(Extension.keyUsage, true, usage);

		certBuilder.addExtension(Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(issuerKeyPair.getPublic()) );
		byte[] certBytes = certBuilder.build(new JCESigner(issuerKeyPair.getPrivate())).getEncoded();
		
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		X509Certificate issuedCertificate = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));
		return issuedCertificate;
	}
  
  /**
   * 
   * @param pkiMessageIn
   * @param hmacSecret
   * @param issuer
   * @return
   * @throws IOException
   * @throws CRMFException
   * @throws CMPException
   * @throws GeneralSecurityException
   */
  public byte[] buildRevocationResponse(final PKIMessage pkiMessageIn,
			final String hmacSecret, X500Name issuer) throws IOException,
			CRMFException, CMPException, GeneralSecurityException {

//		pkiMessageIn.getHeader().
		PKIStatusInfo status = new PKIStatusInfo( PKIStatus.revocationNotification);
		RevRepContent revRepContent = new RevRepContentBuilder().add(status).build();

		X500Name subject = new X500Name("CN=test cert "
				+ System.currentTimeMillis() + ", O=trustable Ltd, C=DE");

		// get a builder
		ProtectedPKIMessageBuilder pbuilder = getPKIResponseBuilder(issuer, subject, pkiMessageIn.getHeader());

		// create the body
		PKIBody pkiBody = new PKIBody(PKIBody.TYPE_REVOCATION_REP, revRepContent);
		pbuilder.setBody(pkiBody);

		// get the MacCalculator
		MacCalculator macCalculator = getMacCalculator(hmacSecret);
		ProtectedPKIMessage message = pbuilder.build(macCalculator);

		org.bouncycastle.asn1.cmp.PKIMessage pkiMessage = message.toASN1Structure();

		return pkiMessage.getEncoded();
	}

  /**
   * 
   * @param pkiMessageIn
   * @param hmacSecret
   * @param issuer
   * @return
   * @throws IOException
   * @throws CRMFException
   * @throws CMPException
   * @throws GeneralSecurityException
   */
  public byte[] buildErrorResponse(final PKIMessage pkiMessageIn,
			final String hmacSecret, X500Name issuer) throws IOException,
			CRMFException, CMPException, GeneralSecurityException {

		PKIStatusInfo status = new PKIStatusInfo( PKIStatus.rejection);
		ErrorMsgContent emc = new ErrorMsgContent(status);
		
		X500Name subject = new X500Name("CN=test cert "
				+ System.currentTimeMillis() + ", O=trustable Ltd, C=DE");

		// get a builder
		ProtectedPKIMessageBuilder pbuilder = getPKIResponseBuilder(issuer, subject, pkiMessageIn.getHeader());

		// create the body
		PKIBody pkiBody = new PKIBody(PKIBody.TYPE_ERROR, emc);
		pbuilder.setBody(pkiBody);

		// get the MacCalculator
		MacCalculator macCalculator = getMacCalculator(hmacSecret);
		ProtectedPKIMessage message = pbuilder.build(macCalculator);

		org.bouncycastle.asn1.cmp.PKIMessage pkiMessage = message.toASN1Structure();

		return pkiMessage.getEncoded();
	}


    /**
     *
     * @param responseBytes
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public RevRepContent readRevResponse( final byte[] responseBytes )
	          throws IOException, GeneralSecurityException {
	  
        final ASN1Primitive derObject = getDERObject(responseBytes);
	  
	    final PKIMessage pkiMessage = PKIMessage.getInstance(derObject);
	    if ( pkiMessage == null ) {
	        throw new GeneralSecurityException("No CMP message could be parsed from received Der object.");
	    }
	  
	    final PKIHeader header = pkiMessage.getHeader();
	    
	    if( header.getRecipNonce() == null){
	    	LOGGER.debug( "no recip nonce");
	    }else{
			if( LOGGER.isDebugEnabled()){
				LOGGER.debug( "recip nonce : " + Base64.toBase64String( header.getRecipNonce().getOctets() ));
			}
	    }
	    
	    if( header.getSenderNonce() == null){
	    	LOGGER.debug( "no sender nonce");
	    }else{
			if( LOGGER.isDebugEnabled()){
				LOGGER.debug( "sender nonce : " + Base64.toBase64String( header.getSenderNonce().getOctets() ));
			}
	    }
	    
	    final PKIBody body = pkiMessage.getBody();
	  
	    int tagno = body.getType();
	  
		if( LOGGER.isDebugEnabled()){
		    LOGGER.debug("Received CMP message with pvno=" + header.getPvno()
		        + ", sender=" + header.getSender().toString() + ", recipient="
		        + header.getRecipient().toString());
		    LOGGER.debug("Body is of type: " + tagno);
		    LOGGER.debug("Transaction id: " + header.getTransactionID());
		}	  
	    if (tagno == PKIBody.TYPE_ERROR) {
	      handleCMPError(body);      

	    } else if (tagno == PKIBody.TYPE_REVOCATION_REP) {
	      
	      LOGGER.debug("Rev response received");        
	  
	      if( body.getContent() != null ){
	        RevRepContent revRepContent = RevRepContent.getInstance(body.getContent());
	        
	        CertId[] certIdArr = revRepContent.getRevCerts();
	        if( certIdArr != null ){
		        for( CertId certId: certIdArr){
		            LOGGER.info("revoked certId : " + certId.getIssuer()+ " / " + certId.getSerialNumber().getValue());         
		        }
	        }else{
	            LOGGER.debug("no certId ");         
	        }
	        return revRepContent;
	        
	      }
	      
	    } else {
	      throw new GeneralSecurityException("unexpected PKI body type :" + tagno);      
	    }
	  
	    return null;
	  }

    /**
     *
     * @param responseBytes
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
	  public GenMsgContent readGenMsgResponse( final byte[] responseBytes )
	          throws IOException,
              GeneralSecurityException {
	  
	      final ASN1Primitive derObject = getDERObject(responseBytes);
	  
	    final PKIMessage pkiMessage = PKIMessage.getInstance(derObject);
	    if ( pkiMessage == null ) {
	      throw new GeneralSecurityException("No CMP message could be parsed from received Der object.");
	    }
	  
	    final PKIHeader header = pkiMessage.getHeader();
	    
		if( LOGGER.isDebugEnabled()){
		    if( header.getRecipNonce() == null){
		    	LOGGER.debug( "no recip nonce");
		    }else{
		        LOGGER.debug( "recip nonce : " + Base64.toBase64String( header.getRecipNonce().getOctets() ));
		    }
		    
		    if( header.getSenderNonce() == null){
		    	LOGGER.debug( "no sender nonce");
		    }else{
		        LOGGER.debug( "sender nonce : " + Base64.toBase64String( header.getSenderNonce().getOctets() ));
		    }
		}
		
	    final PKIBody body = pkiMessage.getBody();
	  
	    int tagno = body.getType();
	  
		if( LOGGER.isDebugEnabled()){
		    LOGGER.debug("Received CMP message with pvno=" + header.getPvno()
		        + ", sender=" + header.getSender().toString() + ", recipient="
		        + header.getRecipient().toString());
		    LOGGER.debug("Body is of type: " + tagno);
		    LOGGER.debug("Transaction id: " + header.getTransactionID());
		}
		
	    if (tagno == PKIBody.TYPE_ERROR) {
	      handleCMPError(body);      

	    } else if (tagno == PKIBody.TYPE_GEN_REP ) {
	      
	      LOGGER.debug("Rev response received");        
	  
	      if( body.getContent() != null ){
	    	  GenMsgContent genMsgContent = GenMsgContent.getInstance(body.getContent());
	        
	    	  InfoTypeAndValue[] infoTypeAndValueArr = genMsgContent.toInfoTypeAndValueArray();
	        if( infoTypeAndValueArr != null ){
		        for( InfoTypeAndValue infoTypeAndValue: infoTypeAndValueArr){
		            LOGGER.info("infoTypeAndValue : " + infoTypeAndValue.getInfoType()+ " / " + infoTypeAndValue.getInfoValue());         
		        }
	        }else{
	            LOGGER.debug("no certId ");         
	        }
	        return genMsgContent;
	        
	      }
	      
	    } else {
	      throw new GeneralSecurityException("unexpected PKI body type :" + tagno);      
	    }
	  
	    return null;
	  }


  /**
   * @param body
   * @throws GeneralSecurityException
   */
  private void handleCMPError(final PKIBody body)
      throws UnrecoverableEntryException {
	  
    ErrorMsgContent errMsgContent = ErrorMsgContent.getInstance(body.getContent());
    PKIFreeText pkiText = errMsgContent.getPKIStatusInfo().getStatusString();
    String statusText = "";
    for(int i = 0; i < pkiText.size(); i++) {
        try{
        	statusText += " " + pkiText.getStringAt(i).getString();
        }catch( NullPointerException npe ){ //NOSONAR
        	// just ignore
        }
    }
    
    String errMsg = "errMsg : #" + errMsgContent.getErrorCode() + " "
        + errMsgContent.getErrorDetails() + " / " + statusText;
    
    LOGGER.info(errMsg);
/*
    try{
	    if( errMsgContent != null && errMsgContent.getPKIStatusInfo() != null ){
		    PKIFreeText freeText = errMsgContent.getPKIStatusInfo().getStatusString();
		    for (int i = 0; i < freeText.size(); i++) {
		      LOGGER.info("#" + i + ": " + freeText.getStringAt(i));
		    }
	    }
    }catch( NullPointerException npe ){ //NOSONAR
    	// just ignore
    }
*/
    
    throw new UnrecoverableEntryException(errMsg);
  }

    /**
     *
     * @param hmacSecret
     * @return
     * @throws GeneralSecurityException
     * @throws CRMFException
     * @throws CMPException
     */
  public PKIMessage buildGeneralMessageRequest(final String hmacSecret)
          throws GeneralSecurityException, CRMFException, CMPException {
  
	  InfoTypeAndValue[] itvArr = new InfoTypeAndValue[0];

	    GenMsgContent genMsgContent = new GenMsgContent(itvArr);
	  
	    X500Name subjectDN = X500Name.getInstance(new X500Name("CN=User1").toASN1Primitive());
	    X500Name issuerDN = X500Name.getInstance(new X500Name("CN=AdminCA1").toASN1Primitive());
	    
	    // get a builder
	    ProtectedPKIMessageBuilder pbuilder = getPKIBuilder(issuerDN, subjectDN);
	  
	    // create the body
	    PKIBody pkiBody = new PKIBody(PKIBody.TYPE_GEN_MSG, genMsgContent); // general message request
	    pbuilder.setBody(pkiBody);
	    
	    // get the MacCalculator
	    MacCalculator macCalculator = getMacCalculator(hmacSecret);
	    ProtectedPKIMessage message = pbuilder.build(macCalculator);
	    
	    org.bouncycastle.asn1.cmp.PKIMessage pkiMessage = message.toASN1Structure();
	  
	    LOGGER.debug( "sender nonce : " + Base64.toBase64String( pkiMessage.getHeader().getSenderNonce().getOctets() ));
	    
	    return pkiMessage;
	    
  }

    /**
     *
     * @param certReqId
     * @param subjectDN
     * @param certExtList
     * @param keyInfo
     * @param hmacSecret
     * @return
     * @throws GeneralSecurityException
     */
  public PKIMessage buildCertRequest( long certReqId, final X500Name subjectDN, final Collection<Extension> certExtList, final SubjectPublicKeyInfo keyInfo, final String hmacSecret)
          throws GeneralSecurityException {
  
    CertificateRequestMessageBuilder msgbuilder = new CertificateRequestMessageBuilder(BigInteger.valueOf(certReqId));
    
    X500Name issuerDN = X500Name.getInstance(new X500Name("CN=AdminCA1").toASN1Primitive());
    
    msgbuilder.setSubject(subjectDN);
  
    // propose an issuer ???
    msgbuilder.setIssuer(issuerDN);
    
    
    try{
      for( Extension ext : certExtList ){
        
          LOGGER.debug("Csr Extension : " + ext.getExtnId().getId() + " -> " + ext.getExtnValue() );
          
          boolean critical = false;
        msgbuilder.addExtension(ext.getExtnId(), critical, ext.getParsedValue() );
      }
      
      msgbuilder.setPublicKey(keyInfo);
      GeneralName sender = new GeneralName(subjectDN);
      msgbuilder.setAuthInfoSender(sender);
  
      // RAVerified POP
      msgbuilder.setProofOfPossessionRaVerified();
    
      CertificateRequestMessage msg = msgbuilder.build();
      
      LOGGER.debug("CertTemplate : " + msg.getCertTemplate() );
      
      ProtectedPKIMessageBuilder pbuilder = getPKIBuilder(issuerDN, subjectDN);
      
      CertReqMessages msgs = new CertReqMessages(msg.toASN1Structure());
      PKIBody pkibody = new PKIBody(PKIBody.TYPE_INIT_REQ, msgs);
      pbuilder.setBody(pkibody);
      
      MacCalculator macCalculator = getMacCalculator(hmacSecret);
      ProtectedPKIMessage message = pbuilder.build(macCalculator);
  
      org.bouncycastle.asn1.cmp.PKIMessage pkiMessage = message.toASN1Structure();
  
      return pkiMessage;
      
    }  catch(CRMFException | CMPException | IOException crmfe){
        LOGGER.warn("Exception occured processing extensions", crmfe );
      throw new GeneralSecurityException(crmfe.getMessage());
    }
  }

  public byte[] buildRevocationRequest( long certRevId, final X500Name issuerDN, final X500Name subjectDN, final BigInteger serial, final CRLReason crlReason, final String hmacSecret) 
          throws IOException, CRMFException,
          CMPException, GeneralSecurityException {
  
  
    // Cert template too tell which cert we want to revoke
    CertTemplateBuilder myCertTemplate = new CertTemplateBuilder();
    myCertTemplate.setIssuer(issuerDN);
    myCertTemplate.setSerialNumber(new ASN1Integer(serial));
  
    // Extension telling revocation reason
    ExtensionsGenerator extgen = new ExtensionsGenerator();
    extgen.addExtension(Extension.reasonCode, false, crlReason);        
  
    Extensions exts = extgen.generate();
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(myCertTemplate.build());
    v.add(exts);
    ASN1Sequence seq = new DERSequence(v);
    RevDetails myRevDetails = RevDetails.getInstance(seq);
    RevReqContent myRevReqContent = new RevReqContent(myRevDetails);

  
    // get a builder
    ProtectedPKIMessageBuilder pbuilder = getPKIBuilder(issuerDN, subjectDN);
  
    // create the body
    PKIBody pkiBody = new PKIBody(PKIBody.TYPE_REVOCATION_REQ, myRevReqContent); // revocation request
    pbuilder.setBody(pkiBody);
    
    // get the MacCalculator
    MacCalculator macCalculator = getMacCalculator(hmacSecret);
    ProtectedPKIMessage message = pbuilder.build(macCalculator);
    
    org.bouncycastle.asn1.cmp.PKIMessage pkiMessage = message.toASN1Structure();

    if( LOGGER.isDebugEnabled() ){
    	LOGGER.debug( "sender nonce : " + Base64.toBase64String( pkiMessage.getHeader().getSenderNonce().getOctets() ));
    }
    
    return pkiMessage.getEncoded();
  }


  
  
}
