package de.trustable.util;

import java.security.PublicKey;
import java.util.Set;

import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

public class Pkcs10RequestHolder {

    private PKCS10CertificationRequest p10Req;

    private PublicKey publicSigningKey;

    private String signingAlgorithm;

    private String signingAlgorithmName;

    private boolean isCSRValid;

    private String x509KeySpec;

    private RDN[] subjectRDNs;

    private String subject;

    private Attribute[] reqAttributes;

    private String publicKeyAlgorithm;

    private String publicKeyAlgorithmName;

    private String publicKeyAlgorithmShortName;

    private String publicKeyHash;

    private String subjectPublicKeyInfoBase64;

    private Set<AlgorithmIdentifier> digestAlgorithmIDs;

    private AlgorithmInfo algorithmInfo;


    public PKCS10CertificationRequest getP10Req() {
        return p10Req;
    }

    public void setP10Req(PKCS10CertificationRequest p10Req) {
        this.p10Req = p10Req;
    }

    public PublicKey getPublicSigningKey() {
        return publicSigningKey;
    }

    public void setPublicSigningKey(PublicKey publicSigningKey) {
        this.publicSigningKey = publicSigningKey;
    }

    public String getSigningAlgorithm() {
        return signingAlgorithm;
    }

    public void setSigningAlgorithm(String signingAlgorithm) {
        this.signingAlgorithm = signingAlgorithm;
    }

    public boolean isCSRValid() {
        return isCSRValid;
    }

    public void setCSRValid(boolean isCSRValid) {
        this.isCSRValid = isCSRValid;
    }

    public String getX509KeySpec() {
        return x509KeySpec;
    }

    public void setX509KeySpec(String x509KeySpec) {
        this.x509KeySpec = x509KeySpec;
    }

    public RDN[] getSubjectRDNs() {
        return subjectRDNs;
    }

    public void setSubjectRDNs(RDN[] subjectRDNs) {
        this.subjectRDNs = subjectRDNs;
    }

    public Attribute[] getReqAttributes() {
        return reqAttributes;
    }

    public void setReqAttributes(Attribute[] reqAttributes) {
        this.reqAttributes = reqAttributes;
    }

    public String getPublicKeyAlgorithm() {
        return publicKeyAlgorithm;
    }

    public void setPublicKeyAlgorithm(String publicKeyAlgorithm) {
        this.publicKeyAlgorithm = publicKeyAlgorithm;
    }

    public String getPublicKeyHash() {
        return publicKeyHash;
    }

    public void setPublicKeyHash(String publicKeyHash) {
        this.publicKeyHash = publicKeyHash;
    }

    public String getSubjectPublicKeyInfoBase64() {
        return subjectPublicKeyInfoBase64;
    }

    public void setSubjectPublicKeyInfoBase64(String subjectPublicKeyInfoBase64) {
        this.subjectPublicKeyInfoBase64 = subjectPublicKeyInfoBase64;
    }

    public String getPublicKeyAlgorithmName() {
        return publicKeyAlgorithmName;
    }

    public void setPublicKeyAlgorithmName(String publicKeyAlgorithmName) {
        this.publicKeyAlgorithmName = publicKeyAlgorithmName;
    }

    public String getPublicKeyAlgorithmShortName() {
        return publicKeyAlgorithmShortName;
    }

    public void setPublicKeyAlgorithmShortName(String publicKeyAlgorithmShortName) {
        this.publicKeyAlgorithmShortName = publicKeyAlgorithmShortName;
    }

    public String getSigningAlgorithmName() {
        return signingAlgorithmName;
    }

    public void setSigningAlgorithmName(String signingAlgorithmName) {
        this.signingAlgorithmName = signingAlgorithmName;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public Set<AlgorithmIdentifier> getDigestAlgorithmIDs(){
      return this.digestAlgorithmIDs;
    }

    public void setDigestAlgorithmIDs(Set<AlgorithmIdentifier> digestAlgorithmIDs) {
        this.digestAlgorithmIDs = digestAlgorithmIDs;
    }

    public AlgorithmInfo getAlgorithmInfo() {
        return algorithmInfo;
    }

    public void setAlgorithmInfo(AlgorithmInfo algorithmInfo) {
        this.algorithmInfo = algorithmInfo;
    }
}
