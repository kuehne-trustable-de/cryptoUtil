package de.trustable.util;

import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public class AlgorithmInfo {

    private String sigAlgName ;
    private String hashAlgName = "undefined";
    private String paddingAlgName = "PKCS1";
    private String mfgName = "";

    static Map<String,String> hashToNormalizedName = new HashMap<>();
    static {
        hashToNormalizedName.put("sha1", "sha-1");
        hashToNormalizedName.put("sha256", "sha-256");
        hashToNormalizedName.put("sha384", "sha-384");
        hashToNormalizedName.put("sha512", "sha-512");
    }

    static Map<String,String> signingAlgoToNormalizedName = new HashMap<>();
    static {
        signingAlgoToNormalizedName.put("rsaencryption", "rsa");
        signingAlgoToNormalizedName.put("ecpublickey", "ecdsa");
    }

    public AlgorithmInfo(final String algoNames){

        // extract signature algo
        sigAlgName = OidNameMapper.lookupOid(algoNames).toLowerCase();

        if( sigAlgName.equals("ed25519")) {
            hashAlgName = "sha-256";
            sigAlgName = "ed25519";
        }else if( sigAlgName.contains("withrsa")) {
                String[] parts = sigAlgName.split("with");
                hashAlgName = parts[0];
                if (hashToNormalizedName.containsKey(hashAlgName)) {
                    hashAlgName = hashToNormalizedName.get(hashAlgName);
                }
                sigAlgName = "rsa";
        }else if (sigAlgName.contains("with")) {
            String[] parts = sigAlgName.split("with");
            if (parts.length > 1) {
                hashAlgName = parts[1];
                if(hashToNormalizedName.containsKey(hashAlgName)){
                    hashAlgName = hashToNormalizedName.get(hashAlgName);
                }
                if (parts[1].contains("and")) {
                    String[] parts2 = parts[1].split("and");
                    sigAlgName = parts2[0];
                    if (parts2.length > 1) {
                        paddingAlgName = parts2[1];
                    }
                } else {
                    sigAlgName = getSigAlgoShortName(parts[0]);
                }
            }
        }else if (sigAlgName.equals("rsapss")){
            sigAlgName = "rsa";
            hashAlgName = "";
            paddingAlgName = "pss";
        }
    }

    public AlgorithmInfo(RSASSAPSSparams rsassapssParams) {
        paddingAlgName = "pss";
        sigAlgName = "rsa";
        hashAlgName = OidNameMapper.lookupOid(rsassapssParams.getHashAlgorithm().getAlgorithm().getId());
        mfgName = OidNameMapper.lookupOid(rsassapssParams.getMaskGenAlgorithm().getAlgorithm().getId());
    }

    public String getSigAlgName() {
        return sigAlgName;
    }

    public String getSigAlgFriendlyName() {
        if( "RSAEncryption".equalsIgnoreCase(sigAlgName)){
            return "rsa";
        }
        return sigAlgName;
    }

    public String getHashAlgName() {
        return hashAlgName;
    }

    public String getPaddingAlgName() {
        return paddingAlgName;
    }

    public String getMfgName() {
        return mfgName;
    }

    static String getSigAlgoShortName(String sigAlgName) {
        if(signingAlgoToNormalizedName.containsKey(sigAlgName.toLowerCase(Locale.ROOT))) {
            return signingAlgoToNormalizedName.get(sigAlgName.toLowerCase(Locale.ROOT));
        }
        return sigAlgName;
    }

}
