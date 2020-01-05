package de.trustable.util;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.owasp.esapi.reference.crypto.CryptoPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final public class JCAManager {

  private static JCAManager instance = null;
  private boolean bIsInitialized = false;

  private static final Logger LOGGER = LoggerFactory.getLogger(JCAManager.class);

  // define some 'surely present' cipher algorithm 
  public static final String DEFAULT_CIPHER_ALGO = "RSA/ECB/PKCS1Padding";
  public static final String DEFAULT_DSA_CIPHER_ALGO = "DSA/ECB/PKCS1Padding";
  
  
  static{
    JCAManager.getInstance();
    LOGGER.info( "JCAManager.getInstance() in static block" );
  }

  private JCAManager() {
  }

  /**
   * Singleton-Pattern zur Beschaffung der einzigen JCAManager-Instanz.
   *
   * @return Referenz auf den Manager
   */
  public static synchronized JCAManager getInstance(){

    if( instance == null ){
      instance = new JCAManager();
      instance.init();
    }

    return instance;
  }


  /**
   * Initialisierung der Crypto-Provider
   *
   */
  public synchronized void init(){

    if( bIsInitialized == false ){
      try {

        LOGGER.debug( "JCAManager init() : bIsInitialized = false" );

        //**********************************************************************
        // Dynamically register the BC provider.
        //**********************************************************************

        java.security.Security.addProvider( new BouncyCastleProvider() );

        // make sure everything work well with BC
        // seen deferred problems when using the crypto provider
        javax.crypto.Cipher keyCipher = javax.crypto.Cipher.getInstance( DEFAULT_CIPHER_ALGO, "BC");
        keyCipher.getAlgorithm();

        
        java.security.Provider[] providers = java.security.Security.getProviders();
        for( int i = 0; i < providers.length; i++ ){
          LOGGER.debug( "Provider " + i + " : " + providers[i].getInfo());
        }

        
        // check for unlimited strength policy :
        // if strength is limited, a relevant application will presumably not be able to work properly
        // with the rise of the openJDK the problem will disappear soon, hopefully
        try{
          
            if( CryptoPolicy.isUnlimitedStrengthCryptoAvailable() ){
              LOGGER.debug( "---- Unlimited strength crypto available ----" );
            } else {
              throw new InvalidKeyException("isUnlimitedStrengthCryptoAvailable failed");
            }
        }catch(InvalidKeyException ike){         
            String msg = "Unlimited strength cryptography NOT available !";
            LOGGER.error( msg, ike );
        }

        bIsInitialized = true;

      } catch( GeneralSecurityException ex ){
        String msg = "Problem while registration of the crypto providers";
        LOGGER.error( msg, ex );
      }
    }
  }

}
