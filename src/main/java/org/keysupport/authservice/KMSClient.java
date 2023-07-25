package org.keysupport.authservice;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.sql.Date;
import java.time.Instant;
import java.util.Calendar;
import java.util.UUID;

import org.keysupport.authservice.awskms.jce.provider.KmsProvider;
import org.keysupport.authservice.awskms.jce.provider.rsa.KmsRSAKeyFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import software.amazon.awssdk.services.kms.KmsClient;

/**
 * 
 * KMS Endpoints and Quotas:
 * 
 * - https://docs.aws.amazon.com/general/latest/gr/kms.html#kms_region
 * 
 * Considering using:
 * 
 * - https://github.com/aws-samples/aws-kms-jce/
 * 
 * @author tejohnson
 *
 */
public class KMSClient {
		
    protected static KmsClient kmsClient;
    protected static KmsProvider kmsProvider;
	public static final String keyArn = "arn:aws:kms:us-east-1:216896468348:key/3a60ee88-dc4e-4b93-9e77-4c13db4b6714";
	public static final String keyId = "RSA4096";


    public static KeyStore iniKms() {
        kmsClient = KmsClient.builder().build();
        kmsProvider = new KmsProvider(kmsClient);
        Security.insertProviderAt(kmsProvider, Security.getProviders().length);
        KeyPair keyPair = KmsRSAKeyFactory.getKeyPair(kmsClient, keyArn);
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAKey rsaKey = new RSAKey.Builder(publicKey)
				.keyID(UUID.nameUUIDFromBytes(keyId.getBytes()).toString())
				.build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		System.out.println(jwkSet.toString());
        
        KeyStore keyStore = null;
		try {
			keyStore = KeyStore.getInstance("KMS");
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
        try {
			keyStore.load(null, null);
		} catch (NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
		}
        return keyStore;
    }

    public static void main(String args[]) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
    	KeyStore hsmKeyStore = iniKms();
    	PrivateKey privateKey = (PrivateKey)hsmKeyStore.getKey(keyId, null);
    	System.out.println(privateKey.getAlgorithm());
    	// Create an RSA signer and configure it to use the HSM
    	RSASSASigner signer = new RSASSASigner(privateKey);
    	signer.getJCAContext().setProvider(kmsProvider);
    	
    	//Calculate now, and expiry time (15 min)
		Instant vNow = Instant.now();
		long lNow = vNow.toEpochMilli();
		Date dNow = new Date(lNow);
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(dNow);
		calendar.add(Calendar.SECOND, 900);

    	// We can now RSA sign JWTs
    	SignedJWT jwt = new SignedJWT(
    	            new JWSHeader.Builder(JWSAlgorithm.RS384).keyID(UUID.nameUUIDFromBytes(keyId.getBytes()).toString()).build(),
    	            new JWTClaimsSet.Builder()
    	            .subject(UUID.nameUUIDFromBytes("SERIALNUMBER=403611 + CN=Todd E. Johnson, OU=People, OU=Bureau of the Fiscal Service, OU=Department of the Treasury, O=U.S. Government, C=US".getBytes()).toString())
    	            .issuer("https://keysupport.net/")
    	            .audience("https://api.keysupport.org/")
    	            .claim("acr", "http://idmanagement.gov/ns/assurance/ial/3/aal/3")
    	            .issueTime(dNow)
    	            .notBeforeTime(dNow)
    	            .expirationTime(calendar.getTime())
    	            .claim("x5t#S256", "wrVZ8xpFCBIWy2/tODog8fVN7R3Y6E0t6KHsaAipF2M=")
    	            .build());

    	try {
			jwt.sign(signer);
		} catch (JOSEException e) {
			e.printStackTrace();
		}
    	String jwtString = jwt.serialize();
    	System.out.println(jwtString);
    }
    
    /**
     * https://jwt.io/#debugger-io?token=eyJraWQiOiI0YzFkM2M5NC04MTMzLTM0ZTItYTdiYy1iZWQxYTg0YjUyNzMiLCJhbGciOiJSUzM4NCJ9.eyJzdWIiOiIwZmFlMmZmNS1kMzhhLTNkZmEtYTI0Yy1lYjEyODc0YWU2MGIiLCJhdWQiOiJodHRwczovL2FwaS5rZXlzdXBwb3J0Lm9yZy8iLCJhY3IiOiJodHRwOi8vaWRtYW5hZ2VtZW50Lmdvdi9ucy9hc3N1cmFuY2UvaWFsLzMvYWFsLzMiLCJ4NXQjUzI1NiI6IndyVlo4eHBGQ0JJV3kyL3RPRG9nOGZWTjdSM1k2RTB0NktIc2FBaXBGMk09IiwibmJmIjoxNjkwMjUyMTY2LCJpc3MiOiJodHRwczovL2tleXN1cHBvcnQubmV0LyIsImV4cCI6MTY5MDI1MzA2NiwiaWF0IjoxNjkwMjUyMTY2fQ.EszuCiya85OpmWwbzCu67zftMy5K7Qaye38GonwnQd3Cr3G-omgi1GWuDEDAGb-ACpoZcPFFXOfSw2j1iBlw4JkBCza0Qdlp7g19PW3E_kuO3EH5ZckpYCH8KLCH2bo06fqjhEalRocoAlJsC_Qc3e79LWo4pHUNIiCXvQXxCCm6_rM_FL5Hqrp7WWlKrrSYRexTUC_1gKJ5MmFd6WqwExZRQbosAWlutcqtA2yXuV17HQc_Y6H3-VoTltod5r-5SQlCuoUO_CDujwtRoufRk0QmG8ftRwkkgzu7c_0J6ruS2xBnXOB9T3fXkq7y7SHpFRWCk-eO3ITZmCQNDJl8b0yRpuWb4MwZ-EUfGBgI3qSDB4xvCrnil8dW9YDRtdcLyGXsa5U4G_Af-BGwm2j019UVGzZki3-ynTenWl4y1mctf1bk0eDv5VwrdmzBmH4YvnuJJweCGfeCQY93Go3E5hv55iVwVx1wIeU2JmrhzgQ26ww6WZATIs3_JnXG4zoZfS0kj3EhYUwfS1_bK8Beti398U95EbMTbQF3mD07jDk-_2ZU3JnRVbpUvQ_rO8UO0Z1VKYpBw2IYpW7D1Ha2FTtHkf2jrlcDaTAWduparMlpZoAkWtTLVgN0b8bv-RtUaiSSoiM8zwuYL0O-ftyKgbWr1OMeIoByb0jAWlmExUs&publicKey=%7B%22kty%22%3A%22RSA%22%2C%22e%22%3A%22AQAB%22%2C%22kid%22%3A%224c1d3c94-8133-34e2-a7bc-bed1a84b5273%22%2C%22n%22%3A%22yH5vkXRTecrm8YECawgC3xcXTMABQhPS8QrKQjAo0gG6Tk94vLw7jOWdTUT5pe_yn5mYS_NwGrCPWaQHUNMJLonQapvgojY4P56irZIdzrywp1aTTfgm9EmJFgdjNPWJ7RKfuv-nGwJlFSOt4cyybvSWqx25Umyw9fT7CC54oiJISNuPDZhHFRlDPQSP9oPJfQ_L0T8nhRdy339K4NJfsdtcl4xI5HShNXF79amrCKrfX24E5kSBoG1rOoKKA24rrty5qTOQvZ9KLnT_mkF2gbb_0_WAuaEalLhFv8UKJEh0wKMHuWZYTmV71-oqy6lvTLKkxVDuRACYprpP7R3JPQMLslVozTPkfVeJ4EHToAzhK2c4LpHX0k9r-6fxQvs7F3Oaz6hbnS9FavAOvKkePYObXxEavjv5H5AKTwPG-KwlD4VHTimhPhFLuBFraObARCjNi9dqX5PfeIJVmsQ6hCni0qp2zkPfOTVErcPMYxLIa-lQM2kJTl2YiD8IhjA0moiSuzD0F6lN4WusIkyky0e8VsLEtggVyuJf2eoXdGLCUyKxAjXJsthj6to3DHYeYYvcX3VkSyEIdEf-NIbMYcUgEtygc8w6-EXiCrecLOsp4--ExZjvo-P83wcmZOCaMHttWuOwGNyULpQkG0kgJ6K6MBXmBNIFremXb9jOh0k%22%7D
     */
	
}
