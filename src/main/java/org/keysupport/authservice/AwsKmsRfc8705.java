package org.keysupport.authservice;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.sql.Date;
import java.time.Instant;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
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
 * This is some prototype code to generate an OAuth token for an mTLS authenticated client.
 * 
 * - https://datatracker.ietf.org/doc/html/rfc8705
 * 
 * The key material *should* be protected in an HSM (in this case, AWS KMS)
 * 
 * KMS Endpoints and Quotas:
 * 
 * - https://docs.aws.amazon.com/general/latest/gr/kms.html#kms_region
 * 
 * Considering using:
 * 
 * - https://github.com/aws-samples/aws-kms-jce/
 * 
 * @author tejohnson@keysupport.net
 *
 */
public class AwsKmsRfc8705 {
		
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
        for (Provider.Service service: kmsProvider.getServices()) {
            System.out.println(service.getType() + " : " + service.getAlgorithm());
        }
        return keyStore;
    }

    public static void main(String args[]) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
    	
    	/*
    	 * TODO: Add mock certificate validation service call:
    	 * 
    	 * - https://api.keysupport.org/swagger-ui/index.html
    	 * 
    	 * Use results to build an access token, preferably opaque using `DIR` with `A256GCM`
    	 * 
    	 * For now, we will built a JWT and use PS384 with and RSA-1096 key via AWS KMS
    	 */
    	
    	KeyStore hsmKeyStore = iniKms();
    	PrivateKey privateKey = (PrivateKey)hsmKeyStore.getKey(keyId, null);
    	System.out.println(privateKey.getAlgorithm());
    	
    	/*
    	 *  Create an RSA signer and configure it to use the HSM
    	 */
    	RSASSASigner signer = new RSASSASigner(privateKey);
    	signer.getJCAContext().setProvider(kmsProvider);
    	
    	/*
    	 * Calculate now, and expiry time (15 min)
    	 */
		Instant vNow = Instant.now();
		long lNow = vNow.toEpochMilli();
		Date dNow = new Date(lNow);
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(dNow);
		calendar.add(Calendar.SECOND, 900);

		/*
		 * Build RFC 8705 Claim
		 */
		Map<String,String> cnf = new HashMap<String,String>();
		cnf.put("x5t#S256", "wrVZ8xpFCBIWy2/tODog8fVN7R3Y6E0t6KHsaAipF2M=");
		
    	/*
    	 *  We can now RSA sign JWTs
    	 */
    	SignedJWT jwt = new SignedJWT(
    	            new JWSHeader.Builder(JWSAlgorithm.PS512).keyID(UUID.nameUUIDFromBytes(keyId.getBytes()).toString()).build(),
    	            new JWTClaimsSet.Builder()
    	            .subject("SERIALNUMBER=403611 + CN=Todd E. Johnson, OU=People, OU=Bureau of the Fiscal Service, OU=Department of the Treasury, O=U.S. Government, C=US")
    	            .issuer("https://keysupport.net/")
    	            .audience("https://api.keysupport.org/")
    	            .claim("acr", "http://idmanagement.gov/ns/assurance/ial/3/aal/3/fal/3")
    	            .expirationTime(calendar.getTime())
    	            .notBeforeTime(dNow)
    	            .claim("cnf", cnf)
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
     * {"keys":[{"kty":"RSA","e":"AQAB","kid":"4c1d3c94-8133-34e2-a7bc-bed1a84b5273","n":"yH5vkXRTecrm8YECawgC3xcXTMABQhPS8QrKQjAo0gG6Tk94vLw7jOWdTUT5pe_yn5mYS_NwGrCPWaQHUNMJLonQapvgojY4P56irZIdzrywp1aTTfgm9EmJFgdjNPWJ7RKfuv-nGwJlFSOt4cyybvSWqx25Umyw9fT7CC54oiJISNuPDZhHFRlDPQSP9oPJfQ_L0T8nhRdy339K4NJfsdtcl4xI5HShNXF79amrCKrfX24E5kSBoG1rOoKKA24rrty5qTOQvZ9KLnT_mkF2gbb_0_WAuaEalLhFv8UKJEh0wKMHuWZYTmV71-oqy6lvTLKkxVDuRACYprpP7R3JPQMLslVozTPkfVeJ4EHToAzhK2c4LpHX0k9r-6fxQvs7F3Oaz6hbnS9FavAOvKkePYObXxEavjv5H5AKTwPG-KwlD4VHTimhPhFLuBFraObARCjNi9dqX5PfeIJVmsQ6hCni0qp2zkPfOTVErcPMYxLIa-lQM2kJTl2YiD8IhjA0moiSuzD0F6lN4WusIkyky0e8VsLEtggVyuJf2eoXdGLCUyKxAjXJsthj6to3DHYeYYvcX3VkSyEIdEf-NIbMYcUgEtygc8w6-EXiCrecLOsp4--ExZjvo-P83wcmZOCaMHttWuOwGNyULpQkG0kgJ6K6MBXmBNIFremXb9jOh0k"}]}
     * KeyStore : KMS
     * Signature : SHA384withECDSA
     * Signature : SHA256withRSA
     * Signature : SHA512withRSAandMGF1
     * Signature : SHA384withRSAandMGF1
     * Signature : SHA256withRSAandMGF1
     * Signature : SHA256withECDSA
     * Signature : SHA512withRSA
     * Signature : SHA384withRSA
     * Signature : SHA512withECDSA
     * DescribeKeyResponse(KeyMetadata=KeyMetadata(AWSAccountId=216896468348, KeyId=3a60ee88-dc4e-4b93-9e77-4c13db4b6714, Arn=arn:aws:kms:us-east-1:216896468348:key/3a60ee88-dc4e-4b93-9e77-4c13db4b6714, CreationDate=2023-07-24T17:49:28.545Z, Enabled=true, Description=, KeyUsage=SIGN_VERIFY, KeyState=Enabled, Origin=AWS_KMS, KeyManager=CUSTOMER, CustomerMasterKeySpec=RSA_4096, KeySpec=RSA_4096, SigningAlgorithms=[RSASSA_PKCS1_V1_5_SHA_256, RSASSA_PKCS1_V1_5_SHA_384, RSASSA_PKCS1_V1_5_SHA_512, RSASSA_PSS_SHA_256, RSASSA_PSS_SHA_384, RSASSA_PSS_SHA_512], MultiRegion=false))
     * RSA
     * eyJraWQiOiI0YzFkM2M5NC04MTMzLTM0ZTItYTdiYy1iZWQxYTg0YjUyNzMiLCJhbGciOiJQUzUxMiJ9.eyJzdWIiOiJTRVJJQUxOVU1CRVI9NDAzNjExICsgQ049VG9kZCBFLiBKb2huc29uLCBPVT1QZW9wbGUsIE9VPUJ1cmVhdSBvZiB0aGUgRmlzY2FsIFNlcnZpY2UsIE9VPURlcGFydG1lbnQgb2YgdGhlIFRyZWFzdXJ5LCBPPVUuUy4gR292ZXJubWVudCwgQz1VUyIsImF1ZCI6Imh0dHBzOi8vYXBpLmtleXN1cHBvcnQub3JnLyIsImFjciI6Imh0dHA6Ly9pZG1hbmFnZW1lbnQuZ292L25zL2Fzc3VyYW5jZS9pYWwvMy9hYWwvMy9mYWwvMyIsIm5iZiI6MTY5MDMzNDg5MywiaXNzIjoiaHR0cHM6Ly9rZXlzdXBwb3J0Lm5ldC8iLCJjbmYiOnsieDV0I1MyNTYiOiJ3clZaOHhwRkNCSVd5Mi90T0RvZzhmVk43UjNZNkUwdDZLSHNhQWlwRjJNPSJ9LCJleHAiOjE2OTAzMzU3OTN9.ptw0J2Bz_W5VGFLU7KtS6aPaivkOS3CgC-0DiYPYxFOUFksWsi1fEtGW9OkmShplLrWmW2SQs9wqsyyjE5tu_olVzjKlbST0yMDdJ4p-7b76gKhn4pgJbOrNpqjEDL297gvoiShIPvdm6f-hKzUQo1GRnKZHym5gvm0crLwQYR7Pg5OGXJP1Ezr7L98GDpLi75OOKAYdX_sLekLS91h9hTah0hTciasheJ8xBBewvffxXSYevL-fg6FkOWk8yhp_bs-_qNOqyvkC3yIS7xb0FUwXwPIEnlH6lWSIdN4m14f5YWXyu9tOmWOjltPmDCaqU2nfI5PDx_oMgntBtvwjjQmyichgxjYqNlryZdXndjFX-Mq0spIccg6dJ8bEFriKS_5BedMgp65nwtNctyiYZXqGYs6yxUO57dGPUTITezjy7ob7nFcI9ZAMnce3glE-R9mCj9Qlf_DBtQlGI1N1tGOKYhLJMQCI76SyMC_pu3RCoGVMNlhIW2qWPIRgFBYO-AjaDZfqkXDUfExbECAzKusym41oaAr0RRTbizjv8krJQlcAwCO2BOFWUrAotvk8aIsrx5n_jixd-hci1rarOCjn7KTqxmoC7DG9D7fH8qQktQx4y7p5PjcJiiLBLSpAOwzfk5p1g0TTc2uaJzzKDBVz4-wOmrTKGrN4IhTEwzo
     * 
     * https://jwt.io/#debugger-io?token=eyJraWQiOiI0YzFkM2M5NC04MTMzLTM0ZTItYTdiYy1iZWQxYTg0YjUyNzMiLCJhbGciOiJQUzUxMiJ9.eyJzdWIiOiJTRVJJQUxOVU1CRVI9NDAzNjExICsgQ049VG9kZCBFLiBKb2huc29uLCBPVT1QZW9wbGUsIE9VPUJ1cmVhdSBvZiB0aGUgRmlzY2FsIFNlcnZpY2UsIE9VPURlcGFydG1lbnQgb2YgdGhlIFRyZWFzdXJ5LCBPPVUuUy4gR292ZXJubWVudCwgQz1VUyIsImF1ZCI6Imh0dHBzOi8vYXBpLmtleXN1cHBvcnQub3JnLyIsImFjciI6Imh0dHA6Ly9pZG1hbmFnZW1lbnQuZ292L25zL2Fzc3VyYW5jZS9pYWwvMy9hYWwvMy9mYWwvMyIsIm5iZiI6MTY5MDMzNDg5MywiaXNzIjoiaHR0cHM6Ly9rZXlzdXBwb3J0Lm5ldC8iLCJjbmYiOnsieDV0I1MyNTYiOiJ3clZaOHhwRkNCSVd5Mi90T0RvZzhmVk43UjNZNkUwdDZLSHNhQWlwRjJNPSJ9LCJleHAiOjE2OTAzMzU3OTN9.ptw0J2Bz_W5VGFLU7KtS6aPaivkOS3CgC-0DiYPYxFOUFksWsi1fEtGW9OkmShplLrWmW2SQs9wqsyyjE5tu_olVzjKlbST0yMDdJ4p-7b76gKhn4pgJbOrNpqjEDL297gvoiShIPvdm6f-hKzUQo1GRnKZHym5gvm0crLwQYR7Pg5OGXJP1Ezr7L98GDpLi75OOKAYdX_sLekLS91h9hTah0hTciasheJ8xBBewvffxXSYevL-fg6FkOWk8yhp_bs-_qNOqyvkC3yIS7xb0FUwXwPIEnlH6lWSIdN4m14f5YWXyu9tOmWOjltPmDCaqU2nfI5PDx_oMgntBtvwjjQmyichgxjYqNlryZdXndjFX-Mq0spIccg6dJ8bEFriKS_5BedMgp65nwtNctyiYZXqGYs6yxUO57dGPUTITezjy7ob7nFcI9ZAMnce3glE-R9mCj9Qlf_DBtQlGI1N1tGOKYhLJMQCI76SyMC_pu3RCoGVMNlhIW2qWPIRgFBYO-AjaDZfqkXDUfExbECAzKusym41oaAr0RRTbizjv8krJQlcAwCO2BOFWUrAotvk8aIsrx5n_jixd-hci1rarOCjn7KTqxmoC7DG9D7fH8qQktQx4y7p5PjcJiiLBLSpAOwzfk5p1g0TTc2uaJzzKDBVz4-wOmrTKGrN4IhTEwzo&publicKey=%7B%22kty%22%3A%22RSA%22%2C%22e%22%3A%22AQAB%22%2C%22kid%22%3A%224c1d3c94-8133-34e2-a7bc-bed1a84b5273%22%2C%22n%22%3A%22yH5vkXRTecrm8YECawgC3xcXTMABQhPS8QrKQjAo0gG6Tk94vLw7jOWdTUT5pe_yn5mYS_NwGrCPWaQHUNMJLonQapvgojY4P56irZIdzrywp1aTTfgm9EmJFgdjNPWJ7RKfuv-nGwJlFSOt4cyybvSWqx25Umyw9fT7CC54oiJISNuPDZhHFRlDPQSP9oPJfQ_L0T8nhRdy339K4NJfsdtcl4xI5HShNXF79amrCKrfX24E5kSBoG1rOoKKA24rrty5qTOQvZ9KLnT_mkF2gbb_0_WAuaEalLhFv8UKJEh0wKMHuWZYTmV71-oqy6lvTLKkxVDuRACYprpP7R3JPQMLslVozTPkfVeJ4EHToAzhK2c4LpHX0k9r-6fxQvs7F3Oaz6hbnS9FavAOvKkePYObXxEavjv5H5AKTwPG-KwlD4VHTimhPhFLuBFraObARCjNi9dqX5PfeIJVmsQ6hCni0qp2zkPfOTVErcPMYxLIa-lQM2kJTl2YiD8IhjA0moiSuzD0F6lN4WusIkyky0e8VsLEtggVyuJf2eoXdGLCUyKxAjXJsthj6to3DHYeYYvcX3VkSyEIdEf-NIbMYcUgEtygc8w6-EXiCrecLOsp4--ExZjvo-P83wcmZOCaMHttWuOwGNyULpQkG0kgJ6K6MBXmBNIFremXb9jOh0k%22%7D
     */
	
}
