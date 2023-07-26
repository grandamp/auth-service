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
    	 * $ curl -X 'POST' \
    	 *   'https://api.keysupport.org/vss/v2/validate' \
    	 *   -H 'accept: application/json' \
    	 *   -H 'Content-Type: application/json' \
     	 *  -d '{
    	 *   "validationPolicyId": "cc54e0ec-49da-333a-8150-2dd00b758b17",
    	 *   "x509Certificate": "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"
    	 * }' | jq
    	 * {
    	 *   "requestId": "C8A2B1D36B6B05F83EFFFD57E9F55F2EB3FC95481A19AF62CAAA1C8A071A0E42",
    	 *   "validationPolicyId": "cc54e0ec-49da-333a-8150-2dd00b758b17",
    	 *   "x5t#S256": "wrVZ8xpFCBIWy2/tODog8fVN7R3Y6E0t6KHsaAipF2M=",
    	 *   "x509SubjectName": "SERIALNUMBER=403611 + CN=Todd E. Johnson, OU=People, OU=Bureau of the Fiscal Service, OU=Department of the Treasury, O=U.S. Government, C=US",
    	 *   "x509IssuerName": "OU=OCIO CA, OU=Certification Authorities, OU=Department of the Treasury, O=U.S. Government, C=US",
    	 *   "x509SerialNumber": "1648491554",
    	 *   "x509SubjectAltName": [
    	 *     {
    	 *       "type": "otherName#userPrincipalName",
    	 *       "value": "TODD.JOHNSON@FISCAL.TREASURY.GOV"
    	 *     },
    	 *     {
    	 *       "type": "rfc822Name",
    	 *       "value": "Todd.Johnson@fiscal.treasury.gov"
    	 *     },
    	 *     {
    	 *      "type": "otherName#pivFASC-N",
    	 *       "value": "D2024458210B6CD436010DA1685A0108439211A4820210C3EB"
    	 *     },
    	 *     {
    	 *       "type": "uniformResourceIdentifier",
     	 *      "value": "urn:uuid:1a39f91d-a83c-4f4e-aeb3-2c7aefda8dab"
    	 *     }
    	 *   ],
    	 *   "isCA": false,
    	 *   "validationTime": "2023-07-26T02:44:27.749+0000",
    	 *   "nextUpdate": "2023-07-26T02:59:27.749+0000",
     	 *  "validationResult": {
     	 *    "result": "SUCCESS",
     	 *    "x509CertificatePath": [
      	 *     {
    	 *         "x509Certificate": "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"
       	 *    },
      	 *     {
    	 *         "x509Certificate": "MIIHWzCCBUOgAwIBAgIEXMsx/jANBgkqhkiG9w0BAQsFADCBjjELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEjMCEGA1UECxMaRGVwYXJ0bWVudCBvZiB0aGUgVHJlYXN1cnkxIjAgBgNVBAsTGUNlcnRpZmljYXRpb24gQXV0aG9yaXRpZXMxHDAaBgNVBAsTE1VTIFRyZWFzdXJ5IFJvb3QgQ0EwHhcNMTkwNjIyMTMxNDAyWhcNMjkwNjIyMTM0NDAyWjCBgjELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEjMCEGA1UECxMaRGVwYXJ0bWVudCBvZiB0aGUgVHJlYXN1cnkxIjAgBgNVBAsTGUNlcnRpZmljYXRpb24gQXV0aG9yaXRpZXMxEDAOBgNVBAsTB09DSU8gQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCo+v8tgC+bhpvjfEr7pu4Qjh9YgGedGnrpkbIogo3w+nwv5LsamJiUIrBYtYwmGlRw7AD0gogQ9ScUWeeYbeIomxVT0rsUAbY+sJsqJwYzio/EYHZjozQXRqg8oxMF/8QvzQvFQRavZV7jGR4wCB3FZ8iQHBQeYM6CpvI/lTD1fReRnLmhTcL2lxNjaMwt+YMQvFQv50okqjfQkTuTRLF9j0Gw8vkb/F+m/3+1UZiuNFwlSRzYfzrkLIh+B9JVLV1TS4lFW+GVg5ezHErRTWcr70m2Hbn7Q5I1hheKfx4t5Yt1smHJ6rpC6gF6gdWvCefVu8qdi4fRT447PHBJkk1lAgMBAAGjggLJMIICxTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zCB6wYDVR0gBIHjMIHgMAwGCmCGSAFlAwIBBQIwDAYKYIZIAWUDAgEFAzAMBgpghkgBZQMCAQUEMAwGCmCGSAFlAwIBBQcwDAYKYIZIAWUDAgEFCjAMBgpghkgBZQMCAQULMAwGCmCGSAFlAwIBBQwwDAYKYIZIAWUDAgEDBjAMBgpghkgBZQMCAQMHMAwGCmCGSAFlAwIBAwgwDAYKYIZIAWUDAgEDDTAMBgpghkgBZQMCAQMRMAwGCmCGSAFlAwIBAycwDAYKYIZIAWUDAgEDJDAMBgpghkgBZQMCAQMoMAwGCmCGSAFlAwIBAykwQAYIKwYBBQUHAQEENDAyMDAGCCsGAQUFBzAChiRodHRwOi8vcGtpLnRyZWFzdXJ5Lmdvdi90b2NhX2FpYS5wN2MwQAYIKwYBBQUHAQsENDAyMDAGCCsGAQUFBzAFhiRodHRwOi8vcGtpLnRyZWFzdXJ5Lmdvdi90b2NhX3NpYS5wN2Mwge8GA1UdHwSB5zCB5DA2oDSgMoYwaHR0cDovL3BraS50cmVhc3VyeS5nb3YvVVNfVHJlYXN1cnlfUm9vdF9DQTEuY3JsMIGpoIGmoIGjpIGgMIGdMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MSMwIQYDVQQLExpEZXBhcnRtZW50IG9mIHRoZSBUcmVhc3VyeTEiMCAGA1UECxMZQ2VydGlmaWNhdGlvbiBBdXRob3JpdGllczEcMBoGA1UECxMTVVMgVHJlYXN1cnkgUm9vdCBDQTENMAsGA1UEAxMEQ1JMMTAfBgNVHSMEGDAWgBQXS7gmuml6rRJQV0Uxnle7dKXaLzAdBgNVHQ4EFgQUzZocYHLB676uxausSZDrTY7x364wDQYJKoZIhvcNAQELBQADggIBAG9wmogOowxlcDKIU02g41uYNPHj6cbzVYrZRPsBqGHAFLgaUujYqhTrnt8WAPSTiYMqK5dElH5yTwsxZa4t1JZTqoftu/B72Jl5FK06iiHkTAL3UUvXoJMMK+WXaIKIDHuX+9Eghh/HMh85pBjbA1oEo29x7bvaLzKwBtSxBlTTnCymEJ+KgoUJkwTId51FMnKWVjf9TFxQSlqNQWIUVfZd4/Fps5lLuD18qUH10LbisS8mg5ZHimXD1TbPLc+Mwx+uoYDqf+2UYmDra7cTYApYLbNotGTHOKLtQX/2bF2YS0ovyr0M4JPk8BrKSkOdx/8BpxrohhedVk7sWPN/3h545MZKN9XGgA1/DRMK7vmDvDv29BatIUjaiRcCs/1ioWaswnrrTPGsZaeswOmJQgDvzcypSQyGWCG0KsHWiJHefhpABYHFx50Sx7MrJE8KC+/hwn3FyC7A/m4JyZNRKwk7oiBuD2rM9hVGkQtb0Ufbk+IP5QYgIRMcLi0kopVJlyrdAs3EZov5b8dB/abZMyb5/gdRurZAPDZz/OyZv6y+FM78BtVNfVtwxvZsRrCIksIxAbcEGGsr6pUXjPmHUhMg6SaH+i8dwor77muqucT3IxJ9vO3hsqnvTsoHlL4gx35FxjHSzWT/dRGzBsg0rwOn74bVoheP2PAarCvmEWXL"
      	 *     },
      	 *     {
      	 *       "x509Certificate": "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"
     	 *      }
     	 *    ],
    	 *     "policyTree": {
      	 *     "depth": 0,
    	 *       "critical": false,
    	 *       "expectedPolicies": [
    	 *         "2.5.29.32.0"
     	 *      ],
     	 *      "validPolicy": "2.5.29.32.0",
     	 *      "children": [
      	 *       {
      	 *         "depth": 1,
       	 *        "critical": false,
      	 *         "expectedPolicies": [
     	 *            "2.16.840.1.101.3.2.1.3.13"
     	 *          ],
       	 *        "validPolicy": "2.16.840.1.101.3.2.1.3.13",
      	 *         "children": [
      	 *           {
      	 *             "depth": 2,
    	 *               "critical": false,
    	 *               "expectedPolicies": [
     	 *                "2.16.840.1.101.3.2.1.3.13"
     	 *              ],
    	 *               "validPolicy": "2.16.840.1.101.3.2.1.3.13",
    	 *               "children": [
    	 *                 {
     	 *                  "depth": 3,
     	 *                  "critical": false,
     	 *                  "expectedPolicies": [
    	 *                     "2.16.840.1.101.3.2.1.3.13"
     	 *                  ],
     	 *                  "validPolicy": "2.16.840.1.101.3.2.1.3.13"
     	 *                }
     	 *              ]
      	 *           }
    	 *           ]
    	 *         }
     	 *      ]
    	 *     }
    	 *   }
    	 * }
    	 * 
    	 * Use results to build an access token, preferably opaque using `DIR` with `A256GCM`
    	 * 
    	 * For now, we will built a JWT, and use PS512 (with an RSA-4096 key) via AWS KMS
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
