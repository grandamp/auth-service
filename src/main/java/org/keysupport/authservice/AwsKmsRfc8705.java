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
 * <pre>
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
 * </pre>
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
		for (Provider.Service service : kmsProvider.getServices()) {
			System.out.println(service.getType() + " : " + service.getAlgorithm());
		}
		return keyStore;
	}

	public static void main(String args[])
			throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {

		/**
		 * <pre>
		 * # TODO: Add mock certificate validation service call:
		 * 
		 * - https://api.keysupport.org/swagger-ui/index.html
		 * - The requesting client *should* be able to indicate their choice of a certificate validation policy, based on the validation service implementation.
		 * 
		 * ## AAL3 Policy via reference validation service
		 * 
		 * curl -X 'GET' \
		 *   'https://api.keysupport.org/vss/v2/policies/cc54e0ec-49da-333a-8150-2dd00b758b17' \
		 *   -H 'accept: application/json' \
		 *   | jq
		 * {
		 *   "validationPolicyId": "cc54e0ec-49da-333a-8150-2dd00b758b17",
		 *   "validationPolicyName": "aal3",
		 *   "validationPolicyDescription": "Derived from legacy LOA4 validation policy (2.16.840.1.101.10.2.18.2.1.4)",
		 *   "trustAnchors": [
		 *   {
		 *      "x5t#S256": "X5rswkYWshkTcmAN2A9t0yDIyloM638JyYXr8GlpNPw=",
		 *     "x509Certificate": "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",
		 *     "X509SubjectName": "CN=Federal Common Policy CA G2, OU=FPKI, O=U.S. Government, C=US"
		 *   }
		 *   ],
		 *   "userPolicySet": [
		 *     "2.16.840.1.101.3.2.1.3.7",
		 *     "2.16.840.1.101.3.2.1.3.13",
		 *     "2.16.840.1.101.3.2.1.3.16",
		 *     "2.16.840.1.101.3.2.1.3.18",
		 *     "2.16.840.1.101.3.2.1.3.41"
		 *   ],
		 *   "inhibitPolicyMapping": false,
		 *   "requireExplicitPolicy": true,
		 *   "inhibitAnyPolicy": true,
		 *   "validCacheLifetime": 900,
		 *   "inValidCacheLifetime": 900,
		 *   "cmsIntermediateHintListUri": [
		 *    "https://raw.githubusercontent.com/grandamp/rest-service/main/configuration/FCPCAG2-Intermediates/valid-cc54e0ec-49da-333a-8150-2dd00b758b17-current.p7b"
		 *   ],
		 *  "excludeIntermediates": [
		 *     {
		 *       "x509SubjectName": "CN=Federal Common Policy CA G2,OU=FPKI,O=U.S. Government,C=US",
		 *       "x509IssuerName": "CN=Federal Common Policy CA G2,OU=FPKI,O=U.S. Government,C=US",
		 *       "excludeReason": "current trust anchor",
		 *       "x5t#S256": "X5rswkYWshkTcmAN2A9t0yDIyloM638JyYXr8GlpNPw="
		 *     },
		 *     {
		 *       "x509SubjectName": "OU=GPO PCA, OU=Certification Authorities, OU=Government Printing Office, O=U.S. Government, C=US",
		 *       "x509IssuerName": "CN=Federal Bridge CA G4, OU=FPKI, O=U.S. Government, C=US",
		 *       "excludeReason": "No longer operational",
		 *       "x5t#S256": "Lyg2QXvzhTDy3d+9XqigaeYp0HQiwpJhTUJfGtY4kQ8="
		 *     },
		 *     {
		 *       "x509SubjectName": "OU=GPO SCA, OU=Certification Authorities, OU=Government Printing Office, O=U.S. Government, C=US",
		 *       "x509IssuerName": "OU=GPO PCA, OU=Certification Authorities, OU=Government Printing Office, O=U.S. Government, C=US",
		 *       "excludeReason": "No longer operational",
		 *       "x5t#S256": "HFij+jQCeQwaheOto+UKH2TurJJbBQUFBYUYLGZVm6o="
		 *     },
		 *     {
		 *       "x509SubjectName": "CN=Federal Bridge CA G4,OU=FPKI,O=U.S. Government,C=US",
		 *       "x509IssuerName": "CN=TSCP SHA256 Bridge CA,OU=CAs,O=TSCP Inc.,C=US",
		 *       "excludeReason": "wrong direction",
		 *       "x5t#S256": "OO5H7b6JjmMdoV5ecbtcTQG2M+YNqcml4gusdkopUl4="
		 *     },
		 *     {
		 *       "x509SubjectName": "CN=Federal Bridge CA G4,OU=FPKI,O=U.S. Government,C=US",
		 *       "x509IssuerName": "CN=STRAC Bridge Root Certification Authority,OU=STRAC PKI Trust Infrastructure,O=STRAC,C=US",
		 *       "excludeReason": "wrong direction",
		 *       "x5t#S256": "bDP35teW2+4ku8ODIZe6UwNDWfjQgbg05YygB8dze/E="
		 *     },
		 *     {
		 *       "x509SubjectName": "CN=Federal Common Policy CA G2,OU=FPKI,O=U.S. Government,C=US",
		 *       "x509IssuerName": "CN=Federal Bridge CA G4,OU=FPKI,O=U.S. Government,C=US",
		 *       "excludeReason": "wrong direction",
		 *       "x5t#S256": "C2WMJ3J9/WzUfjeK4jkOo3bZcI7PSwZ3X47nvFARmZE="
		 *     },
		 *     {
		 *       "x509SubjectName": "CN=Federal Bridge CA G4,OU=FPKI,O=U.S. Government,C=US",
		 *       "x509IssuerName": "CN=CertiPath Bridge CA - G3,OU=Certification Authorities,O=CertiPath,C=US",
		 *       "excludeReason": "wrong direction",
		 *       "x5t#S256": "8FU5ti7BioqYOiNPsidDa2/xDSEE11pxiOO4Fwp/grY="
		 *     }
		 *   ]
		 * }
		 * 
		 * ## Intermediates for this policy, that could help build a hint list for mTLS
		 * 
		 * curl -X 'GET' \
		 *   'https://api.keysupport.org/vss/v2/intermediates/cc54e0ec-49da-333a-8150-2dd00b758b17' \
		 *   -H 'accept: application/json' \
		 *   | jq
		 * [
		 *   {
		 *     "x509Certificate": "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"
		 *   },
		 *   {...}
		 * ]
		 * 
		 * ## Validation request using an example certificate
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
		 *         "x509Certificate": "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"
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
		 * ## Comments
		 * 
		 * Use results to build an access token, preferably opaque using `DIR` with `A256GCM`
		 * 
		 * For now, we will build a JWT, and use PS512 (with an RSA-4096 key) via AWS KMS
		 * </pre>
		 */

		KeyStore hsmKeyStore = iniKms();
		PrivateKey privateKey = (PrivateKey) hsmKeyStore.getKey(keyId, null);
		System.out.println(privateKey.getAlgorithm());

		/*
		 * Create an RSA signer and configure it to use the HSM
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
		Map<String, String> cnf = new HashMap<String, String>();
		cnf.put("x5t#S256", "wrVZ8xpFCBIWy2/tODog8fVN7R3Y6E0t6KHsaAipF2M=");

		/*
		 * We can now RSA sign JWTs
		 */
		SignedJWT jwt = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.PS512)
						.keyID(UUID.nameUUIDFromBytes(keyId.getBytes()).toString())
						.build(),
				new JWTClaimsSet.Builder()
						.subject("SERIALNUMBER=403611 + CN=Todd E. Johnson, OU=People, OU=Bureau of the Fiscal Service, OU=Department of the Treasury, O=U.S. Government, C=US")
						.issuer("https://keysupport.net/")
						.audience("https://api.keysupport.org/")
						.claim("acr", "http://idmanagement.gov/ns/assurance/ial/3/aal/3/fal/3")
						.expirationTime(calendar.getTime()).notBeforeTime(dNow).claim("cnf", cnf)
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
	 * <pre>
	 * Output (using my KMS key [arn:aws:kms:us-east-1:216896468348:key/3a60ee88-dc4e-4b93-9e77-4c13db4b6714] via AWS CLI credentials):
	 * 
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
	 * </pre>
	 */

}
