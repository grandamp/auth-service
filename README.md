# Auth Service (Spring Boot Auth Server Experiment)

- Spring Authorization Server Quickstart Docs:

https://docs.spring.io/spring-authorization-server/docs/current/reference/html/getting-started.html

- application.yml

```TEXT
server:
  port: 9000

logging:
  level:
    org.springframework.security: trace

spring:
  security:
    oauth2:
      authorizationserver:
        client:
          oidc-client:
            registration:
              client-id: "4492269c-1a8d-45fd-b90e-1e6289cdf506"
              client-secret: "{noop}4492269c-1a8d-45fd-b90e-1e6289cdf506"
              client-authentication-methods:
                - "client_secret_basic"
              authorization-grant-types:
                - "authorization_code"
                - "refresh_token"
              redirect-uris:
                - "https://oauthdebugger.com/debug"
              post-logout-redirect-uris:
                - "http://127.0.0.1:8080/"
              scopes:
                - "openid"
                - "profile"
            require-authorization-consent: false
```

- metadata

```TEXT
{
	"issuer": "http://localhost:9000",
	"authorization_endpoint": "http://localhost:9000/oauth2/authorize",
	"device_authorization_endpoint": "http://localhost:9000/oauth2/device_authorization",
	"token_endpoint": "http://localhost:9000/oauth2/token",
	"token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt"],
	"jwks_uri": "http://localhost:9000/oauth2/jwks",
	"userinfo_endpoint": "http://localhost:9000/userinfo",
	"end_session_endpoint": "http://localhost:9000/connect/logout",
	"response_types_supported": ["code"],
	"grant_types_supported": ["authorization_code", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"],
	"revocation_endpoint": "http://localhost:9000/oauth2/revoke",
	"revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt"],
	"introspection_endpoint": "http://localhost:9000/oauth2/introspect",
	"introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt"],
	"subject_types_supported": ["public"],
	"id_token_signing_alg_values_supported": ["RS256"],
	"scopes_supported": ["openid"]
}
```

- jwks

```TEXT
{
	"keys": [{
		"kty": "RSA",
		"e": "AQAB",
		"kid": "6b9c632e-7a3b-428a-80fa-25e7617ec06b",
		"n": "q5b1ENtGul7iFWOpMXYgPLp8C0BPPAiTWwRotNfKLQ8xt4FALHvh4L6tIejF38qYID8SxxA0SOnK0nZRcqTrRLc-N2RSz8chJ20A9L48u8R42YhS-DEwuOOgRR1YWemj5a_Uc-22x1TYHqUxRsGhoIqcAB_ouLo3jBv1rHIT0wXjXlinpyV1D9YDSCwTQGX0Dha7plmIxB8E7aT_sdpMzyh4nZalw2xpRqhUv-2YkPgWOqfDMaJgMP0bQHPHsreIUXma1A2Un531Jv6LZ6MqXqyz_jKtiGJNZ3Ubxn5mxwQJKg8ssldrOSy1dkh3OsDorhcx8sfJJo8irpg1AM3zyw"
	}]
}
```

- auth endpoint request example (not PKCE)

```TEXT
http://localhost:9000/oauth2/authorize
?client_id=4492269c-1a8d-45fd-b90e-1e6289cdf506
&redirect_uri=https://oauthdebugger.com/debug
&scope=openid profile
&response_type=code
&response_mode=form_post
&state=45caon237kp
&nonce=39u55fkyfbg
```

- token request example (not PKCE)

```TEXT
curl -vX POST \
    -u "4492269c-1a8d-45fd-b90e-1e6289cdf506:4492269c-1a8d-45fd-b90e-1e6289cdf506" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code&code=NQwm4ZFxxf6RbpQDiZ_nv4k1Yb17q6F63y7IRZH1m7_rNZqx-C_yp8ROmxYhNoOhO2yJZQB0mqjYNvk6it1RTiftEsNbuMZAdQaW0nQ6VA_h7o-bNygA25CT4jZWhiWW&redirect_uri=https%3A%2F%2Foauthdebugger.com%2Fdebug" \
    http://localhost:9000/oauth2/token \
    | jq
```

- Example token response

```TEXT
{
  "access_token": "eyJraWQiOiI2YjljNjMyZS03YTNiLTQyOGEtODBmYS0yNWU3NjE3ZWMwNmIiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoiNDQ5MjI2OWMtMWE4ZC00NWZkLWI5MGUtMWU2Mjg5Y2RmNTA2IiwibmJmIjoxNjkwMTQ4NzU4LCJzY29wZSI6WyJvcGVuaWQiLCJwcm9maWxlIl0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMCIsImV4cCI6MTY5MDE0OTA1OCwiaWF0IjoxNjkwMTQ4NzU4fQ.SHUue-SheRDd5jHEFI8eIe_jzAsKfvrgdaGyfSWXrytJ93ImFYq29FLY7ktfGXAGL_bgwE_H3K7Kh7pw7SFEP_fNIxHhoMpDvyHtBeQHF5gyxNdahJOpBXrVDiswzxi7YiYWuiapmhBHVVy2yRWvKKlLArTfsic5yLJIEwYpxQed76x0C97AOvfOmhK3FbK4mIFwkWiKcl1-aE1y2xRnxHkleBCB9iyI7tVPpvruzcuX3sPnHPEVurC5UzHUP43Y0kkwc2mvE5Gy9IgnqPMH7a-0QGmN63eWPVpUMWlm360xVxCsVG6l9qmvkplPa94RxvibjbUAd-H48lyhQeArHg",
  "refresh_token": "aHd9Eh4tEmmWFl7KiFUBffunayriwHEm_R6btUICWnemSWuVbGg5Ogw3wjhZXpVh7Mera_PeZe201Jyc7cAmd2HVGfWYA_0uzuARpDr0B6dvRDy-Plis3Tgbt9T6cqOV",
  "scope": "openid profile",
  "id_token": "eyJraWQiOiI2YjljNjMyZS03YTNiLTQyOGEtODBmYS0yNWU3NjE3ZWMwNmIiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoiNDQ5MjI2OWMtMWE4ZC00NWZkLWI5MGUtMWU2Mjg5Y2RmNTA2IiwiYXpwIjoiNDQ5MjI2OWMtMWE4ZC00NWZkLWI5MGUtMWU2Mjg5Y2RmNTA2IiwiYXV0aF90aW1lIjoxNjkwMTQ4NDk3LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJleHAiOjE2OTAxNTA1NTgsImlhdCI6MTY5MDE0ODc1OCwibm9uY2UiOiIxMWM3aXM4ZmtxNSIsInNpZCI6IjYyMWV1TDZMVEJOdEFGQmZ0bmlDaUVyTjRya2phUDdYdG5GOFFIZVY0aHcifQ.flrn5xJ-0nTWlrqCwWLkGGn_HEtwx0m6DOkVU57V-3bLnDVJ8gV18-niktV3naWvo9b8-1MpIgDeFnw3azfXxt60BmzGBEtjat2hkQJ-p7AnFGBmmFpI6j7Uapdr4rc4y19Vu-s_bUGJtTIINRC3CqLS2vtjUh2-J5pj3dgB42dbhFVk4KgKuO06e4--1ttmby2AuoePyTo6RVaBaozz_JeRwkid2Q_-AcHJeyr-P0u1HwddapPzYgO1Ho3ckJn9ms5t-NLTbDdRopc2fNpkWN-R2WfUP9kFlLthcO_p-3wb-PxlJFiitgK91j3_aNaEPIm44RFjJ0fQnFc33HTC3A",
  "token_type": "Bearer",
  "expires_in": 299
}
```

- Access Token

```TEXT
{
  "kid": "6b9c632e-7a3b-428a-80fa-25e7617ec06b",
  "alg": "RS256"
}
{
  "sub": "user",
  "aud": "4492269c-1a8d-45fd-b90e-1e6289cdf506",
  "nbf": 1690148758,
  "scope": [
    "openid",
    "profile"
  ],
  "iss": "http://localhost:9000",
  "exp": 1690149058,
  "iat": 1690148758
}
```

- ID Token

```TEXT
{
  "kid": "6b9c632e-7a3b-428a-80fa-25e7617ec06b",
  "alg": "RS256"
}
{
  "sub": "user",
  "aud": "4492269c-1a8d-45fd-b90e-1e6289cdf506",
  "azp": "4492269c-1a8d-45fd-b90e-1e6289cdf506",
  "auth_time": 1690148497,
  "iss": "http://localhost:9000",
  "exp": 1690150558,
  "iat": 1690148758,
  "nonce": "11c7is8fkq5",
  "sid": "621euL6LTBNtAFBftniCiErN4rkjaP7XtnF8QHeV4hw"
}
```

## How to Contribute

The source repository exists [here](https://github.com/grandamp/auth-service).

### Public domain

This project is in the worldwide [public domain](LICENSE.md).

> This project is in the public domain within the United States, and copyright and related rights in the work worldwide are waived through the [CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).
>
> All contributions to this project will be released under the CC0 dedication. By submitting a pull request, you are agreeing to comply with this waiver of copyright interest.
