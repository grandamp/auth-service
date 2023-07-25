package org.keysupport.authservice.awskms.jce.provider;

import java.security.PublicKey;

public interface KmsPublicKey extends KmsKey {

    PublicKey getPublicKey();

}
