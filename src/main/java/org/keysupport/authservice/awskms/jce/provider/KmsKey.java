package org.keysupport.authservice.awskms.jce.provider;

import java.security.Key;

public interface KmsKey extends Key {

    String getId();

}
