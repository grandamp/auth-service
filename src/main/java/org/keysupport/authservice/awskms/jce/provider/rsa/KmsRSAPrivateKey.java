package org.keysupport.authservice.awskms.jce.provider.rsa;

import org.keysupport.authservice.awskms.jce.provider.KmsKey;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;

public class KmsRSAPrivateKey implements KmsKey, RSAPrivateKey {

    private static final long serialVersionUID = 1L;
	private String id;
    private String algorithm = "RSA";
    private String format = "X.509";

    public KmsRSAPrivateKey(String id) {
    	this.id = id;
    }
    
    @Override
    public BigInteger getPrivateExponent() {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] getEncoded() {
        throw new UnsupportedOperationException();
    }

    @Override
    public BigInteger getModulus() {
        throw new UnsupportedOperationException();
    }

    @Override
	public String getId() {
		return this.id;
	}

    @Override
	public String getAlgorithm() {
		return this.algorithm;
	}

    @Override
	public String getFormat() {
		return this.format;
	}

}
