package com.liu.test;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.tomcat.util.codec.binary.Base64;
import org.junit.Test;

/**
 * @author 刘佳瑞
 *
 * @date 2018年4月11日
 */
public class RSATest {
	private String publicKey;
	private String privateKey;
	@Test
	public void testRSA() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
		KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(1024);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		RSAPublicKey public1 = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey  private1 = (RSAPrivateKey) keyPair.getPrivate();
		publicKey = Base64.encodeBase64String(public1.getEncoded());
		privateKey=Base64.encodeBase64String(private1.getEncoded());
//		System.out.println(encodeBase64String);
//		System.out.println(Base64.encodeBase64String(private1.getEncoded()));
		
		
		//加密
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.decodeBase64(publicKey));
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey generatePublic = keyFactory.generatePublic(x509KeySpec);
		String msg="my name";
		Cipher cipher=Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, generatePublic);
		byte[] doFinal = cipher.doFinal(msg.getBytes("UTF-8"));
		//加密后的内容
		String enmsg=Base64.encodeBase64String(doFinal);
		
		
		//解密
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKey));
		KeyFactory keyFactory1 = KeyFactory.getInstance("RSA");
		PrivateKey generatePrivate = keyFactory1.generatePrivate(pkcs8EncodedKeySpec);
		cipher.init(Cipher.DECRYPT_MODE, generatePrivate);
		String demsg = new String(cipher.doFinal(Base64.decodeBase64(enmsg)), "UTF-8");
		System.out.println(demsg);
	}
	
	
}
