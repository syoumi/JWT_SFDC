package com.syoumi;

import org.apache.commons.codec.binary.Base64;
import java.io.*; 
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.MessageFormat;  

public class JWTExample {
	//Consumer key of connected app
	private final static String ISSUER = "3MVG95NPsF2gwOiODUnXFyTkAI0lgDuWs4tQ07r5gzmpQ00u8WSSBGH37vV9CFfqxlQhRYFuayY18dBP6dlaO";
	private final static String USERNAME = "syoumi@neoxia.com";
	private final static String AUDIENCE = "https://login.salesforce.com";

  public static void main(String[] args) {

    String header = "{\"alg\":\"RS256\"}";
    String claimTemplate = "'{'\"iss\": \"{0}\", \"sub\": \"{1}\", \"aud\": \"{2}\", \"exp\": \"{3}\"'}'";

    try {
      StringBuffer token = new StringBuffer();

      //Encode the JWT Header and add it to our string to sign
      token.append(Base64.encodeBase64URLSafeString(header.getBytes("UTF-8")));

      //Separate with a period
      token.append(".");

      //Create the JWT Claims Object
      String[] claimArray = new String[4];
      claimArray[0] = ISSUER;
      claimArray[1] = USERNAME;
      claimArray[2] = AUDIENCE;
      claimArray[3] = Long.toString((System.currentTimeMillis()/1000) + 300);
      MessageFormat claims;
      claims = new MessageFormat(claimTemplate);
      String payload = claims.format(claimArray);

      //Add the encoded claims object
      token.append(Base64.encodeBase64URLSafeString(payload.getBytes("UTF-8")));

      //Load the private key from a local file
      File privKeyFile = new File("/Users/syoumi/Desktop/pkcs8_key");
      byte[] privKeyBytes = new byte[(int)privKeyFile.length()];
      BufferedInputStream bis = new BufferedInputStream(new FileInputStream(privKeyFile));
      bis.read(privKeyBytes);
      bis.close();
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      KeySpec ks = new PKCS8EncodedKeySpec(privKeyBytes);
      RSAPrivateKey privKey = (RSAPrivateKey) keyFactory.generatePrivate(ks);
      
      //Sign the JWT Header + "." + JWT Claims Object
      Signature signature = Signature.getInstance("SHA256withRSA");
      signature.initSign(privKey);
      signature.update(token.toString().getBytes("UTF-8"));
      String signedPayload = Base64.encodeBase64URLSafeString(signature.sign());

      //Separate with a period
      token.append(".");

      //Add the encoded signature
      token.append(signedPayload);

      System.out.println(token.toString());

    } catch (Exception e) {
        e.printStackTrace();
    }
  }
}