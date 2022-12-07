package com.clover;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EncryptPan {
  static final String PAN_NUMBER = "<CC>";
  static final String taPublicKey = "rxHJAejXwDpyWwjsMzL7D1WJ/rDCaiqvsiiHZA+8nnVHVD65oWB9HH1O+ONuhhSblWBNKB0YWeA47cS0JisTizZAvXHfRNC2Sp9ZnSQvtA67GKPZsTsvOS2AlrExvYHc7ibwVVvLoz/ByJV/N7w5lBABmu57aFuIa4GEWPfb677dqnv695D1qlbJwTI+BjPk/OPHXuudYG1bi1uE7goqStX/fL6D0joXnzzMzs2ZdUKMAV/zC/kaILlAe5qA1q3aQQfd8h+gkYCskjfOrp38abNCe/DFXceq9qQ3R5YkviCxQAZJBZYzD1FjtTsOG7xIV4uoQLJjHzsJaQLkDdrwYwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAE=";

  public static void main(String[] args) {
    try {
      System.out.println(encryptPAN(PAN_NUMBER, getPublicKey(taPublicKey)));
    } catch (Exception var2) {
      var2.printStackTrace();
    }
  }

  public static PublicKey getPublicKey(String taPublicKey) throws Exception {
    byte[] key = DatatypeConverter.parseBase64Binary(taPublicKey);
    byte[] unsignedPrefix = new byte[]{0};
    BigInteger modulus1 = new BigInteger(ArrayUtils.addAll(unsignedPrefix, Arrays.copyOfRange(key, 0, 256)));
    BigInteger exponent1 = new BigInteger(Arrays.copyOfRange(key, 256, 512));
    KeyFactory factory = KeyFactory.getInstance("RSA");
    return factory.generatePublic(new RSAPublicKeySpec(modulus1, exponent1));
  }

  public static String encryptPAN(String pan, PublicKey publicKey) throws Exception {
    byte[] input = String.format("%s%s", "00000000", pan).getBytes();
    Security.addProvider(new BouncyCastleProvider());
    Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
    cipher.init(1, publicKey, new SecureRandom());
    byte[] cipherText = cipher.doFinal(input);
    return DatatypeConverter.printBase64Binary(cipherText);
  }
}
