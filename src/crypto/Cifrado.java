package src.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Cifrado {
    
    public static byte[] cifrarAES(byte[] data, SecretKey key, IvParameterSpec iv) throws Exception{
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(data);
    }

    public static byte[] descifrarAES(byte[] data, SecretKey key, IvParameterSpec iv)throws Exception{
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(data);
    }

    public static byte[] cifrarRSA(byte[] data, PublicKey key) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] descifrarRSA(byte[] data, PrivateKey key) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] firmarDatos(byte[] data, PrivateKey key) throws Exception{
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key);
        signature.update(data);
        return signature.sign();
    }

    public static boolean verificarFirma(byte[] data, byte[] firma, PublicKey key) throws Exception{
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(key);
        signature.update(data);
        return signature.verify(firma);
    }

    public static byte[] HMAC(byte[] data, SecretKey key) throws Exception{
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        return mac.doFinal(data);
    }

    public static IvParameterSpec generarIV(){
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static SecretKey crearLlaveAES(byte[] keyData){
        return new SecretKeySpec(keyData, 0, 32, "AES");
    }

    public static SecretKey crearLlaveHMAC(byte[] keyData){
        return new SecretKeySpec(keyData, 0, 32, "HmacSHA256");
    }
}
