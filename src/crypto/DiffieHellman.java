package src.crypto;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHGenParameterSpec;
import javax.crypto.spec.DHParameterSpec;

public class DiffieHellman {
    
    public static KeyPair crearLlavesDH() throws Exception{
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(1024);
        AlgorithmParameters params = paramGen.generateParameters();
        DHParameterSpec dh = params.getParameterSpec(DHParameterSpec.class);
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("DH");
        keygen.initialize(dh);
        return keygen.generateKeyPair();
    }

    public static KeyAgreement acuerdoLlaves(PrivateKey llavePrivada) throws Exception{
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(llavePrivada);
        return ka;
    }

    public static PublicKey reconstruirLlavePublica(byte[] data) throws Exception{
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509 = new X509EncodedKeySpec(data);
        return keyFactory.generatePublic(x509);
    }

    public static byte[] crearSecretoCompartido(KeyAgreement acuerdo, PublicKey llavePublica) throws Exception{
        acuerdo.doPhase(llavePublica, true);
        return acuerdo.generateSecret();
    }
}
