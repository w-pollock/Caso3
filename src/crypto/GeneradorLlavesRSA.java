package src.crypto;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class GeneradorLlavesRSA {

    public static void main(String[] args) throws Exception{
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);
        KeyPair par = keygen.generateKeyPair();

        PrivateKey privatekey = par.getPrivate();
        PublicKey publicKey = par.getPublic();

        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("keys/private.key"))){
            oos.writeObject(privatekey);
        }

        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("keys/public.key"))){
            oos.writeObject(publicKey);
        }
        System.out.println("Llaves RSA generadas.");
    }
}

