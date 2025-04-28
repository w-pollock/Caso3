package src.servidor;

import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import src.crypto.Cifrado;
import src.crypto.DiffieHellman;
import src.crypto.MedidorTiempo;

import java.io.*;
import java.net.Socket;
import java.security.*;

import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import javax.crypto.KeyAgreement;
import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.MessageDigest;

public class DelegadoServidor implements Runnable {

    private Socket cliente;
    private PrivateKey llavePrivada;
    private PublicKey llavePublicaServidor; // NUEVO
    private ObjectInputStream entrada;
    private ObjectOutputStream salida;
    private MedidorTiempo medidorFirmar = new MedidorTiempo();
    private MedidorTiempo medidorCifrar = new MedidorTiempo();
    private MedidorTiempo medidorVerificar = new MedidorTiempo();

    public DelegadoServidor(Socket cliente, PrivateKey llavePrivada) throws Exception {
        this.cliente = cliente;
        this.llavePrivada = llavePrivada;
        cargarLlavePublica(); // NUEVO
    }

    private void cargarLlavePublica() throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream("keys/public.key"))) {
            this.llavePublicaServidor = (PublicKey) ois.readObject();
        }
    }

    @Override
    public void run() {
        try {
            entrada = new ObjectInputStream(cliente.getInputStream());
            salida = new ObjectOutputStream(cliente.getOutputStream());

            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(1024);
            AlgorithmParameters params = paramGen.generateParameters();
            DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            keyGen.initialize(dhSpec);
            KeyPair parLlaves = keyGen.generateKeyPair();

            KeyAgreement acuerdo = KeyAgreement.getInstance("DH");
            acuerdo.init(parLlaves.getPrivate());

            salida.writeObject(dhSpec.getP());
            salida.writeObject(dhSpec.getG());
            salida.flush();

            salida.writeObject(parLlaves.getPublic().getEncoded());
            salida.flush();

            byte[] llavePublicaClienteBytes = (byte[]) entrada.readObject();
            PublicKey llavePublicaCliente = DiffieHellman.reconstruirLlavePublica(llavePublicaClienteBytes);

            byte[] secretoCompartido = DiffieHellman.crearSecretoCompartido(acuerdo, llavePublicaCliente);

            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] hash = sha512.digest(secretoCompartido);

            byte[] llaveCifradoBytes = new byte[32];
            byte[] llaveHMACBytes = new byte[32];
            System.arraycopy(hash, 0, llaveCifradoBytes, 0, 32);
            System.arraycopy(hash, 32, llaveHMACBytes, 0, 32);

            SecretKey llaveCifrado = Cifrado.crearLlaveAES(llaveCifradoBytes);
            SecretKey llaveHMAC = Cifrado.crearLlaveHMAC(llaveHMACBytes);

            enviarTablaServicios(llaveCifrado, llaveHMAC);
            recibirYResponderSolicitud(llaveCifrado, llaveHMAC);

            cliente.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void enviarTablaServicios(SecretKey llaveCifrado, SecretKey llaveHMAC) throws Exception {
        Map<Integer, String> servicios = Servidor.obtenerServicios();
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<Integer, String> entry : servicios.entrySet()) {
            sb.append(entry.getKey()).append(":").append(entry.getValue()).append("\n");
        }
        byte[] datosTabla = sb.toString().getBytes();

        // Medir tiempo de firmar
        medidorFirmar.comenzar();
        byte[] firma = Cifrado.firmarDatos(datosTabla, llavePrivada);
        medidorFirmar.parar();
        System.out.println("[Tiempo] Firma de tabla: " + medidorFirmar.tiempoMilisegundos() + " ms");

        // Medir tiempo de cifrar (simétrico AES)
        medidorCifrar.comenzar();
        IvParameterSpec iv = Cifrado.generarIV();
        byte[] tablaCifrada = Cifrado.cifrarAES(datosTabla, llaveCifrado, iv);
        medidorCifrar.parar();
        System.out.println("[Tiempo] Cifrado simétrico (AES) de tabla: " + medidorCifrar.tiempoMilisegundos() + " ms");

        // Medir tiempo de cifrar (asimétrico RSA)
        Cipher cifradorRSA = Cipher.getInstance("RSA");
        cifradorRSA.init(Cipher.ENCRYPT_MODE, llavePublicaServidor);

        MedidorTiempo medidorCifrarAsimetrico = new MedidorTiempo();
        medidorCifrarAsimetrico.comenzar();
        byte[] tablaCifradaRSA = cifradorRSA.doFinal(datosTabla);
        medidorCifrarAsimetrico.parar();
        System.out.println("[Tiempo] Cifrado asimétrico (RSA) de tabla: " + medidorCifrarAsimetrico.tiempoMilisegundos() + " ms");

        byte[] hmac = Cifrado.HMAC(tablaCifrada, llaveHMAC);

        salida.writeObject(iv.getIV());
        salida.writeObject(tablaCifrada);
        salida.writeObject(firma);
        salida.writeObject(hmac);
        salida.flush();
    }

    private void recibirYResponderSolicitud(SecretKey llaveCifrado, SecretKey llaveHMAC) throws Exception {
        byte[] ivBytes = (byte[]) entrada.readObject();
        byte[] solicitudCifrada = (byte[]) entrada.readObject();
        byte[] hmacRecibido = (byte[]) entrada.readObject();

        // Medir tiempo de verificación
        medidorVerificar.comenzar();
        byte[] hmacCalculado = Cifrado.HMAC(solicitudCifrada, llaveHMAC);
        boolean hmacValido = MessageDigest.isEqual(hmacRecibido, hmacCalculado);
        medidorVerificar.parar();
        System.out.println("[Tiempo] Verificación de HMAC solicitud: " + medidorVerificar.tiempoMilisegundos() + " ms");

        if (!hmacValido) {
            System.out.println("Error en la consulta (HMAC inválido). Terminando conexión.");
            cliente.close();
            return;
        }

        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        byte[] solicitudDescifrada = Cifrado.descifrarAES(solicitudCifrada, llaveCifrado, iv);
        String solicitudStr = new String(solicitudDescifrada);
        int idServicio = Integer.parseInt(solicitudStr.trim());

        Map<Integer, String> direcciones = Servidor.obtenerDirecciones();
        String direccion = direcciones.getOrDefault(idServicio, "-1:-1");

        byte[] direccionBytes = direccion.getBytes();

        IvParameterSpec ivRespuesta = Cifrado.generarIV();
        byte[] direccionCifrada = Cifrado.cifrarAES(direccionBytes, llaveCifrado, ivRespuesta);
        byte[] hmacDireccion = Cifrado.HMAC(direccionCifrada, llaveHMAC);

        salida.writeObject(ivRespuesta.getIV());
        salida.writeObject(direccionCifrada);
        salida.writeObject(hmacDireccion);
        salida.flush();
    }
}
