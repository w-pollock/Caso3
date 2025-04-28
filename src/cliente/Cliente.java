package src.cliente;

import src.crypto.Cifrado;
import src.crypto.DiffieHellman;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.util.Scanner;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.security.MessageDigest;

public class Cliente {

    private static final String SERVIDOR_IP = "127.0.0.1";
    private static final int SERVIDOR_PUERTO = 5000;

    private PublicKey llavePublicaServidor;

    private ObjectOutputStream salida;
    private ObjectInputStream entrada;

    private SecretKey llaveCifrado;
    private SecretKey llaveHMAC;

    public Cliente() throws Exception {
        cargarLlavePublicaServidor();
    }

    private void cargarLlavePublicaServidor() throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream("keys/public.key"))) {
            llavePublicaServidor = (PublicKey) ois.readObject();
        }
    }

    public void iniciar() throws Exception {
        Socket socket = new Socket(SERVIDOR_IP, SERVIDOR_PUERTO);
        salida = new ObjectOutputStream(socket.getOutputStream());
        entrada = new ObjectInputStream(socket.getInputStream());

        BigInteger p = (BigInteger) entrada.readObject();
        BigInteger g = (BigInteger) entrada.readObject();
        DHParameterSpec dhSpec = new DHParameterSpec(p, g);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(dhSpec);
        KeyPair parLlaves = keyGen.generateKeyPair();

        KeyAgreement acuerdo = KeyAgreement.getInstance("DH");
        acuerdo.init(parLlaves.getPrivate());

        byte[] llavePublicaServidorBytes = (byte[]) entrada.readObject();
        PublicKey llavePublicaServidorDH = DiffieHellman.reconstruirLlavePublica(llavePublicaServidorBytes);

        salida.writeObject(parLlaves.getPublic().getEncoded());
        salida.flush();

        byte[] secretoCompartido = DiffieHellman.crearSecretoCompartido(acuerdo, llavePublicaServidorDH);

        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] hash = sha512.digest(secretoCompartido);

        byte[] llaveCifradoBytes = new byte[32];
        byte[] llaveHMACBytes = new byte[32];
        System.arraycopy(hash, 0, llaveCifradoBytes, 0, 32);
        System.arraycopy(hash, 32, llaveHMACBytes, 0, 32);

        llaveCifrado = Cifrado.crearLlaveAES(llaveCifradoBytes);
        llaveHMAC = Cifrado.crearLlaveHMAC(llaveHMACBytes);

        recibirTablaServicios();
        enviarSolicitudServicio();

        socket.close();
    }

    private void recibirTablaServicios() throws Exception {
        byte[] ivBytes = (byte[]) entrada.readObject();
        byte[] tablaCifrada = (byte[]) entrada.readObject();
        byte[] firma = (byte[]) entrada.readObject();
        byte[] hmacRecibido = (byte[]) entrada.readObject();

        byte[] hmacCalculado = Cifrado.HMAC(tablaCifrada, llaveHMAC);
        if (!MessageDigest.isEqual(hmacRecibido, hmacCalculado)) {
            System.out.println("Error en la consulta (HMAC inválido). Terminando.");
            System.exit(1);
        }

        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        byte[] datosDescifrados = Cifrado.descifrarAES(tablaCifrada, llaveCifrado, iv);

        boolean firmaValida = Cifrado.verificarFirma(datosDescifrados, firma, llavePublicaServidor);
        if (!firmaValida) {
            System.out.println("Error: firma de la tabla inválida. Terminando.");
            System.exit(1);
        }

        String tabla = new String(datosDescifrados);
        System.out.println("Servicios disponibles:");
        System.out.println(tabla);
    }

    private void enviarSolicitudServicio() throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Ingrese el ID del servicio que desea consultar: ");
        String idServicio = scanner.nextLine();

        byte[] datos = idServicio.getBytes();
        IvParameterSpec iv = Cifrado.generarIV();
        byte[] solicitudCifrada = Cifrado.cifrarAES(datos, llaveCifrado, iv);

        byte[] hmacSolicitud = Cifrado.HMAC(solicitudCifrada, llaveHMAC);

        salida.writeObject(iv.getIV());
        salida.writeObject(solicitudCifrada);
        salida.writeObject(hmacSolicitud);
        salida.flush();

        recibirDireccion();
    }

    private void recibirDireccion() throws Exception {
        byte[] ivBytes = (byte[]) entrada.readObject();
        byte[] direccionCifrada = (byte[]) entrada.readObject();
        byte[] hmacRecibido = (byte[]) entrada.readObject();

        byte[] hmacCalculado = Cifrado.HMAC(direccionCifrada, llaveHMAC);
        if (!MessageDigest.isEqual(hmacRecibido, hmacCalculado)) {
            System.out.println("Error en la respuesta (HMAC inválido). Terminando.");
            System.exit(1);
        }

        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        byte[] direccionBytes = Cifrado.descifrarAES(direccionCifrada, llaveCifrado, iv);

        String direccion = new String(direccionBytes);
        System.out.println("Dirección del servidor del servicio: " + direccion);
    }

    public static void main(String[] args) throws Exception {
        Cliente cliente = new Cliente();
        cliente.iniciar();
    }
}
