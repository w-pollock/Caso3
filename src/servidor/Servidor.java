package src.servidor;

import src.crypto.Cifrado;
import src.crypto.DiffieHellman;
import src.crypto.MedidorTiempo;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.KeyAgreement;
import java.util.Base64;
import java.security.MessageDigest;

public class Servidor {

    private static final int PUERTO = 5000; // Puerto del servidor
    private static Map<Integer, String> servicios; // ID -> Nombre del servicio
    private static Map<Integer, String> direcciones; // ID -> "IP:PUERTO"

    private PrivateKey llavePrivada;
    private PublicKey llavePublica;

    public Servidor() throws Exception {
        cargarLlaves();
        inicializarServicios();
    }

    private void cargarLlaves() throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream("keys/private.key"))) {
            llavePrivada = (PrivateKey) ois.readObject();
        }
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream("keys/public.key"))) {
            llavePublica = (PublicKey) ois.readObject();
        }
    }

    private void inicializarServicios() {
        servicios = new HashMap<>();
        direcciones = new HashMap<>();

        servicios.put(1, "Consulta estado vuelo");
        servicios.put(2, "Disponibilidad vuelos");
        servicios.put(3, "Costo vuelo");

        direcciones.put(1, "127.0.0.1:6001");
        direcciones.put(2, "127.0.0.1:6002");
        direcciones.put(3, "127.0.0.1:6003");
    }

    public void iniciar() throws Exception {
        ServerSocket servidor = new ServerSocket(PUERTO);
        System.out.println("Servidor principal escuchando en el puerto " + PUERTO);

        while (true) {
            Socket cliente = servidor.accept();
            new Thread(new DelegadoServidor(cliente, llavePrivada)).start();
        }
    }

    public static Map<Integer, String> obtenerServicios() {
        return servicios;
    }

    public static Map<Integer, String> obtenerDirecciones() {
        return direcciones;
    }

    public static void main(String[] args) throws Exception {
        Servidor servidor = new Servidor();
        servidor.iniciar();
    }
}