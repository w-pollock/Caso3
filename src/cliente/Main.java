package src.cliente;
import java.util.Scanner;

import src.servidor.Servidor;

public class Main {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            // Si no hay argumentos, mostramos un menú para que elija el modo
            Scanner scanner = new Scanner(System.in);
            System.out.println("Seleccione el modo de ejecución:");
            System.out.println("1. Mediciones iterativas");
            System.out.println("2. Mediciones concurrentes");
            System.out.print("Ingrese el número de la opción deseada: ");
            int opcion = scanner.nextInt();

            if (opcion == 1) {
                correrIterativo();
            } else if (opcion == 2) {
                System.out.print("Ingrese el número de clientes para modo concurrente: ");
                int numClientes = scanner.nextInt();
                correrConcurrente(numClientes);
            } else {
                System.out.println("Opción desconocida. Terminando.");
            }
        } else {
            String modo = args[0];

            new Thread(() -> {
                try {
                    Servidor servidor = new Servidor();
                    servidor.iniciar();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();

            if (modo.equals("iterativo")) {
                correrIterativo();
            } else if (modo.equals("concurrente")) {
                if (args.length != 2) {
                    // Si no se pasa el número de clientes, pedimos que lo ingrese el usuario
                    Scanner scanner = new Scanner(System.in);
                    System.out.print("Debe especificar número de clientes para modo concurrente. Ingrese el número de clientes: ");
                    int numClientes = scanner.nextInt();
                    correrConcurrente(numClientes);
                } else {
                    // Si el número de clientes se pasa como argumento
                    int numClientes = Integer.parseInt(args[1]);
                    correrConcurrente(numClientes);
                }
            } else {
                System.out.println("Modo desconocido: " + modo);
            }
        }
    }

    public static void correrIterativo() throws Exception {
        System.out.println("Corriendo cliente iterativo (32 consultas secuenciales)");

        Cliente cliente = new Cliente();

        for (int i = 0; i < 32; i++) {
            System.out.println("Ejecutando consulta " + (i + 1));
            cliente.iniciar();
        }
    }

    private static void correrConcurrente(int numClientes) throws Exception {
        System.out.println("Corriendo clientes concurrentes: " + numClientes);
        Thread[] hilos = new Thread[numClientes];
        for (int i = 0; i < numClientes; i++) {
            hilos[i] = new Thread(() -> {
                try {
                    Cliente cliente = new Cliente();
                    cliente.iniciar();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
            hilos[i].start();
        }

        // Esperar a que todos los hilos terminen
        for (Thread hilo : hilos) {
            hilo.join();
        }
    }
}
