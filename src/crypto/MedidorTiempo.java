package src.crypto;

public class MedidorTiempo {
    private long inicio;
    private long fin;

    public void comenzar(){
        inicio = System.nanoTime();
    }

    public void parar(){
        fin = System.nanoTime();
    }

    public double tiempoMilisegundos(){
        return (fin-inicio)/1000000.0;
    }
}
