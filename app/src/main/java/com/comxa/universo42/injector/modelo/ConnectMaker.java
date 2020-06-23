package com.comxa.universo42.injector.modelo;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import android.content.*;


public class ConnectMaker implements Loggable {
    private int id;

    private int tamBufferEnvio = 4096;
    private int tamBufferRecepcao = 4096;
    private Host destino;
    private Host cliente;
    
    private boolean isThread1Closed;
    private boolean isThread2Closed;
    private boolean isStopped;

	private SharedPreferences sp;

    public ConnectMaker() {}

    public ConnectMaker(Host destino, Host cliente) throws IOException {
        this.cliente = cliente;
        this.destino = destino;
    }
  
    public int getTamBufferEnvio() {
        return tamBufferEnvio;
    }

    public void setTamBufferEnvio(int tamBufferEnvio) {
        this.tamBufferEnvio = tamBufferEnvio;
    }

    public int getTamBufferRecepcao() {
        return tamBufferRecepcao;
    }

    public void setTamBufferRecepcao(int tamBufferRecepcao) {
        this.tamBufferRecepcao = tamBufferRecepcao;
    }

    public Host getDestino() {
        return destino;
    }

    public void setDestino(Host destino) {
        this.destino = destino;
    }

    public Host getCliente() {
        return cliente;
    }

    public void setCliente(Host cliente) {
        this.cliente = cliente;
    }
    
    public int getId() {
        return this.id;
    }
    
    public void setId(int id) {
        this.id = id;
    }
    
    public void stop() {
    	isStopped = true;
    	close();
    }
    
    private void close() {
    	try {
	    	try {
	    		this.destino.close();
	    	} finally {
	    		this.cliente.close();
	    	}
    	} catch(IOException e) {}
    }

    
    public void run() {
        //Sender thread
        run(this.cliente, this.destino, 16384); // Integer.parseInt(sp.getString("buffer_send", "16384")));
        //Receiver thread
        run(this.destino, this.cliente, 32768);// Integer.parseInt(sp.getString("buffer_receive", "32768")));
    }

    private void run(final Host hostIn, final Host hostOut, final int tamBuffer) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    InputStream in = hostIn.getIn();
                    OutputStream out = hostOut.getOut();
                    Socket inSocket = hostIn.getSocket();
                    Socket outSocket = hostOut.getSocket();

                    byte[] buffer = new byte[tamBuffer];

                    int len = in.read(buffer);

                    while (len != -1 && !inSocket.isOutputShutdown()) {
                        out.write(buffer, 0, len);
                        out.flush();
                        len = in.read(buffer);
                    }

                    if (len == -1 || inSocket.isOutputShutdown()) {
                        if (!isThread1Closed)
                            isThread1Closed = true;
                        else
                            isThread2Closed = true;

                        inSocket.shutdownInput();
                        outSocket.shutdownOutput();
                    }
                } catch (IOException e) {
                    if (!isStopped)
                        ConnectMaker.this.onLogReceived("<#> Thread " + ConnectMaker.this.getId() + ": erro na transfer�ncia de dados. " + e.getMessage(), LOG_LEVEL_CRITICAL, e);
                } finally {
                    if (isThread2Closed) {
                        ConnectMaker.this.close();
                        ConnectMaker.this.onLogReceived("<-> Thread " + ConnectMaker.this.getId() + ": conex�o encerrada.", LOG_LEVEL_INFO, null);
                    }
                    ConnectMaker.this.onConnectionClosed();
                }
            }
        }).start();
    }

    @Override
    public void onLogReceived(String log, int level, Exception e) {}
    
    public void onConnectionClosed() {}
    
}

