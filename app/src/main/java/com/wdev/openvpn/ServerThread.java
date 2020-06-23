package com.wdev.openvpn;

import android.util.Log;

import com.comxa.universo42.injector.modelo.Host;
import com.comxa.universo42.injector.modelo.InjectService;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

public class ServerThread extends Thread {

    private ServerSocket listen_socket;
    private boolean isRunning;

    @Override
    public void run() {
        isRunning = true;
        try {
            if (listen_socket == null) {
                listen_socket = new ServerSocket(9393, 50, InetAddress.getByName("127.0.0.1"));
                listen_socket.setReuseAddress(true);
            }
//                oreo.sendEmptyMessage(1);
            while (isRunning) {
                try {
                    Socket input = listen_socket.accept();
                    input.setSoTimeout(0);
                    Host hostProxy;
                    String[] host = PUtil.getServerAndPort().split(":");
                    hostProxy = new Host(host[0], Integer.parseInt(host[1]));

                    Host hostCliente = new Host(input);

                    InjectService reqInject = new InjectService(hostProxy, hostCliente, input.getPort()) {
                        @Override
                        public void onLogReceived(String log, int level, Exception e) {
                            //Injector.this.onLogReceived(log, level, e);
                        }

                        @Override
                        public void onConnectionClosed() {
                            //Injector.this.onConnectionClosed(this);
                        }
                    };
                    //Log.d("PAYLOAD",PUtil.getPayload());
                    reqInject.setPayload(PUtil.getPayload());

                    new Thread(reqInject).start();
                } catch (IOException e32) {
                    e32.printStackTrace();
                }
            }
        } catch (Exception e) {
            Log.e("SERVICE", e.getMessage(), e);
        }
    }

    @Override
    public void interrupt() {
        isRunning = false;
        try {
            listen_socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        super.interrupt();
    }
}
