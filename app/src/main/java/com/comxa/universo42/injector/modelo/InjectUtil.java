package com.comxa.universo42.injector.modelo;

import android.annotation.SuppressLint;
import android.util.ArrayMap;

import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class InjectUtil {
//    private static final String NETDATA = "[netData]";     //Ex.: CONNECT 188.100.100.123:443 HTTP/1.0
//    private static final String HOST = "[host]";           //Ex.: 188.100.100.123
//    private static final String PORT = "[port]";           //Ex.: 443
//    private static final String HOST_PORT = "[host_port]"; //Ex.: 188.100.100.123:443
//    private static final String PROTOCOL = "[protocol]";   //Ex.: HTTP/1.0
//    private static final String NEW_LINE = "[crlf]";       //Ex.: \r\n

    private String metodo;
    private String host;
    private String port;
    private String hostPort;
    private String protocolo;
    private Map<String, String> headers;
    
    private String payload;
    private String strRequisicao;

    public InjectUtil() {
    }

    public String getMetodo() {
        return metodo;
    }

    public void setMetodo(String metodo) {
        this.metodo = metodo;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getPort() {
        return port;
    }

    public void setPort(String port) {
        this.port = port;
    }

    public String getProtocolo() {
        return protocolo;
    }

    public void setProtocolo(String protocolo) {
        this.protocolo = protocolo;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public void setHeaders(Map<String, String> headers) {
        this.headers = headers;
    }
    
    public String getPayload() {
        return this.payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }
    
    public String getHeaderVal(String header) {
        String val = null;
        
        for (String h : this.headers.keySet()) {
            if (h.equalsIgnoreCase(header)) {
                val = this.headers.get(h);
                break;
            }
        }
        
        return val;
    }

    public String getStrRequisicao() {
        if (this.payload != null) {
            parsePayload(this.payload);
        }

        return this.strRequisicao;
    }

//    public void parsePayload(String payload) {
//        if (this.metodo != null && this.host != null && this.port != null && this.protocolo != null)
//            payload = payload.replace(NETDATA, String.format("%s %s %s", this.metodo, this.hostPort, this.protocolo));
//
//        if (this.host != null)
//            payload = payload.replace(HOST, this.host);
//
//        if (this.port != null)
//            payload = payload.replace(PORT, this.port);
//
//        if (this.host != null && this.port != null)
//            payload = payload.replace(HOST_PORT, getHostWithPort());
//
//        if (this.protocolo != null)
//            payload = payload.replace(PROTOCOL, this.protocolo);
//
//        payload = payload.replace(NEW_LINE, "\r\n");
//
//        this.strRequisicao = payload;
//    }

    @SuppressLint("DefaultLocale")
    public void parsePayload(String hostname) {
        ArrayMap<String, String> tags_list = new ArrayMap<>();
        tags_list.put("[method]", metodo);
        tags_list.put("[host]", hostname);
        tags_list.put("[port]", port);
        tags_list.put("[host_port]", String.format("%s:%s", hostname, port));
        tags_list.put("[protocol]", protocolo);
        tags_list.put("[ssh]", String.format("%s:%s", hostname, port));

        tags_list.put("[crlf]", "\r\n");
        tags_list.put("[cr]", "\r");
        tags_list.put("[lf]", "\n");
        tags_list.put("[lfcr]", "\n\r");

        // para corrigir bugs
        tags_list.put("\\n", "\n");
        tags_list.put("\\r", "\r");

        String ua = System.getProperty("http.agent");
        tags_list.put("[ua]", ua == null ? "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.130 Safari/537.36" : ua);

        if (!payload.isEmpty()) {
            for (String key : tags_list.keySet()) {
                String value = tags_list.get(key);
                payload = payload.replace(key, value);
                payload = payload.replace(key.toUpperCase(), value);
            }
            payload = parseRotate(payload);
        }

        this.strRequisicao = payload;
    }

    private static Map<Integer,Integer> lastRotateList = new ArrayMap<>();
    private static String lastPayload = "";

    public static String parseRotate(String payload) {
        Matcher match = Pattern.compile("\\[rotate=(.*?)]")
                .matcher(payload);

        // limpa dados quando a payload fôr alterada
        if (!lastPayload.equals(payload)) {
            lastRotateList.clear();
            lastPayload = payload;
        }

        int i = 0;
        while (match.find()) {
            String group = match.group(1);

            String[] split = group.split(";");
            if (split.length <= 0) continue;

            int split_key;
            if (lastRotateList.containsKey(i)) {
                split_key = lastRotateList.get(i)+1;
                if (split_key >= split.length) {
                    split_key = 0;
                }
            }
            else  {
                split_key = 0;
            }

            String host = split[split_key];

            payload = payload.replace(match.group(0), host);

            lastRotateList.put(i, split_key);

            i++;
        }

        return payload;
    }

    public static void restartRotate() {
        lastRotateList.clear();
    }

    public void parseRequisicaoStr(String strReq) {
        if (strReq.length() == 0)
            return;

        Scanner scanner = new Scanner(strReq);
        this.metodo = scanner.next();
        this.hostPort = scanner.next();
        String[] hostAndPort = getHostAndPort();
        this.host = hostAndPort[0];
        this.port = hostAndPort[1];
        this.protocolo = scanner.next();
        this.headers = new HashMap<String, String>();
        String headerKey, headerValue;

        while (scanner.hasNext()) {
            headerKey = scanner.next();
            headerKey = headerKey.substring(0, headerKey.length() - 1);

            if (scanner.hasNextLine())
                headerValue = scanner.nextLine().substring(1);
            else
                break;
            this.headers.put(headerKey, headerValue);
        }

        this.strRequisicao = strReq;

        scanner.close();
    }

    public String makeRequisicao() {
        StringBuilder builder = new StringBuilder();

        builder.append(String.format("%s %s %s\r\n", this.metodo, this.hostPort, this.protocolo));

        for (String headerKey : this.headers.keySet()) {
            builder.append(String.format("%s: %s\r\n", headerKey, this.headers.get(headerKey)));
        }
        builder.append("\r\n");

        this.strRequisicao = builder.toString();

        return this.strRequisicao;
    }

    
    private String[] getHostAndPort() {
        String[] ret = new String[2];

        if (hostPort.length() > 7 && hostPort.substring(0, 4).equals("http")) {
            ret[0] = hostPort.substring(hostPort.indexOf('/') + 2);
        } else {
            ret[0] = hostPort;
        }

        if (ret[0].contains(":")) {
            String str = ret[0];
            ret[0] = ret[0].substring(0, ret[0].indexOf(':'));
            ret[1] = str.substring(str.indexOf(':') + 1);
            if (ret[1].contains("/")) {
                ret[1] = ret[1].substring(0, ret[1].indexOf('/'));
            }
        }

        return ret;
    }

    private String getHostWithPort() {
        if (this.port != null) {
            return String.format("%s:%s", this.host, this.port);
        }

        return this.host;
    }
}
