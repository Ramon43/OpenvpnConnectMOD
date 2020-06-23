package com.wdev.openvpn;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.text.Editable;
import android.util.Log;
import android.widget.EditText;

import net.openvpn.openvpn.OpenVPNService;
import net.openvpn.openvpn.PrefUtil;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PUtil {

    @SuppressLint("StaticFieldLeak")
    private static Context mContext;
    private static String mServerAndPort;
    private static ServerThread mServer;
    public static String DEFAULT_PAYLOAD = "CONNECT 127.0.0.1:1194 HTTP/1.0[crlf][crlf]";
    private static PrefUtil prefs;
    private static String payload = DEFAULT_PAYLOAD;


    public static void setContext(Context mContext) {
        PUtil.mContext = mContext;
    }


    private static PrefUtil getPrefs() {
        if (prefs == null)
            prefs = new PrefUtil(PreferenceManager.getDefaultSharedPreferences(mContext));
        return prefs;
    }


    public static void save(EditText editText) {
        SharedPreferences.Editor edit = mContext.getSharedPreferences("Payload", Context.MODE_PRIVATE).edit();
        Editable editTextText = editText.getText();
        String payload;
        if (editText.length() > 0)
            payload = editTextText.toString();
        else
            payload = DEFAULT_PAYLOAD;

        edit.putString("PAYLOAD", payload);
        edit.commit();
        edit.apply();
    }

    public static String getServerAndPort() {
        return mServerAndPort;
    }

    public static String hook_profile(String server, OpenVPNService.Profile profile) {
        Pattern pattern = Pattern.compile("http-proxy\\s+([\\w.]+)\\s+(\\d+)");
        Matcher m = pattern.matcher(server);
        if (m.find()) {
            String host = m.group(1);
            String port = m.group(2);
            mServerAndPort = host + ":" + port;
            String ret = m.replaceAll("http-proxy 127.0.0.1 9393") + "\nroute " + host + " 255.255.255.255 net_gateway";
            setPayload(profile);
            return ret;
        }
        return server;
    }

    private static void setPayload(OpenVPNService.Profile profile) {
        String pay = profile.get_payload();
        String pay_prefs = getPrefs().get_string_by_profile(profile.get_name(), "payload");
        if (pay_prefs != null)
            payload = pay_prefs;
        else if (pay != null)
            payload = pay;
        else
            payload = DEFAULT_PAYLOAD;

    }


    public static String getPayload() {
        return payload;
    }

    public static void startServer() {
        stopServer();
        mServer = new ServerThread();
        mServer.start();
    }

    public static void stopServer() {
        if (mServer != null && mServer.isAlive())
            mServer.interrupt();

    }

}
