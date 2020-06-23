package net.openvpn.openvpn;

import android.app.Application;
import android.content.Context;

import com.wdev.openvpn.PUtil;

public class OpenVPNApplication extends Application {
    public static Context context;

    public void onCreate() {
        super.onCreate();
        context = getApplicationContext();
        PUtil.setContext(this);
    }

    public static String resString(int res_id) {
        return context.getString(res_id);
    }
}
