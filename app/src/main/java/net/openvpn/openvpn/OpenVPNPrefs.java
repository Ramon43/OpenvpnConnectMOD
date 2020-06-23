package net.openvpn.openvpn;

import android.os.Bundle;
import android.preference.PreferenceActivity;

public class OpenVPNPrefs extends PreferenceActivity {
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        addPreferencesFromResource(R.xml.preferences);
    }
}
