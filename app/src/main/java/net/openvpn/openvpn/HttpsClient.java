package net.openvpn.openvpn;

import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.os.Handler;
import android.support.v7.app.AlertDialog.Builder;
import android.text.method.PasswordTransformationMethod;
import android.text.method.SingleLineTransformationMethod;
import android.util.Base64;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import net.openvpn.openvpn.TrustMan.Callback;
import net.openvpn.openvpn.TrustMan.TrustContext;
import net.openvpn.openvpn.XMLRPC.XMLRPCException;

import org.apache.http.conn.ssl.BrowserCompatHostnameVerifier;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLConnection;
import java.security.SecureRandom;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

public class HttpsClient {
    private static final String TAG = "OpenVPNHttpsClient";

    public interface Interact {
        void challenge_response_dialog(AuthContext authContext, String str);

        void error_dialog(int i, int i2, Object obj);
    }

    public static class AdaptiveHostnameVerifier implements HostnameVerifier {
        private HostnameVerifier bchv = new BrowserCompatHostnameVerifier();
        private boolean mode = false;

        public void allowAll(boolean newMode) {
            this.mode = newMode;
        }

        public boolean verify(String hostname, SSLSession session) {
            if (this.mode) {
                return true;
            }
            return this.bchv.verify(hostname, session);
        }
    }

    public static class AuthContext {
        private CR cr;
        private String hostname = "";
        private String password;
        private boolean pw_is_sess_id = false;
        private String server;
        private String username;

        public static class CR {
            private String challenge_text;
            private boolean echo = false;
            private String response = "";
            private boolean response_required = false;
            private String state_id;
            private String username;

            public static class ParseError extends Exception {
                public ParseError() {
                    super("AuthContext.CR.ParseError");
                }
            }

            public CR(String cookie) throws ParseError {
                int i = 0;
                String[] sl = cookie.split(":", 5);
                if (sl.length != 5) {
                    throw new ParseError();
                } else if (sl[0].equals("CRV1")) {
                    String[] opt = sl[1].split(",");
                    int length = opt.length;
                    while (i < length) {
                        String s = opt[i];
                        if (s.equals("E")) {
                            this.echo = true;
                        }
                        if (s.equals("R")) {
                            this.response_required = true;
                        }
                        i++;
                    }
                    this.state_id = sl[2];
                    try {
                        this.username = new String(Base64.decode(sl[3], 0), "UTF-8");
                        this.challenge_text = sl[4];
                    } catch (UnsupportedEncodingException e) {
                        throw new ParseError();
                    }
                } else {
                    throw new ParseError();
                }
            }

            public String get_username() {
                return this.username;
            }

            public String get_password() {
                return "CRV1::" + this.state_id + "::" + this.response;
            }

            public String get_challenge_text() {
                return this.challenge_text;
            }

            public boolean get_echo() {
                return this.echo;
            }

            public boolean get_response_required() {
                return this.response_required;
            }

            public String get_response() {
                return this.response;
            }

            public void set_response(String resp) {
                this.response = resp;
            }

            public static boolean is_challenge(String client_reason) {
                return client_reason != null && client_reason.startsWith("CRV1:");
            }
        }

        public AuthContext(String server_arg, String username_arg, String password_arg) {
            this.server = server_arg;
            this.username = username_arg;
            this.password = password_arg;
        }

        public void set_session_id(String sess_id) {
            this.pw_is_sess_id = true;
            this.password = sess_id;
            this.cr = null;
        }

        public String get_username() {
            if (this.pw_is_sess_id) {
                return "SESSION_ID";
            }
            if (this.cr != null) {
                return this.cr.get_username();
            }
            return this.username;
        }

        public String get_password() {
            if (this.cr != null) {
                return this.cr.get_password();
            }
            return this.password;
        }

        public String profile_filename() {
            return String.format("%s@%s.ovpn", new Object[]{this.username, this.server});
        }

        public static boolean is_challenge(String client_reason) {
            return CR.is_challenge(client_reason);
        }

        public void cr_parse(String cookie) throws Exception {
            this.cr = new CR(cookie);
        }

        public boolean cr_defined() {
            return this.cr != null;
        }

        public CR get_cr() {
            return this.cr;
        }

        public void set_basic_auth(URLConnection uc) throws UnsupportedEncodingException {
            uc.setRequestProperty("Authorization", "Basic " + Base64.encodeToString((get_username() + ":" + get_password()).getBytes("UTF-8"), 2));
        }

        public String getHostname() {
            return this.hostname;
        }

        public void setHostname(String hostname) {
            this.hostname = hostname;
        }
    }

    public static class CancelDetect {
        private final int gen;
        private final I obj;

        public interface I {
            int cancel_generation();
        }

        public CancelDetect(I object) {
            this.obj = object;
            this.gen = object.cancel_generation();
        }

        public boolean is_canceled() {
            return this.gen != this.obj.cancel_generation();
        }
    }

    public static class PresettableHostnameVerifier implements HostnameVerifier {
        private HostnameVerifier bchv = new BrowserCompatHostnameVerifier();
        public String hostnameOverride;

        public boolean verify(String hostname, SSLSession session) {
            return this.bchv.verify(this.hostnameOverride, session);
        }
    }

    public static abstract class Task implements Runnable {
        protected static final int PROF_AUTOLOGIN = 1;
        protected static final int PROF_USERLOGIN = 2;
        protected HostnameVerifier hostnameVerifier;
        protected Interact interact;
        protected long max_download_size;
        protected SSLContext sslContext;

        protected static class ErrorDialogException extends Exception {
            private int msg_resid;
            private Object obj;
            private int title_resid;

            public ErrorDialogException(int title_resid_arg, int msg_resid_arg, Object obj_arg) {
                super("ErrorDialogException");
                this.title_resid = title_resid_arg;
                this.msg_resid = msg_resid_arg;
                this.obj = obj_arg;
            }

            void dispatch(Interact inter) {
                inter.error_dialog(this.title_resid, this.msg_resid, this.obj);
            }
        }

        protected static class SilentException extends ErrorDialogException {
            public SilentException() {
                super(0, 0, null);
            }
        }

        protected HttpsURLConnection get_conn(AuthContext ac) throws MalformedURLException, IOException, ProtocolException, UnsupportedEncodingException {
            HttpsURLConnection conn = (HttpsURLConnection) new URL("https://" + ac.server + "/RPC2").openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(30000);
            conn.setReadTimeout(60000);
            if (ac.getHostname().isEmpty()) {
                conn.setHostnameVerifier(this.hostnameVerifier);
            } else {
                PresettableHostnameVerifier v = new PresettableHostnameVerifier();
                v.hostnameOverride = ac.getHostname();
                conn.setHostnameVerifier(v);
            }
            conn.setSSLSocketFactory(this.sslContext.getSocketFactory());
            ac.set_basic_auth(conn);
            return conn;
        }

        protected static String xmlrpc_simple_query(String method_name) {
            Object[] objArr = new Object[PROF_AUTOLOGIN];
            objArr[0] = method_name;
            return String.format("<?xml version=\"1.0\"?>\n<methodCall>\n<methodName>%s</methodName>\n<params></params>\n</methodCall>\n", objArr);
        }

        protected void write(HttpsURLConnection conn, String s) throws IOException {
            OutputStreamWriter writer = new OutputStreamWriter(conn.getOutputStream());
            writer.write(s);
            writer.flush();
        }

        protected String read(HttpsURLConnection conn) throws IOException {
            return FileUtil.readStream(new BufferedInputStream(conn.getInputStream()), this.max_download_size, "<XML-RPC input>");
        }

        protected Object parse_xmlrpc(String xml_text) throws XmlPullParserException, XMLRPCException, IOException {
            XmlPullParser xpp = XmlPullParserFactory.newInstance().newPullParser();
            xpp.setInput(new StringReader(xml_text));
            return XMLRPC.parse_response(xpp);
        }

        protected void get_session_id(AuthContext ac) throws Exception {
            HttpsURLConnection conn = get_conn(ac);
            write(conn, xmlrpc_simple_query("GetSession"));
            String xml_text = read(conn);
            conn.disconnect();
            Map<String, Object> map = (Map) parse_xmlrpc(xml_text);
            if (map != null) {
                Integer status = (Integer) map.get("status");
                if (status != null) {
                    if (status.intValue() == 0) {
                        String session_id = (String) map.get("session_id");
                        if (session_id != null) {
                            ac.set_session_id(session_id);
                            return;
                        }
                    } else if (status.intValue() == PROF_AUTOLOGIN) {
                        String client_reason = (String) map.get("client_reason");
                        if (client_reason == null) {
                            throw new ErrorDialogException(R.string.profile_import_error, R.string.auth_failed, null);
                        } else if (AuthContext.is_challenge(client_reason)) {
                            this.interact.challenge_response_dialog(ac, client_reason);
                            throw new SilentException();
                        } else {
                            throw new ErrorDialogException(R.string.profile_import_error, R.string.auth_failed, client_reason);
                        }
                    }
                }
            }
            throw new XMLRPCException("malformed XML response to GetSession");
        }

        protected int profile_types_available(AuthContext ac) throws Exception {
            int ret = 0;
            HttpsURLConnection conn = get_conn(ac);
            write(conn, xmlrpc_simple_query("EnumConfigTypes"));
            String xml_text = read(conn);
            conn.disconnect();
            Map<String, Object> map = (Map) parse_xmlrpc(xml_text);
            if (map != null) {
                Boolean autologin = (Boolean) map.get("autologin");
                if (autologin != null && autologin.booleanValue()) {
                    ret = 0 | PROF_AUTOLOGIN;
                }
                Boolean userlogin = (Boolean) map.get("userlogin");
                if (userlogin == null || !userlogin.booleanValue()) {
                    return ret;
                }
                return ret | PROF_USERLOGIN;
            }
            throw new XMLRPCException("malformed XML response to EnumConfigTypes");
        }

        protected String get_profile(AuthContext ac, String method) throws Exception {
            HttpsURLConnection conn = get_conn(ac);
            write(conn, xmlrpc_simple_query(method));
            String xml_text = read(conn);
            conn.disconnect();
            String profile = (String) parse_xmlrpc(xml_text);
            if (profile != null) {
                return profile;
            }
            throw new XMLRPCException("malformed XML response to " + method);
        }

        protected void close_session(AuthContext ac) throws Exception {
            HttpsURLConnection conn = get_conn(ac);
            write(conn, xmlrpc_simple_query("CloseSession"));
            String xml_text = read(conn);
            conn.disconnect();
        }
    }

    private static void raise_dialog(Context context, String title, String msg) {
        new Builder(context).setTitle(title).setMessage(msg).setPositiveButton(R.string.ok, new OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
            }
        }).show();
    }

    private static String resstr(Context context, int res_id) {
        return context.getResources().getString(res_id);
    }

    public static void run_task(Context context, final Task task, CancelDetect.I cancel_source, Runnable on_fail, boolean enable_cert_dialog, boolean enable_trust_error_dialog, long max_download_size) {
        final Handler handler = new Handler();
        try {
            final TrustMan tm = new TrustMan(context);
            SSLContext sc = SSLContext.getInstance("TLS");
            final CancelDetect cancel = new CancelDetect(cancel_source);
            SSLContext sSLContext = sc;
            sSLContext.init(null, new X509TrustManager[]{tm}, new SecureRandom());
            final AdaptiveHostnameVerifier hv = new AdaptiveHostnameVerifier();
            final Context context2 = context;
            final boolean z = enable_trust_error_dialog;
            final Runnable runnable = on_fail;
            final Task task2 = task;
            Interact interact = new Interact() {
                public void error_dialog(final int title_resid, final int msg_resid, final Object obj) {
                    handler.post(new Runnable() {
                        public void run() {
                            if (!cancel.is_canceled()) {
                                if ((!(obj instanceof Exception) || !TrustMan.isTrustFail((Exception) obj)) && title_resid != 0) {
                                    StringBuilder sb = new StringBuilder();
                                    if (msg_resid != 0) {
                                        sb.append(HttpsClient.resstr(context2, msg_resid));
                                    }
                                    if (obj != null) {
                                        if (sb.length() > 0) {
                                            sb.append(" : ");
                                        }
                                        sb.append(obj.toString());
                                    }
                                    String title = HttpsClient.resstr(context2, title_resid);
                                    String msg = sb.toString();
                                    if (z) {
                                        HttpsClient.raise_dialog(context2, title, msg);
                                    }
                                    handler.post(runnable);
                                }
                            }
                        }
                    });
                }

                public void challenge_response_dialog(final AuthContext ac, final String client_reason) {
                    handler.post(new Runnable() {
                        public void run() {
                            if (!cancel.is_canceled()) {
                                try {
                                    ac.cr_parse(client_reason);
                                    boolean echo = ac.get_cr().get_echo();
                                    boolean response_required = ac.get_cr().get_response_required();
                                    String challenge_text = ac.get_cr().get_challenge_text();
                                    OnClickListener receiver;
                                    if (response_required) {
                                        View view = LayoutInflater.from(context2).inflate(R.layout.cr_dialog, null);
                                        final EditText resp = (EditText) view.findViewById(R.id.dialog_response);
                                        ((TextView) view.findViewById(R.id.dialog_challenge)).setText(challenge_text);
                                        if (echo) {
                                            resp.setTransformationMethod(SingleLineTransformationMethod.getInstance());
                                        } else {
                                            resp.setTransformationMethod(PasswordTransformationMethod.getInstance());
                                        }
                                        receiver = new OnClickListener() {
                                            public void onClick(DialogInterface dialog, int which) {
                                                if (!cancel.is_canceled()) {
                                                    if (which == -1) {
                                                        ac.get_cr().set_response(resp.getText().toString());
                                                        new Thread(task2).start();
                                                        return;
                                                    }
                                                    handler.post(runnable);
                                                }
                                            }
                                        };
                                        new Builder(context2).setTitle(HttpsClient.resstr(context2, R.string.cr_title)).setView(view).setPositiveButton(R.string.cr_continue, receiver).setNegativeButton(R.string.cr_cancel, receiver).show();
                                        return;
                                    }
                                    receiver = new OnClickListener() {
                                        public void onClick(DialogInterface dialog, int which) {
                                            if (!cancel.is_canceled()) {
                                                if (which == -1) {
                                                    new Thread(task2).start();
                                                } else {
                                                    handler.post(runnable);
                                                }
                                            }
                                        }
                                    };
                                    new Builder(context2).setTitle(HttpsClient.resstr(context2, R.string.cr_title)).setMessage(challenge_text).setPositiveButton(R.string.cr_continue, receiver).setNegativeButton(R.string.cr_cancel, receiver).show();
                                } catch (Exception e) {
                                    Log.e(HttpsClient.TAG, "challenge_response_dialog", e);
                                    HttpsClient.raise_dialog(context2, HttpsClient.resstr(context2, R.string.cr_error), e.toString());
                                    handler.post(runnable);
                                }
                            }
                        }
                    });
                }
            };
            task.sslContext = sc;
            task.hostnameVerifier = hv;
            task.interact = interact;
            task.max_download_size = max_download_size;
            final boolean z2 = enable_cert_dialog;
            final Context context3 = context;
            final CancelDetect cancelDetect = cancel;
            final Task task3 = task;
            final Handler handler2 = handler;
            final Runnable runnable2 = on_fail;
            tm.setCallback(new Callback() {
                public void onTrustFail(final TrustContext tc) {
                    handler2.post(new Runnable() {
                        public void run() {
                            if (z2) {
                              new CertWarn(context3, tc.chain[0], tc.excep.toString()) {
                                    protected void done(int response) {
                                        if (response == 1) {
                                            tm.trustCert(tc);
                                            if (!cancelDetect.is_canceled()) {
                                                new Thread(task3).start();
                                            }
                                        } else if (!cancelDetect.is_canceled()) {
                                            handler2.post(runnable2);
                                        }
                                    }
                                };
                                return;
                            }
                            HttpsClient.raise_dialog(context3, HttpsClient.resstr(context3, R.string.profile_import_error), HttpsClient.resstr(context3, R.string.profile_import_invalid_cert));
                            handler2.post(runnable2);
                        }
                    });
                }

                public void onTrustSucceed(boolean appTrusted) {
                    hv.allowAll(appTrusted);
                }
            });
            new Thread(task).start();
        } catch (Throwable e) {
            Log.e(TAG, "run_task", e);
            raise_dialog(context, resstr(context, R.string.https_client_task_error), e.toString());
            handler.post(on_fail);
        }
    }
}
