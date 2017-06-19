import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.Map;

public class Request {
    static final String MethodPost   = "POST";
    static final String MethodGet    = "GET";
    static final String MethodPut    = "PUT";
    static final String MethodDelete = "DELETE";
    private static final Gson gson = new Gson();

    String route;
    String method;
    String auth_token;
    Map<String, Object> data;
    private transient boolean verified;
    private transient String username;

    public static String toJson(Request req) {
        return gson.toJson(req);
    }

    Request(String message) {
        Type mapType = new TypeToken<Map<String, Object>>(){}.getType();
        Map<String, Object> parsed = gson.fromJson(message, mapType);
        method = parsed.get("method").toString();
        route = parsed.get("route").toString();
        if (parsed.containsKey("auth_token"))
            auth_token = parsed.get("auth_token").toString();
        data = parsed;
        this.verified = false;
    }

    public Request(Map<String, Object> data) {
        this.route = data.get("route").toString();
        this.method = data.get("method").toString();
        this.data = data;
        this.verified = false;
    }

    void setVerified(boolean verified) { this.verified = verified; }
    boolean isVerified() { return verified; }
    void setUsername(String username) { this.username = username; }
    String getUsername() { return username; }

    @Override
    public String toString() {
        return route + ' ' + method + ' ' + data;
    }
}
