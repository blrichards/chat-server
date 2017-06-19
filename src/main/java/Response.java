import java.io.PrintWriter;
import com.google.gson.Gson;

public class Response {
    public final String status;
    public final String message;
    private static Gson gson = new Gson();

    public Response(String s, String m) {
        status = s;
        message = m;
    }

    public static Response fromJson(String message) {
        if (message == null)
            return null;
        Response response = gson.fromJson(message, Response.class);
        if (response == null) {
            Log.ERROR(message);
        }
        return new Response(response.status.trim(), response.message.trim());
    }

    public static void sendError(PrintWriter w, String err) {
        w.println(gson.toJson(new Response("error", err)));
    }

    public static void sendSuccess(PrintWriter w, String msg) {
        w.println(gson.toJson(new Response("success", msg)));
    }

    @Override
    public String toString() {
        return String.format("\nstatus: %s\nmessage: %s", status, message);
    }
}
