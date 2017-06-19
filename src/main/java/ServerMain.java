import com.esotericsoftware.yamlbeans.YamlReader;
import com.google.gson.Gson;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.*;

public class ServerMain implements Runnable {
    private static ServerMain self;
    public int port;
    public String database;
    public Boolean delete_old_db;
    public String secret_key;

    public static void main(String[] args) {
        System.out.println(ServerMain.class.getName());
        try {
            YamlReader reader = new YamlReader(new FileReader("config.yaml"));
            self = reader.read(ServerMain.class);
        } catch (Exception e) {
            Log.INFO("Config file couldn't be found. Using default values (port: 4242, database: chat.db)");
            self = new ServerMain();
            self.port = 4242;
            self.database = "chat.db";
            self.secret_key = "fiqwep8f9jqwpieuhfpwnejm=e-90qwefunqw=e0f9=qweufpmqwefmqw9ef";
        }
        self.run();
    }

    String generateToken(String subject) {
        return Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS512, secret_key).compact();
    }

    void checkToken(Request req, String subject) {
        if (subject == null || req.auth_token == null)
            return;
        String username = Jwts.parser().setSigningKey(secret_key).parseClaimsJws(req.auth_token).getBody().getSubject();
        if (username.equals(subject)) {
            req.setUsername(username);
            req.setVerified(true);
        }
    }

    static ServerMain instance() {
        return self;
    }

    @SuppressWarnings("InfiniteLoopStatement")
    @Override
    public void run() {
        Database.initialize(database, delete_old_db);
        int clientCount = 0;
        try (ServerSocket server = new ServerSocket(port)) {
            Log.INFO("Server listening on port " + port);
            while (true) {
                try {
                    Socket sock = server.accept();
                    new Thread(new ClientHandler(sock, clientCount++)).start();
                } catch (IOException e) {
                    Log.ERROR(e);
                }
            }
        } catch (IOException e) {
            Log.ERROR(e);
        } finally {
            Database.close();
        }
    }

    public static class ClientHandler implements Runnable, Observer {
        private static final Gson gson = new Gson();
        static final HashMap<String, ClientHandler> clientHandlers = new HashMap<>();

        BufferedReader reader;
        PrintWriter writer;
        Socket sock;
        int clientId;
        String username;

        ClientHandler(Socket socket, int id) throws IOException {
            clientId = id;
            reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            writer = new PrintWriter(socket.getOutputStream(), true);
            sock = socket;
            username = null;
        }

        static void notify(String username, String message) {
            if (clientHandlers.containsKey(username))
                clientHandlers.get(username).writer.println(message);
        }

        @Override
        public void run() {
            Log.INFO("New client connection opened (id=" + clientId + ")");
            try {
                String message;
                while ((message = reader.readLine()) != null) {
                    Request request = new Request(message);
                    Log.INFO(request);
                    instance().checkToken(request, username);

                    Multiplexer.Status status = Multiplexer.handle(writer, request);
                    switch (status.type) {
                        case NEW_USER:
                        case SIGNED_IN:
                            username = status.message;
                            clientHandlers.put(username, this);
                            Group.addListener(this);
                            break;
                        case SIGNED_OUT:
                            clientHandlers.remove(username, this);
                            try {
                                reader.close();
                                writer.close();
                                sock.close();
                                return;
                            } catch (Exception e) {
                                Log.ERROR("Socket couldn't be closed for some reason.");
                            }
                            break;
                    }
                }
            } catch (IOException e) {
                Log.INFO("Connection closed by client (id=" + clientId + ")");
            } finally {
                try {
                    reader.close();
                    writer.close();
                    sock.close();
                    Log.INFO("Connection to client (id=" + clientId + ") was closed");
                } catch (Exception e) {
                    Log.ERROR(e);
                }
            }
        }

        public void update(Observable observable, Object object) {
            assert observable instanceof Group;
            assert object instanceof Message;
            Message message = (Message)object;

            Map<String, Object> payload = new HashMap<>();
            payload.put("groupid", message.groupid);
            payload.put("sender", message.sender);
            payload.put("message", message.message);

            Response notification = new Response("new-message", gson.toJson(payload));
            writer.println(gson.toJson(notification));
        }
    }
}
