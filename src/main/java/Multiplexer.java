import com.google.gson.Gson;
import org.springframework.security.crypto.bcrypt.BCrypt;

import java.io.PrintWriter;
import java.util.*;

class Multiplexer {

    private static Gson gson = new Gson();

    enum StatusType {SUCCESS, ERROR, NEW_USER, SIGNED_IN, SIGNED_OUT}

    static class Status {
        final StatusType type;
        final String message;

        Status(StatusType type, String message) {
            this.type = type;
            this.message = message;
        }

        Status(StatusType type) {
            this.type = type;
            this.message = null;
        }
    }

    static Status handle(PrintWriter w, Request req) {
        try {
            switch (req.route) {
                case "/users":
                    return users(w, req);
                case "/groups":
                    return groups(w, req);
                case "/chats":
                    return chats(w, req);
                case "/auth":
                    return auth(w, req);
                default:
                    Response.sendError(w, "Invalid route");
                    Log.ERROR(req);
            }
        } catch (Exception e) {
            Response.sendError(w, "invalid route");
            Log.ERROR(e);
            return new Status(StatusType.ERROR, "invalid route");
        }
        return new Status(StatusType.ERROR, "Something went wrong");
    }

    private static Status auth(PrintWriter w, Request req) {
        String err = null;
        User user, check;
        try {
            switch (req.method) {
                case Request.MethodPost:
                    check = User.getUser((String)req.data.get("username"));
                    if (check == null) {
                        user = new User(req.data);
                        err = user.addToDatabase();
                        if (err == null) {
                            Response.sendSuccess(w, ServerMain.instance().generateToken(user.username));
                            return new Status(StatusType.NEW_USER, user.username);
                        }
                    } else {
                        err = "Sorry that username has already been taken";
                    }
                    break;
                case Request.MethodPut:
                    user = new User(req.data);
                    check = User.getUser(user.username);
                    if (check != null && BCrypt.checkpw(user.password, check.password)) {
                        Response.sendSuccess(w, ServerMain.instance().generateToken(user.username));
                        return new Status(StatusType.NEW_USER, user.username);
                    }
                    err = "Invalid username or password";
                    break;
                case Request.MethodDelete:
                    if (req.isVerified()) {
                        Response.sendSuccess(w, "User successfully signed out");
                        return new Status(StatusType.SIGNED_OUT);
                    }
                    err = "Bad credentials";
                    break;
                default:
                    err = "Invalid method for route '/auth'";
            }
        } catch (Exception e) {
            Log.ERROR(e);
            err = "invalid request";
        }
        Response.sendError(w, err);
        return new Status(StatusType.ERROR);
    }

    private static Status users(PrintWriter w, Request req) {
        if (!req.isVerified()) {
            Response.sendError(w, "Bad credentials");
            return new Status(StatusType.ERROR, "Bad credentials");
        }

        String err;
        User user;
        try {
            switch (req.method) {
                case Request.MethodGet:
                    user = User.getUser(req.data.get("username").toString());
                    if (user == null) {
                        err = "No user with the username " + req.getUsername() + " exists.";
                    } else {
                        Response.sendSuccess(w, gson.toJson(user.getInfo()));
                        return new Status(StatusType.SUCCESS);
                    }
                    break;
                case Request.MethodPut:
                    user = new User(req.data);

                    err = user.addToDatabase();
                    if (err == null) {
                        Response.sendSuccess(w, "User info has been updated.");
                        return new Status(StatusType.SUCCESS);
                    }
                    break;
                case Request.MethodDelete:
                    User.deleteUser(req.getUsername());
                    Response.sendSuccess(w, "User has been successfully deleted.");
                    return new Status(StatusType.SIGNED_OUT);
                default:
                    err = "Invalid method for route '/users'";
            }
        } catch (Exception e) {
            Log.ERROR(e);
            err = "invalid request";
        }
        Response.sendError(w, err);
        return new Status(StatusType.ERROR, "");
    }

    @SuppressWarnings("unchecked")
    private static Status groups(PrintWriter w, Request req) {
        if (!req.isVerified()) {
            Response.sendError(w, "Bad credentials.");
            return new Status(StatusType.ERROR, "bad auth token");
        }

        try {
            switch (req.method) {
                case Request.MethodPost:
                    Group group = new Group(req.data);
                    group.owner = req.getUsername();
                    ArrayList<String> members = (ArrayList<String>)req.data.get("members");
                    String err = group.addToDatabase(members);
                    if (err != null) {
                        Response.sendError(w, err);
                        Log.ERROR(err);
                        return new Status(StatusType.ERROR, err);
                    }

                    Map<String, Object> payload = new HashMap<>();
                    payload.put("ID", group.ID);
                    payload.put("groupname", group.groupname);
                    payload.put("isDirectMessage", group.isDirectMessage);
                    Response.sendSuccess(w, gson.toJson(payload));

                    Response notification = new Response("new-group", gson.toJson(payload));
                    Set<String> notified = new HashSet<>();
                    members.forEach(member -> {
                        if (!notified.contains(member)) {
                            ServerMain.ClientHandler.notify(member, gson.toJson(notification));
                            notified.add(member);
                        }
                    });

                    return new Status(StatusType.SUCCESS, "new group: " + group.ID + group.groupname);
                case Request.MethodGet:
                    ArrayList<Map<String, Object>> groups = new ArrayList<>();

                    for (GroupMember oldGroup : GroupMember.getGroups(req.getUsername())) {
                        Group g = Group.getGroup(oldGroup.groupid);
                        payload = new HashMap<>();
                        payload.put("ID", g.ID);
                        payload.put("groupname", g.groupname);
                        payload.put("isDirectMessage", g.isDirectMessage);
                        groups.add(payload);
                    }
                    Response groupNotice = new Response("groups", gson.toJson(groups));
                    w.println(gson.toJson(groupNotice));
                    return new Status(StatusType.SUCCESS);
            }
        } catch (Exception e) {
            throw new RuntimeException();
        }
        Response.sendError(w, "Bad request");
        return new Status(StatusType.ERROR, "Bad request");
    }

    private static Status chats(PrintWriter w, Request req) {
        if (!req.isVerified()) {
            Response.sendError(w, "Bad credentials.");
            return new Status(StatusType.ERROR, "bad auth token");
        }

        try {
            switch (req.method) {
                case Request.MethodPost:
                    Message message = new Message(req.data);
                    Group.newMessage(message);
                    return new Status(StatusType.SUCCESS, "getMessage sent: " + message);
                case Request.MethodGet:
                    ArrayList<Map<String, Object>> messages = new ArrayList<>();
                    for (Message oldMessage : Message.list(req.getUsername())) {
                        Map<String, Object> payload = new HashMap<>();
                        payload.put("groupid", oldMessage.groupid);
                        payload.put("sender", oldMessage.sender);
                        payload.put("message", oldMessage.message);
                        messages.add(payload);
                    }
                    Response notify = new Response("messages", gson.toJson(messages));
                    w.println(gson.toJson(notify));
                    return new Status(StatusType.SUCCESS, "messages sent");
            }
        } catch (Exception e) {
            Log.ERROR(e);
            throw new RuntimeException();
        }
        Response.sendError(w, "Bad request");
        return new Status(StatusType.ERROR, "Bad request");
    }
}
