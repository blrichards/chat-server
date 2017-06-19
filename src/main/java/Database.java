import com.google.gson.Gson;
import com.sun.istack.internal.Nullable;
import org.springframework.security.crypto.bcrypt.BCrypt;

import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.sql.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Observable;
import java.util.regex.Pattern;

class Database {
    private static Database self;
    private Connection c;

    static void initialize(String database_name, boolean deleteOld) {
        self = new Database(database_name, deleteOld);
    }

    static Connection getConnection() {
        return self.c;
    }

    private Database(String database, boolean deleteOld) {
        File db = new File(database);
        if (db.exists() && deleteOld) {
            boolean wasDeleted = db.delete();
            if (!wasDeleted)
                throw new RuntimeException("For some reason the old database couldn't be deleted...");
        }

        boolean recreateTables = deleteOld || !db.exists();

        try {
            Class.forName("org.sqlite.JDBC");
            c = DriverManager.getConnection("jdbc:sqlite:" + database);
            if (recreateTables) createTables();
            Log.INFO("Opened database successfully");
        } catch ( Exception e ) {
            Log.ERROR(e);
            System.exit(1);
        }
    }

    private void createTables() throws SQLException {
        Statement stmt = c.createStatement();
        String sql =
                "CREATE TABLE 'User' (" +
                        "username  TEXT PRIMARY KEY NOT NULL, " +
                        "password  TEXT             NOT NULL, " +
                        "firstname TEXT             NOT NULL, " +
                        "lastname  TEXT             NOT NULL, " +
                        "joined    DATETIME DEFAULT CURRENT_TIMESTAMP, " +
                        "loggedin  INTEGER          NULL DEFAULT 0); " +

                        "CREATE TABLE 'Group' (" +
                        "ID  INTEGER PRIMARY KEY AUTOINCREMENT, " +
                        "groupname   TEXT NOT NULL, " +
                        "owner       TEXT NOT NULL, " +
                        "description TEXT     NULL, " +
                        "isDirectMessage INTEGER DEFAULT 0, " +
                        "created     DATETIME DEFAULT CURRENT_TIMESTAMP, " +
                        "FOREIGN KEY (owner) REFERENCES 'User'(username)); " +

                        "CREATE TABLE 'GroupMember' (" +
                        "username     TEXT    NOT NULL, " +
                        "groupid  INTEGER NOT NULL, " +
                        "PRIMARY KEY (username, groupid), " +
                        "FOREIGN KEY (username) REFERENCES 'User'(username), " +
                        "FOREIGN KEY (groupid) REFERENCES 'Group'(ID)); " +

                        "CREATE TABLE 'Message' (" +
                        "ID INTEGER PRIMARY KEY AUTOINCREMENT, " +
                        "sender  TEXT    NOT NULL, " +
                        "message TEXT    NOT NULL, " +
                        "groupid INTEGER NOT NULL, " +
                        "sent    DATETIME DEFAULT CURRENT_TIMESTAMP, " +
                        "FOREIGN KEY (groupid) REFERENCES 'Group'(ID), " +
                        "FOREIGN KEY (sender) REFERENCES 'User'(username));";
        stmt.executeUpdate(sql);
        stmt.close();
    }

    static void close() {
        try {
            self.c.close();
        } catch ( Exception e ) {
            Log.ERROR(e);
        }
    }

    static abstract class Table<T extends Table<T>> extends Observable {
        private static final Gson gson = new Gson();
        public static final Map<String, String> tableFields = new HashMap<>();
        private static Class[] tables = { User.class, Group.class, Message.class, GroupMember.class };
        static {
            for (Class table : tables) {
                StringBuilder sb = new StringBuilder();
                for (Field field : table.getDeclaredFields()) {
                    String fieldName = field.getName();
                    if (!Modifier.isStatic(field.getModifiers()) && !Modifier.isTransient(field.getModifiers()))
                        sb.append(fieldName).append(", ");
                }
                sb.delete(sb.lastIndexOf(", "), sb.length());
                tableFields.put(table.getSimpleName(), sb.toString());
            }
        }

        private Class<T> tableClass;
        private Constructor<T> constructor;
        Table(Class<T> tClass) {
            this.tableClass = tClass;
            try {
                constructor = tClass.getDeclaredConstructor();
                constructor.setAccessible(true);
            } catch (NoSuchMethodException e) {
                throw new RuntimeException();
            }
        }
        Table(Class<T> tClass, Map<String, Object> data) {
            this(tClass);
            for (Field field : tableClass.getDeclaredFields()) {
                try { field.set(this, data.get(field.getName())); } catch (Exception e) {}
            }
        }

        static final String insertStatement = "INSERT OR REPLACE INTO '%s' (%s) VALUES (%s);";
        private void add() {
            try {
                Statement stmt = self.c.createStatement();
                final String fields = tableFields.get(tableClass.getSimpleName());

                final StringBuilder values = new StringBuilder();
                for (Field field : tableClass.getDeclaredFields()) {
                    if (Modifier.isStatic(field.getModifiers()) || Modifier.isTransient(field.getModifiers()))
                        continue;
                    Object value = field.get(this);
                    if (value instanceof String)
                        values.append('\'').append(value).append("', ");
                    else if (value instanceof Integer)
                        values.append(value).append(", ");
                    else if (value instanceof Boolean)
                        values.append((Boolean)value ? 1 : 0).append(", ");
                }
                values.delete(values.length() - 2, values.length());

                String sql = String.format(insertStatement, tableClass.getSimpleName(), fields, values.toString());
                stmt.execute(sql);
                stmt.close();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        static final String queryStatement = "SELECT * FROM '%s'%s;";
        @SuppressWarnings("unchecked")
        ArrayList<T> get(@Nullable String condition) {
            try {
                Statement stmt = self.c.createStatement();
                String sql = String.format(queryStatement, tableClass.getSimpleName(), condition == null ? "" : " WHERE " + condition);
                ResultSet rs = stmt.executeQuery(sql);
                stmt.closeOnCompletion();

                ArrayList<T> results = new ArrayList<>();
                while (rs.next()) {
                    results.add(constructor.newInstance().initFromQuery(rs));
                }
                return results;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        Map<String, Object> getInfo() {
            Map<String, Object> info = new HashMap<>();

            for (Field field : tableClass.getDeclaredFields()) {
                try { info.put(field.getName(), field.get(this)); } catch (Exception e) {}
            }

            if (tableClass.getSimpleName().equals("User"))
                info.remove("password");

            return info;
        }

        static final String deleteStatement = "DELETE FROM '%s' WHERE %s;";
        void deleteFromDatabase() {
            try {
                StringBuilder condition = new StringBuilder();
                for (String primaryKey : getPrimaryKey()) {
                    Object value = tableClass.getDeclaredField(primaryKey).get(this);
                    if (value instanceof String)
                        condition.append(primaryKey).append(" = '").append(value).append("', ");
                    else if (value instanceof Integer)
                        condition.append(primaryKey).append(" = ").append(value).append(", ");
                }
                condition.delete(condition.length() - 2, condition.length());
                Statement stmt = self.c.createStatement();
                String sql = String.format(deleteStatement, tableClass.getSimpleName(), condition.toString());
                stmt.execute(sql);
                stmt.close();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        String addToDatabase() {
            String err = isValid();
            if (err != null) return err;
            if (this instanceof User) {
                User user = (User)this;
                String pass = user.password;
                user.password = BCrypt.hashpw(user.password, BCrypt.gensalt());
                add();
                user.password = pass;
            } else {
                add();
            }
            return null;
        }

        T initFromQuery(ResultSet rs) throws Exception {
            T instance = constructor.newInstance();
            for (Field field : tableClass.getDeclaredFields()) {
                if (field.getName().equals("isDirectMessage"))
                    field.set(instance, rs.getBoolean(field.getName()));
                else if (!Modifier.isStatic(field.getModifiers()))
                    field.set(instance, rs.getObject(field.getName()));
            }
            return instance;
        }

        abstract String isValid();
        abstract String[] getPrimaryKey();
    }
}

class User extends Database.Table<User> {
    private static final User self = new User();
    private static final String[] primaryKeys = { "username" };

    /** Table Columns **/
    String username;
    String password;
    String firstname;
    String lastname;

    private User() { super(User.class); }
    User(Map<String, Object> data) { super(User.class, data); }
    User(String username, String password, String firstname, String lastname) {
        this();
        this.username = username;
        this.password = password;
        this.firstname = firstname;
        this.lastname = lastname;
    }

    @Override
    String addToDatabase() {
        String err = super.addToDatabase();
        if (err != null)
            return err;

        for (GroupMember member : GroupMember.getGroups(username)) {
            Group group = Group.getGroup(member.groupid);
            if (group.isDirectMessage) {
                ArrayList<GroupMember> members = GroupMember.getMembers(group.ID);
                if (members.size() == 2) {
                    User user1 = User.getUser(members.get(0).username);
                    User user2 = User.getUser(members.get(1).username);
                    if (user1 != null && user2 != null) {
                        group.groupname = user1.firstname + "::" +
                                user1.username + "::" +
                                user1.lastname +
                                user2.firstname + "::" +
                                user2.username + "::" +
                                user2.lastname;
                        try {
                            Statement stmt = Database.getConnection().createStatement();
                            String sql = "UPDATE 'Group' SET groupname = '" + group.groupname + "' WHERE ID = " + group.ID + ";";
                            stmt.execute(sql);
                            stmt.close();
                        } catch (SQLException e) {
                            Log.ERROR(e);
                        }
                    }
                }
            }
        }
        return null;
    }

    @Override
    public String toString() {
        return String.format("Username: %s - Password: %s - First Name: %s - Last Name: %s", username, password, firstname, lastname);
    }

    String isValid() {
        final Pattern validPassword = Pattern.compile("(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*(_|[^\\w])).{6,}");
        final Pattern validUsername = Pattern.compile("[\\w|_]{6,20}");

        StringBuilder err = new StringBuilder("");
        if (!validUsername.matcher(username).find())
            err.append("Username must be between 5 and 20 characters. Valid characters include all alphanumeric characters and hyphens ('-').\n");
        if (!validPassword.matcher(password).find())
            err.append("Password must be greater than 6 characters and include at least one lowercase letter, uppercase letter, number, and symbol.");
        if (firstname.equals(""))
            err.append("First name is required.\n");
        if (lastname.equals(""))
            err.append("Last name is required.\n");

        return err.toString().equals("") ? null : err.toString();
    }

    String[] getPrimaryKey() { return primaryKeys; }

    static User getUser(String username) {
        try {
            return self.get("username = '" + username + "'").iterator().next();
        } catch (Exception e) {
            return null;
        }
    }

    static void deleteUser(String username) {
        User user = new User();
        user.username = username;
        user.deleteFromDatabase();
    }

    static ArrayList<User> list() {
        return self.get(null);
    }
}

class Group extends Database.Table<Group> {
    private static final Group self = new Group();
    private static final String[] primaryKeys = { "ID" };

    transient int ID;
    String owner;
    String groupname;
    String description = "";
    Boolean isDirectMessage;

    private static Map<Integer, Group> groupChats = new HashMap<>();

    private Group() { super(Group.class); }
    Group(Map<String, Object> data) { super(Group.class, data); }

    String isValid() {
        String err = "";
        if (User.getUser(owner) == null)
            err += "Owner of group does not exist.\n";
        if (groupname.length() < 1)
            err += "Groupname cannot be empty.\n";
        if (Group.getID(groupname, owner) != null)
            err += "You already own a group named " + groupname;
        return err.equals("") ? null : err;
    }

    String[] getPrimaryKey() {
        return primaryKeys;
    }

    String addToDatabase(ArrayList<String> members) {
        StringBuilder err = new StringBuilder();
        for (String member : members)
            if (User.getUser(member) == null)
                err.append("User (").append(member).append(") doesn't exist.\n");
        if (err.length() != 0)
            return err.toString();

        String databaseError = super.addToDatabase();
        if (databaseError != null)
            err.append(databaseError);

        if (err.length() == 0) {
            Integer groupID = getID(groupname, owner);
            if (groupID == null)
                throw new RuntimeException();
            ID = groupID;
            groupChats.put(ID, this);
            members.forEach(this::addMember);
            return null;
        }
        return err.toString();
    }

    private void addMember(String username) {
        new GroupMember(username, ID).addToDatabase();
        if (ServerMain.ClientHandler.clientHandlers.containsKey(username)) {
            ensureGroup(ID);
            groupChats.get(ID).addObserver(ServerMain.ClientHandler.clientHandlers.get(username));
        }
    }

    static Integer getID(String groupname, String owner) {
        ArrayList<Group> groups = self.get(String.format("groupname = '%s' AND owner = '%s'", groupname, owner));
        return groups.size() == 1 ? groups.get(0).ID : null;
    }

    static ArrayList<Group> list() {
        return self.get(null);
    }

    static ArrayList<Group> withName(String groupname) {
        return self.get("groupname = '" + groupname + "'");
    }

    static Group getGroup(int ID) {
        try {
            return self.get("ID = " + ID).iterator().next();
        } catch (Exception e) {
            throw new RuntimeException();
        }
    }

    private static void ensureGroup(int ID) {
        if (!groupChats.containsKey(ID))
            groupChats.put(ID, Group.getGroup(ID));
    }

    static void addListener(ServerMain.ClientHandler clientHandler) {
        ArrayList<GroupMember> groups = GroupMember.getGroups(clientHandler.username);
        for (GroupMember group : groups) {
            ensureGroup(group.groupid);
            groupChats.get(group.groupid).addObserver(clientHandler);
        }
    }

    static void newMessage(Message message) {
        ensureGroup(message.groupid);
        groupChats.get(message.groupid).setChanged();
        groupChats.get(message.groupid).notifyObservers(message);
        message.addToDatabase();
    }
}

class GroupMember extends Database.Table<GroupMember> {
    private static final GroupMember self = new GroupMember();
    private static final String[] primaryKeys = { "user", "groupid" };

    String username;
    int groupid;

    private GroupMember() {
        super(GroupMember.class);
    }

    GroupMember(String user, int groupid) {
        this();
        this.username = user;
        this.groupid = groupid;
    }

    String isValid() {
        String err = "";
        if (User.getUser(username) == null)
            err += "User does not exist";
        if (Group.getGroup(groupid) == null)
            err += "That group doesn't exist";
        return err.equals("") ? null : err;
    }

    String[] getPrimaryKey() {
        return primaryKeys;
    }

    static ArrayList<GroupMember> getGroups(String username) {
        try {
            return self.get("username = '" + username + "'");
        } catch (Exception e) {
            throw new RuntimeException();
        }
    }

    static ArrayList<GroupMember> getMembers(int groupname) {
        try {
            return self.get("groupid = " + groupname);
        } catch (Exception e) {
            throw new RuntimeException();
        }
    }
}

class Message extends Database.Table<Message> {
    private static final Message self = new Message();
    private static final String[] primaryKeys = { "ID" };

    String sender;
    String message;
    int groupid;
    transient int ID;

    private Message() { super(Message.class); }
    Message(Map<String, Object> data) {
        this();
        sender = data.get("sender").toString();
        message = data.get("message").toString();
        groupid = ((Double)data.get("groupid")).intValue();
    }

    String isValid() {
        String err = "";
        if (User.getUser(sender) == null)
            err += "That user doesn't exist";
        if (Group.getGroup(groupid) == null)
            err += "That group doesn't exist";
        return err.equals("") ? null : err;
    }

    String[] getPrimaryKey() {
        return primaryKeys;
    }

    static ArrayList<Message> list(int groupid, int num) {
        return self.get("groupid = " + groupid + " LIMIT " + num);
    }

    static ArrayList<Message> list(String username) {
        ArrayList<GroupMember> groups = GroupMember.getGroups(username);
        ArrayList<Message> messages = new ArrayList<>();
        for (GroupMember group : groups)
            messages.addAll(list(group.groupid, 100));
        return messages;
    }

    @Override
    public String toString() {
        return String.format("sender: %s - groupid: %d - message: %s", sender, groupid, message);
    }
}
