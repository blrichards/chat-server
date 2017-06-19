import java.text.SimpleDateFormat;

class Log {

    private static void flush() {
        System.out.flush();
        System.err.flush();
    }

    static void INFO(Object message) {
        flush();
        System.out.println("" + '[' + new SimpleDateFormat("MM/dd/yyyy HH:mm:ss").format(new java.util.Date()) + ']' + ": " + message);
    }

    static void ERROR(Object message) {
        flush();
        System.err.println("" + '[' + new SimpleDateFormat("MM/dd/yyyy HH:mm:ss").format(new java.util.Date()) + ']' + ": " + message);
        if (message instanceof Exception) {
            ((Exception) message).printStackTrace();
            throw new RuntimeException();
        }
    }
}
