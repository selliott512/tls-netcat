package org.selliott.netcat;

import javax.net.ssl.*;
import java.io.*;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Simple Netcat-like program supporting TLS or unencrypted data. This was mostly written by various AIs.
 */
public class TLSNetcat {
    // Static -  mostly for unit tests.
    static final AtomicLong listenCount = new AtomicLong();
    static volatile Boolean lastServerSocketBoundToAnyInterface = null;
    static volatile Boolean lastSocketIsIPv6 = null;
    static final Object stateLock = new Object();

    // Instance
    private final String[] args;
    private boolean ipv4;
    private boolean ipv6;
    private int blockSize;
    private boolean trustAll;
    private boolean listen;
    private boolean unencrypted;
    private String host;
    private int port;
    private String serverPem;
    private String keyPem;
    private String inputFile;
    private String outputFile;
    private boolean quiet;
    private boolean verbose;
    private boolean wait;

    public TLSNetcat(String[] args) {
        this.args = args;
    }

    /**
     * Create a pipe suitable for calling pipe().
     *
     * @param name          Name of the thread for debugging purposes
     * @param inputStream   InputStream to read from
     * @param outputStream  OutputStream to write to
     * @param socket        The socket being written to, or read from.
     * @param socketWrite   true if this thread is writing to the socket, false if reading from it.
     * @param threadResults BlockingQueue to hold the result of the thread execution
     * @return A Thread that will pipe data between the InputStream and OutputStream.
     */
    private Thread createPipeThread(final String name, final InputStream inputStream,
                                    final OutputStream outputStream,
                                    final Socket socket, boolean socketWrite,
                                    final BlockingQueue<Optional<Exception>> threadResults) {
        final Thread thread = new Thread(() -> {
            log("Starting pipe thread: " + name, true);
            Exception ex = null;
            try {
                pipe(inputStream, outputStream);
                outputStream.flush();
                if (socketWrite) {
                    socket.shutdownOutput(); // Close the output stream if writing to the socket
                } else {
                    socket.shutdownInput(); // Close the input stream if reading from the socket
                }
            } catch (final Exception e) {
                ex = e;
            }
            finally {
                log("Ending pipe thread. ex=" + ex, true);
                threadResults.add(Optional.ofNullable(ex));
            }
        });
        thread.setDaemon(true);
        thread.setName(threadName(name));
        return thread;
    }

    /**
     * Load certificates from a PEM file.
     *
     * @param certPath Path to the PEM file containing the certificates.
     * @return An array of loaded certificates.
     * @throws Exception If there is an error loading the certificates.
     */
    private Certificate[] loadCertificates(final Path certPath) throws Exception {
        try (final InputStream is = Files.newInputStream(certPath)) {
            final CertificateFactory cf = CertificateFactory.getInstance("X.509");
            final List<Certificate> certs = new ArrayList<>();
            for (final Certificate cert : cf.generateCertificates(is)) {
                certs.add(cert);
            }
            if (certs.isEmpty()) {
                throw new IllegalArgumentException("No certificates found in " + certPath);
            }
            return certs.toArray(new Certificate[0]);
        }
    }

    /**
     * Load a private key from a PEM file.
     *
     * @param keyPath Path to the PEM file containing the private key.
     * @return The loaded PrivateKey object.
     * @throws Exception If there is an error loading the private key.
     */
    private PrivateKey loadPrivateKey(final Path keyPath) throws Exception {
        final String pem = new String(Files.readAllBytes(keyPath));
        final String[] lines = pem.replace("\r", "").split("\n");
        final StringBuilder sb = new StringBuilder();
        boolean inKey = false;
        for (String l : lines) {
            if (l.contains("BEGIN PRIVATE KEY")) {
                inKey = true;
            } else if (l.contains("END PRIVATE KEY")) {
                break;
            } else if (inKey) {
                sb.append(l.trim());
            }
        }
        if (sb.length() == 0) {
            throw new IllegalArgumentException("No PRIVATE KEY block found in " + keyPath);
        }
        final byte[] der = Base64.getDecoder().decode(sb.toString());
        final PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (Exception rsa) {
            try {
                return KeyFactory.getInstance("EC").generatePrivate(spec);
            } catch (Exception ec) {
                throw new IllegalArgumentException("Failed to parse private key as RSA or EC", rsa);
            }
        }
    }

    /**
     * Notify that we are listening. This is just for testing so that the test can know that it is safe to start the client.
     */
    private static void notifyListen() {
        synchronized (stateLock) {
            listenCount.incrementAndGet();
            stateLock.notifyAll();
        }
    }

        /**
     * Log a message based on the current logging level.
     * In quiet mode, nothing is logged.
     * In normal mode, normal messages are logged.
     * In verbose mode, both normal and verbose messages are logged.
     *
     * @param message The message to log
     * @param isVerbose true if this is a verbose-only message, false for normal messages
     */
    private void log(final String message, final boolean isVerbose) {
        if (quiet) {
            return;
        }
        if (isVerbose && !verbose) {
            return;
        }
        final String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS"));
        final String threadName = Thread.currentThread().getName();
        System.err.println(timestamp + " [" + threadName + "] " + message);
    }

    /**
     * Log a normal (non-verbose) message.
     *
     * @param message The message to log
     */
    private void log(final String message) {
        log(message, false);
    }

    /**
     * Main method to start the TLSNetcat program.
     *
     * @param args Command line arguments.
     * @throws Exception If there is an error during the execution.
     */
    public static void main(final String[] args) throws Exception {
        new TLSNetcat(args).run();
    }

    /**
     * Pipe data between an InputStream and an OutputStream.
     *
     * @param in        The InputStream to read from.
     * @param out       The OutputStream to write to.
     * @throws IOException If there is an error during the piping process.
     */
    private void pipe(final InputStream in, final OutputStream out) throws IOException {
        final byte[] buf = new byte[blockSize];
        int r;
        while ((r = in.read(buf)) != -1) {
            out.write(buf, 0, r);
        }
    }

    /**
     * Pipe data between a Socket's input and output streams.
     *
     * @param socket    The Socket to read from and write to.
     * @throws Exception If there is an error during the piping process.
     */
    private void pipeBoth(final Socket socket) throws Exception {
        // Threads add their results to this. Blocking so the main thread can wait
        // for the first thread to finish.
        final BlockingQueue<Optional<Exception>> threadResults = new LinkedBlockingQueue<>();

        final InputStream inputStream = (inputFile != null && !inputFile.equals("null")) ?
            new FileInputStream(inputFile) : (inputFile != null ? null : System.in);
        final OutputStream outputStream = (outputFile != null && !outputFile.equals("null")) ?
            new FileOutputStream(outputFile) : (outputFile != null ? null : System.out);

        Thread socketWriteThread = null;
        Thread socketReadThread = null;
        try {
            // Only start socket write thread if we have an input stream
            if (inputStream != null) {
                socketWriteThread = createPipeThread("Socket Write", inputStream, socket.getOutputStream(),
                        socket, true, threadResults);
                socketWriteThread.start();
            }

            // Only start socket read thread if we have an output stream
            if (outputStream != null) {
                socketReadThread = createPipeThread("Socket Read", socket.getInputStream(), outputStream,
                        socket, false, threadResults);
                socketReadThread.start();
            }

            // If both threads are null, we have nothing to do
            if (socketWriteThread == null && socketReadThread == null) {
                return;
            }

            // Count how many threads were actually started
            final int threadCount = (socketWriteThread != null ? 1 : 0) + (socketReadThread != null ? 1 : 0);

            // Warn if user specified -w but only one thread is running
            if (wait && threadCount == 1) {
                log("Warning: -w specified but only one thread running (one file is 'null')");
            }

            // By default, we only care about waiting for the first thread. However, if -w wait is specified then wait
            // for the second thread as well, and check it for exceptions as well.

            final Optional<Exception> firstResult = threadResults.take();
            final Optional<Exception> secondResult = (wait && threadCount == 2) ? threadResults.take() : null;

            final long beforeFirstWaitMillis = System.currentTimeMillis();
            if (firstResult.isPresent()) {
                throw firstResult.get();
            }
            log("First thread wait completed in " +
                    (System.currentTimeMillis() - beforeFirstWaitMillis) + " ms", true);

            final long beforeSecondWaitMillis = System.currentTimeMillis();
            if (wait && threadCount == 2 && secondResult.isPresent()) {
                throw secondResult.get();
            }
            if (wait && threadCount == 2) {
                log("Second thread wait completed in " +
                        (System.currentTimeMillis() - beforeSecondWaitMillis) + " ms", true);
            }
        } finally {
            // Increase the odds of the threads exiting. This is mostly just helpful for the tests which do multiple
            // transfers in a single process. Outside of tests these daemon threads will exit when the process exits.
            if (socketWriteThread != null) {
                socketWriteThread.interrupt();
            }
            if (socketReadThread != null) {
                socketReadThread.interrupt();
            }
        }
    }

    /**
     * Main method to run the TLSNetcat program.
     *
     * @throws Exception If there is an error running the program.
     */
    public void run() throws Exception {
        ipv4 = false;
        ipv6 = false;
        blockSize = 8192;
        trustAll = false;
        listen = false;
        unencrypted = false;
        quiet = false;
        verbose = false;
        wait = false;

        int argIndex = 0;
        for (; argIndex < args.length; argIndex++) {
            final String arg = args[argIndex];
            if (arg.charAt(0) != '-') {
                // Option arguments must be before positional arguments.
                break;
            }
            for (final char option : arg.substring(1).toCharArray()) {
                switch (option) {
                    case '4':
                        ipv4 = true;
                        break;
                    case '6':
                        ipv6 = true;
                        break;
                    case 'b':
                        if (argIndex + 1 >= args.length) {
                            usage("-b requires block size");
                        }
                        blockSize = Integer.parseInt(args[++argIndex]);
                        break;
                    case 'i':
                        if (argIndex + 1 >= args.length) {
                            usage("-i requires input file");
                        }
                        inputFile = args[++argIndex];
                        break;
                    case 'l':
                        listen = true;
                        break;
                    case 'o':
                        if (argIndex + 1 >= args.length) {
                            usage("-o requires output file");
                        }
                        outputFile = args[++argIndex];
                        break;
                    case 'q':
                        quiet = true;
                        break;
                    case 't':
                        trustAll = true;
                        break;
                    case 'u':
                        unencrypted = true;
                        break;
                    case 'v':
                        verbose = true;
                        break;
                    case 'w':
                        wait = true;
                        break;
                    default:
                        usage("Unknown option: " + option);
                }
            }
        }

        // Validate that both -q and -v are not specified together
        if (quiet && verbose) {
            usage("Cannot specify both -q (quiet) and -v (verbose) options");
        }

        // Validate that both -4 and -6 are not specified together
        if (ipv4 && ipv6) {
            usage("Cannot specify both -4 (IPv4) and -6 (IPv6) options");
        }

        // At this point, argIndex should point to the first positional argument.
        final int positionalArgsCount = args.length - argIndex;
        if (listen) {
            if (positionalArgsCount < 1 || positionalArgsCount > 4) {
                usage("Expected 1 to 4 positional arguments in listen mode: [host] port [certs/server.pem [certs/key.pem]]");
            }
        } else {
            if (positionalArgsCount < 2 || positionalArgsCount > 2) {
                usage("Expected 2 positional arguments in connect mode: host port");
            }
        }

        if (listen) {
            // In listen mode, try to determine if first argument is a port (integer) or host (string)
            try {
                // Try to parse first argument as port - if successful, it's any interface mode
                port = Integer.parseInt(args[argIndex]);
                host = null; // Any interface
                argIndex++;
            } catch (NumberFormatException e) {
                // First argument is not a port, so it must be host+port
                if (positionalArgsCount < 2) {
                    usage("Listen mode requires either port or host+port");
                }
                host = args[argIndex++];
                port = Integer.parseInt(args[argIndex++]);
            }
        } else {
            // Connect mode - always requires host and port
            host = args[argIndex++];
            port = Integer.parseInt(args[argIndex++]);
        }
        serverPem = "certs/server.pem";
        keyPem = "certs/key.pem";
        if (argIndex < args.length) {
            if (listen && !unencrypted) {
                if (argIndex < args.length) {
                    serverPem = args[argIndex++];
                    if (argIndex < args.length) {
                        keyPem = args[argIndex++];
                    }
                }
            } else {
                usage("certs/server.pem and certs/key.pem can only be given for encrypted server mode.");
            }
        }

        // Setting the thread name depends on parsing the arguments.
        Thread.currentThread().setName(threadName("Main"));

        if (listen) {
            if (unencrypted) {
                runServerUnencrypted();
            } else {
                runServer();
            }
        } else {
            if (unencrypted) {
                runClientUnencrypted();
            } else {
                runClient();
            }
        }
    }

    /**
     * Run the client in TLS mode.
     *
     * @throws Exception If there is an error during the connection or data transfer.
     */
    private void runClient() throws Exception {
        final SSLContext ctx = SSLContext.getInstance("TLS");
        if (trustAll) {
            final TrustManager[] tms = new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(java.security.cert.X509Certificate[] c, String s) {}
                public void checkServerTrusted(java.security.cert.X509Certificate[] c, String s) {}
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return new java.security.cert.X509Certificate[0];}
            }};
            ctx.init(null, tms, null);
            log("Trusting all server certificates");
        } else {
            ctx.init(null, null, null);
        }
        final InetAddress connectAddress = getConnectionAddress(host);
        try (final SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket(connectAddress, port)) {
            // Note whether the last non-server socket created is IPv6.
            final InetAddress inetAddr = socket.getInetAddress();
            lastSocketIsIPv6 = inetAddr != null && inetAddr instanceof Inet6Address;

            socket.startHandshake();
            log("Connected to " + host + ":" + port);
            pipeBoth(socket);
        }
    }

    /**
     * Run the client in unencrypted mode.
     *
     * @throws Exception If there is an error during the connection or data transfer.
     */
    private void runClientUnencrypted() throws Exception {
        final InetAddress connectAddress = getConnectionAddress(host);
        try (final Socket socket = new Socket(connectAddress, port)) {
            // Note whether the last non-server socket created is IPv6.
            final InetAddress inetAddr = socket.getInetAddress();
            lastSocketIsIPv6 = inetAddr != null && inetAddr instanceof Inet6Address;

            log("Connected to " + host + ":" + port);
            pipeBoth(socket);
        }
    }

    /**
     * Run the server in TLS mode.
     *
     * @throws Exception If there is an error during the server setup or data transfer.
     */
    private void runServer() throws Exception {
        final Path certPath = Paths.get(serverPem);
        final Path keyPath = Paths.get(keyPem);
        if (!Files.exists(certPath)) {
            usage("Certificate file not found: " + certPath);
        }
        if (!Files.exists(keyPath)) {
            usage("Key file not found: " + keyPath);
        }
        final SSLContext ctx = SSLContext.getInstance("TLS");
        final KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        final Certificate[] chain = loadCertificates(certPath);
        final PrivateKey pk = loadPrivateKey(keyPath);
        ks.setKeyEntry("key", pk, new char[0], chain);
        final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);
        ctx.init(kmf.getKeyManagers(), null, null);
        final SSLServerSocketFactory ssf = ctx.getServerSocketFactory();
        final InetAddress bindAddress = getServerBindAddress(host);
        try (SSLServerSocket ss = (SSLServerSocket) ssf.createServerSocket(port, 50, bindAddress)) {
            final InetAddress serverInetAddr = ss.getInetAddress();
            lastServerSocketBoundToAnyInterface = serverInetAddr != null && serverInetAddr.isAnyLocalAddress();
            log("Listening on " + (host != null ? host : "*") + ":" + port);
            notifyListen();
            try (final SSLSocket socket = (SSLSocket) ss.accept()) {
                // Note whether the last non-server socket created is IPv6.
                final InetAddress inetAddr = socket.getInetAddress();
                lastSocketIsIPv6 = inetAddr != null && inetAddr instanceof Inet6Address;

                socket.setUseClientMode(false);
                socket.startHandshake();
                log("Accepted connection from " + socket.getRemoteSocketAddress());
                pipeBoth(socket);
            }
        }
    }

    /**
     * Run the server in unencrypted mode.
     *
     * @throws Exception If there is an error during the server setup or data transfer.
     */
    private void runServerUnencrypted() throws Exception {
        final InetAddress bindAddress = getServerBindAddress(host);
        try (final ServerSocket ss = new ServerSocket(port, 50, bindAddress)) {
            final InetAddress serverInetAddr = ss.getInetAddress();
            lastServerSocketBoundToAnyInterface = serverInetAddr != null && serverInetAddr.isAnyLocalAddress();
            log("Listening on " + (host != null ? host : "*") + ":" + port);
            notifyListen();

            try (final Socket socket = ss.accept()) {
                // Note whether the last non-server socket created is IPv6.
                final InetAddress inetAddr = socket.getInetAddress();
                lastSocketIsIPv6 = inetAddr != null && inetAddr instanceof Inet6Address;

                log("Accepted connection from " + socket.getRemoteSocketAddress());
                pipeBoth(socket);
            }
        }
    }

    /**
     * Gets the appropriate InetAddress for connecting based on IPv4/IPv6 preferences and tracks IP version.
     *
     * @param host The hostname to resolve
     * @return InetAddress with appropriate IP version
     * @throws Exception If hostname resolution fails
     */
    private InetAddress getConnectionAddress(final String host) throws Exception {
        if (ipv4 || ipv6) {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            InetAddress chosenAddress = null;

            // Find address of the preferred type
            for (InetAddress addr : addresses) {
                if (ipv4 && addr instanceof Inet4Address) {
                    chosenAddress = addr;
                    break;
                } else if (ipv6 && addr instanceof Inet6Address) {
                    chosenAddress = addr;
                    break;
                }
            }

            if (chosenAddress == null) {
                throw new Exception("No " + (ipv4 ? "IPv4" : "IPv6") + " address found for host: " + host);
            }

            return chosenAddress;
        } else {
            // No preference specified, use default resolution
            return InetAddress.getByName(host);
        }
    }

    /**
     * Gets the appropriate InetAddress for server binding based on IPv4/IPv6 preferences.
     *
     * @param host The hostname to bind to, or null for any interface
     * @return InetAddress with appropriate IP version, or null for any interface
     * @throws Exception If hostname resolution fails
     */
    private InetAddress getServerBindAddress(final String host) throws Exception {
        if (host == null) {
            // Bind to any interface with IP version preference
            if (ipv4) {
                return Inet4Address.getByName("0.0.0.0");
            } else if (ipv6) {
                return Inet6Address.getByName("::");
            } else {
                return null; // Any interface, any IP version
            }
        } else {
            return getConnectionAddress(host);
        }
    }

    /**
     * A name that uniquely identifies a thread. The class name is used so that threads unique to this process
     * can be distinguished from other Maven and unit test threads. The Listen/Connect is used since it unit
     * tests both may exist in a single process.
     * @param suffix a descriptive suffix for the thread name, such as "Input" or "Output".
     * @return a unique thread name for this class.
     */
    private String threadName(final String suffix) {
        return TLSNetcat.class.getSimpleName() + " " + (listen ? "Listen" : "Connect") + " " + suffix;
    }

    /**
     * Print usage information and exit.
     *
     * @param msg An optional error message to display.
     */
    private void usage(final String msg) {
        if (msg != null) System.err.println("Error: " + msg);
        System.err.println("Usage:");
        System.err.println("  java org.selliott.netcat.TLSNetcat [-b block] [-t] [-u] [-4|-6] host port");
        System.err.println("  java org.selliott.netcat.TLSNetcat [-b block] -l [-u] [-4|-6] [host] port [certs/server.pem " +
                "[certs/key.pem]]");
        System.err.println("Options:");
        System.err.println("  -4          force IPv4");
        System.err.println("  -6          force IPv6");
        System.err.println("  -b block    block size for writes (default 8192)");
        System.err.println("  -i in-file  in-file to use instead of stdin");
        System.err.println("  -l          listen (server mode)");
        System.err.println("  -o out-file out-file to use instead of stdout");
        System.err.println("  -q          quiet mode (no logging)");
        System.err.println("  -t          trust all server certificates (client mode)");
        System.err.println("  -u          unencrypted data (no TLS)");
        System.err.println("  -v          verbose logging");
        System.err.println("  -w          wait for both threads to complete");
        System.exit(1);
    }
}
