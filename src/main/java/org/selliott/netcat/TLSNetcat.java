package org.selliott.netcat;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
    // Static
    static AtomicLong listenCount = new AtomicLong();

    // Instance
    private final String[] args;
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

    public TLSNetcat(String[] args) {
        this.args = args;
    }

    /**
     * Create a pipe suitable for calling pipe().
     * @param inputStream InputStream to read from
     * @param outputStream OutputStream to write to
     * @param name Name of the thread for debugging purposes
     * @param threadResults BlockingQueue to hold the result of the thread execution
     * @return A Thread that will pipe data between the InputStream and OutputStream.
     */
    private Thread createPipeThread(final InputStream inputStream,
                                           final OutputStream outputStream, final String name,
                                           final BlockingQueue<Optional<Exception>> threadResults) {
        final Thread thread = new Thread(() -> {
            log("[TLSNetcat] Starting pipe thread: " + name, true);
            Exception ex = null;
            try {
                pipe(inputStream, outputStream);
            } catch (final Exception e) {
                ex = e;
            }
            finally {
                log("[TLSNetcat] Ending pipe thread: " + name, true);
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
        } catch (Exception e) {
            return KeyFactory.getInstance("EC").generatePrivate(spec);
        }
    }

    /**
     * Notify that we are listening. This is just for testing so that the test can know that it is safe to start the client.
     */
    private static void notifyListen() {
        synchronized (listenCount) {
            listenCount.incrementAndGet();
            listenCount.notifyAll();
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
        System.err.println(message);
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
            out.flush();
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

        final InputStream inputStream = inputFile != null ? new FileInputStream(inputFile) : System.in;
        final OutputStream outputStream = outputFile != null ? new FileOutputStream(outputFile) : System.out;

        try {
            final Thread stdinThread = createPipeThread(inputStream, socket.getOutputStream(), "Socket Write",
                    threadResults);
            stdinThread.start();

            final Thread stdoutThread = createPipeThread(socket.getInputStream(), outputStream, "Socket Read",
                    threadResults);
            stdoutThread.start();

            // Get the first result from threadResults and act on it. We don't care
            // about the second thread's result since it is just a result of the socket
            // being closed.
            final Optional<Exception> firstResult = threadResults.take();
            if (firstResult.isPresent()) {
                throw firstResult.get();
            }
        } finally {
            if (inputFile != null && inputStream != System.in) {
                inputStream.close();
            }
            if (outputFile != null && outputStream != System.out) {
                outputStream.close();
            }
        }
    }

    /**
     * Main method to run the TLSNetcat program.
     *
     * @throws Exception If there is an error running the program.
     */
    public void run() throws Exception {
        blockSize = 8192;
        trustAll = false;
        listen = false;
        unencrypted = false;
        quiet = false;
        verbose = false;

        int argIndex = 0;
        for (; argIndex < args.length; argIndex++) {
            final String arg = args[argIndex];
            if (arg.charAt(0) != '-') {
                // Option arguments must be before positional arguments.
                break;
            }
            for (final char option : arg.substring(1).toCharArray()) {
                switch (option) {
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
                    default:
                        usage("Unknown option: " + option);
                }
            }
        }

        // Validate that both -q and -v are not specified together
        if (quiet && verbose) {
            usage("Cannot specify both -q (quiet) and -v (verbose) options");
        }

        // At this point, argIndex should point to the first positional argument.
        final int positionalArgsCount = args.length - argIndex;
        if (positionalArgsCount < 2 || positionalArgsCount > 4) {
            usage("Expected 2 to 4 positional arguments: host port [certs/server.pem [certs/key.pem]]");
        }

        host = args[argIndex++];
        port = Integer.parseInt(args[argIndex++]);
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
            log("[TLSNetcat] Trusting all server certificates");
        } else {
            ctx.init(null, null, null);
        }
        try (final SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket(host, port)) {
            socket.startHandshake();
            log("[TLSNetcat] Connected to " + host + ":" + port);
            pipeBoth(socket);
        }
    }

    /**
     * Run the client in unencrypted mode.
     *
     * @throws Exception If there is an error during the connection or data transfer.
     */
    private void runClientUnencrypted() throws Exception {
        try (final Socket socket = new Socket(host, port)) {
            log("[TLSNetcat] Connected to " + host + ":" + port);
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
        try (SSLServerSocket ss = (SSLServerSocket) ssf.createServerSocket(port, 50,
                InetAddress.getByName(host))) {
            log("[TLSNetcat] Listening on " + host + ":" + port);
            notifyListen();
            try (final SSLSocket socket = (SSLSocket) ss.accept()) {
                socket.setUseClientMode(false);
                socket.startHandshake();
                log("[TLSNetcat] Accepted connection from " + socket.getRemoteSocketAddress());
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
        try (final ServerSocket ss = new ServerSocket(port, 50, InetAddress.getByName(host))) {
            log("[TLSNetcat] Listening on " + host + ":" + port);
            notifyListen();

            try (final Socket socket = ss.accept()) {
                log("[TLSNetcat] Accepted connection from " + socket.getRemoteSocketAddress());
                pipeBoth(socket);
            }
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
        System.err.println("  java org.selliott.netcat.TLSNetcat [-b block] [-t] [-u] host port");
        System.err.println("  java org.selliott.netcat.TLSNetcat [-b block] -l [-u] host port [certs/server.pem " +
                "[certs/key.pem]]");
        System.err.println("Options:");
        System.err.println("  -b block    block size for writes (default 8192)");
        System.err.println("  -i in-file  in-file to use instead of stdin");
        System.err.println("  -l          listen (server mode)");
        System.err.println("  -o out-file out-file to use instead of stdout");
        System.err.println("  -q          quiet mode (no logging)");
        System.err.println("  -t          trust all server certificates (client mode)");
        System.err.println("  -u          unencrypted data (no TLS)");
        System.err.println("  -v          verbose logging");
        System.exit(1);
    }
}
