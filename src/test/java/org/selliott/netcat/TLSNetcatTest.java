package org.selliott.netcat;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.*;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.logging.Logger;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * Test class for TLSNetcat.
 */
public class TLSNetcatTest
{
    private static final Logger logger = Logger.getLogger(TLSNetcatTest.class.getName());
    /**
     * Default file size for testing. This is the size of the file that will be created
     */
    public static final int DEFAULT_FILE_SIZE = 100000;

    /**
     * Test case configuration holding server and client argument templates
     */
    public static class TestCase {
        final String name;
        final String[] serverArgsTemplate;
        final String[] clientArgsTemplate;

        public TestCase(String name, String[] serverArgsTemplate, String[] clientArgsTemplate) {
            this.name = name;
            this.serverArgsTemplate = serverArgsTemplate;
            this.clientArgsTemplate = clientArgsTemplate;
        }

        @Override
        public String toString() {
            return name;
        }
    }

    /**
     * Provides test cases for different TLSNetcat configurations
     */
    static Stream<Arguments> testCases() {
        return Stream.of(
            Arguments.of(new TestCase(
                "Unencrypted",
                new String[]{"-o", "{outputFile}", "-u", "-l", "{host}", "{port}"},
                new String[]{"-i", "{inputFile}", "-u", "{host}", "{port}"}
            )),
            Arguments.of(new TestCase(
                "Encrypted (TLS)",
                new String[]{"-o", "{outputFile}", "-l", "{host}", "{port}", "certs/server.pem", "certs/key.pem"},
                new String[]{"-i", "{inputFile}", "-t", "{host}", "{port}"}
            ))
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("testCases")
    public void testBasics(TestCase testCase, @TempDir Path tempDir) throws Exception {
        final long startTime = System.currentTimeMillis();
        logger.info("Starting test case: " + testCase.name);
        // Test data that will be transferred.
        final byte[] testData = generateRandomData(DEFAULT_FILE_SIZE);

        // Temporary files. Note that the input file will have data now whereas the output file will be created
        // and filled with the same data as a result of invoking TLSNetcat.
        final Path inputFile = tempDir.resolve("input.dat");
        Files.write(inputFile, testData);
        final Path outputFile = tempDir.resolve("output.dat");

        // Use localhost and a dynamically assigned port.
        final String host = "localhost";
        final int port = findAvailablePort();

        final ExecutorService executor = Executors.newFixedThreadPool(2);
        final CountDownLatch serverStarted = new CountDownLatch(1);
        final CountDownLatch dataTransferred = new CountDownLatch(1);

        final long initialListenCount = TLSNetcat.listenCount.get();

        final Future<?> serverTask = executor.submit(() -> {
            try {
                serverStarted.countDown();
                final String[] serverArgs = buildArgs(testCase.serverArgsTemplate, inputFile, outputFile, host, port);
                TLSNetcat.main(serverArgs);
                dataTransferred.countDown();
            } catch (Exception e) {
                throw new RuntimeException("Server error", e);
            }
        });

        final Future<?> clientTask = executor.submit(() -> {
            try {
                assertTrue(serverStarted.await(5, TimeUnit.SECONDS), "Server should start");

                // Wait for the server to be listening.
                synchronized (TLSNetcat.listenCount) {
                    while (initialListenCount == TLSNetcat.listenCount.get()) {
                        TLSNetcat.listenCount.wait(60_000);
                    }
                }

                final String[] clientArgs = buildArgs(testCase.clientArgsTemplate, inputFile, outputFile, host, port);
                TLSNetcat.main(clientArgs);
            } catch (Exception e) {
                throw new RuntimeException("Client error", e);
            }
        });

        clientTask.get(10, TimeUnit.SECONDS);
        assertTrue(dataTransferred.await(5, TimeUnit.SECONDS), "Data transfer should complete");
        serverTask.get(1, TimeUnit.SECONDS);

        executor.shutdown();

        assertTrue(Files.exists(outputFile), "Output file should exist");
        final byte[] receivedData = Files.readAllBytes(outputFile);
        assertEquals(testData.length, receivedData.length,
            "Received data length should match sent data length");
        assertArrayEquals(testData, receivedData, "Sent and received data should be identical");

        final long endTime = System.currentTimeMillis();
        final long duration = endTime - startTime;
        logger.info("Completed test case: " + testCase.name + " in " + duration + " ms");
    }

    /**
     * Generates random data of the specified size.
     *
     * @param size The size of the data to generate.
     * @return A byte array filled with random data.
     */
    private byte[] generateRandomData(int size) {
        byte[] data = new byte[size];
        new Random().nextBytes(data);
        return data;
    }

    /**
     * Finds an available port on the localhost by creating a temporary server socket.
     *
     * @return An available port number.
     * @throws IOException If an I/O error occurs while creating the socket.
     */
    private int findAvailablePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    /**
     * Builds argument array by replacing placeholders with actual values
     */
    private String[] buildArgs(String[] template, Path inputFile, Path outputFile, String host, int port) {
        String[] args = new String[template.length];
        for (int i = 0; i < template.length; i++) {
            args[i] = template[i]
                .replace("{inputFile}", inputFile.toString())
                .replace("{outputFile}", outputFile.toString())
                .replace("{host}", host)
                .replace("{port}", String.valueOf(port));
        }
        return args;
    }
}
