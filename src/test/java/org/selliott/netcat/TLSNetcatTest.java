package org.selliott.netcat;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.*;
import java.net.ServerSocket;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Random;
import java.util.concurrent.atomic.AtomicReference;
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
    // *** Constants and static variables ***

    /**
     * Default file size for testing. This is the size of the file that will be created
     */
    public static final int DEFAULT_FILE_SIZE = 100000;

    /**
     * A timeout that is generally much longer than it actually take. If this
     * timeout is reached, the test will be noticably slow.
     */
    public static final int LONG_TIMEOUT_SECONDS = 30;
    public static final int LONG_TIMEOUT_MILLIS = LONG_TIMEOUT_SECONDS * 1000;

    // *** Fields ***

    /**
     * Shared test data generated once for all test cases
     */
    private static byte[] sharedTestData;

    /**
     * Shared test data (twice as big) for bidirectional tests
     */
    private static byte[] sharedTestDataBig;

    // *** Test methods ***

    /**
     * Initialize shared test data once before all tests
     */
    @BeforeAll
    static void initializeTestData() {
        sharedTestData = generateRandomData(DEFAULT_FILE_SIZE);
        sharedTestDataBig = generateRandomData(DEFAULT_FILE_SIZE * 5);
    }

    /**
     * Test case configuration holding server and client argument templates
     */
    public static class TestCase {
        final String name;
        final boolean active; // Whether the test case is active
        final String[] serverArgsTemplate;
        final String[] clientArgsTemplate;
        final boolean expectedToPass;
        final boolean bidirectional;
        final boolean wait;
        final boolean clientBrokenPipeResetAllowed;
        final boolean serverBrokenPipeResetAllowed;

        public TestCase(final String name, final boolean active, final String[] serverArgsTemplate,
                        final String[] clientArgsTemplate, final boolean expectedToPass, final boolean bidirectional,
                        final boolean wait, final boolean clientBrokenPipeResetAllowed,
                        final boolean serverBrokenPipeResetAllowed) {
            this.name = name;
            this.active = active;
            this.serverArgsTemplate = serverArgsTemplate;
            this.clientArgsTemplate = clientArgsTemplate;
            this.expectedToPass = expectedToPass;
            this.bidirectional = bidirectional;
            this.wait = wait;
            this.clientBrokenPipeResetAllowed = clientBrokenPipeResetAllowed;
            this.serverBrokenPipeResetAllowed = serverBrokenPipeResetAllowed;

            // Assert the name is consistent with the test case properties
            final String lowerName = name.toLowerCase();

            // Check bidirectional consistency
            final boolean hasBidirectionalInName = lowerName.contains("bidirectional");
            if (bidirectional != hasBidirectionalInName) {
                throw new IllegalArgumentException("Test name '" + name + "' bidirectional indicator inconsistent with bidirectional=" + bidirectional);
            }

            // Check wait consistency
            final boolean hasWaitInName = lowerName.contains("wait");
            if (wait != hasWaitInName) {
                throw new IllegalArgumentException("Test name '" + name + "' wait indicator inconsistent with wait=" + wait);
            }

            // Check failure expectation consistency
            final boolean hasShouldFailInName = lowerName.contains("should fail");
            if (expectedToPass == hasShouldFailInName) {
                throw new IllegalArgumentException("Test name '" + name + "' failure indicator inconsistent with expectedToPass=" + expectedToPass);
            }
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
                Arguments.of(
                        new TestCase(
                        "Unencrypted",
                        true,
                        new String[]{"-vi", "null", "-o", "{outputFile}", "-lu", "{host}", "{port}"},
                        new String[]{"-vi", "{inputFile}", "-o", "null", "-u", "{host}", "{port}"},
                        true,
                        false,
                                false, false,
                        false)),
                Arguments.of(new TestCase(
                        "Encrypted (TLS)",
                        true,
                        new String[]{"-vi", "null", "-o", "{outputFile}", "-l", "{host}", "{port}", "certs/server.pem",
                                "certs/key.pem"},
                        new String[]{"-vi", "{inputFile}", "-o", "null", "-t", "{host}", "{port}"},
                        true,
                        false,
                        false, false,
                        false)),
                Arguments.of(new TestCase(
                        "Unencrypted Reverse",
                        true,
                        new String[]{"-vi", "{inputFile}", "-o", "null", "-lu", "{host}", "{port}"},
                        new String[]{"-vi", "null", "-o", "{outputFile}", "-u", "{host}", "{port}"},
                        true,
                        false,
                        false, false,
                        false)),
                Arguments.of(new TestCase(
                        "Encrypted (TLS) Reverse",
                        true,
                        new String[]{"-vi", "{inputFile}", "-o", "null", "-l", "{host}", "{port}", "certs/server.pem",
                                "certs/key.pem"},
                        new String[]{"-vi", "null", "-o", "{outputFile}", "-t", "{host}", "{port}"},
                        true,
                        false,
                        false, false,
                        false)),
                Arguments.of(new TestCase(
                        "Unencrypted Bidirectional",
                        true,
                        new String[]{"-vi", "{inputFile}", "-o", "{outputFileBig}", "-lu", "-b", "16", "{host}",
                                "{port}"},
                        new String[]{"-vi", "{inputFileBig}", "-o", "{outputFile}", "-u", "-b", "16", "{host}",
                                "{port}"},
                        true,
                        true,
                        false, true,
                        false)),
                Arguments.of(new TestCase(
                        "Encrypted (TLS) Bidirectional",
                        true,
                        new String[]{"-vi", "{inputFile}", "-o", "{outputFileBig}", "-l", "-b", "16", "{host}",
                                "{port}", "certs/server.pem", "certs/key.pem"},
                        new String[]{"-vi", "{inputFileBig}", "-o", "{outputFile}", "-t", "-b", "16", "{host}",
                                "{port}"},
                        true,
                        true,
                        false, true,
                        false)),
                Arguments.of(new TestCase(
                        "Unencrypted Bidirectional Wait",
                        true,
                        new String[]{"-vi", "{inputFile}", "-o", "{outputFileBig}", "-lu", "-b", "16", "-w", "{host}",
                                "{port}"},
                        new String[]{"-vi", "{inputFileBig}", "-o", "{outputFile}", "-u", "-b", "16", "-w", "{host}",
                                "{port}"},
                        true,
                        true,
                        true, false,
                        false)),
                Arguments.of(new TestCase(
                        "Encrypted (TLS) Bidirectional Wait",
                        true,
                        new String[]{"-vi", "{inputFile}", "-o", "{outputFileBig}", "-l", "-b", "16", "-w", "{host}",
                                "{port}", "certs/server.pem", "certs/key.pem"},
                        new String[]{"-vi", "{inputFileBig}", "-o", "{outputFile}", "-t", "-b", "16", "-w", "{host}",
                                "{port}"},
                        true,
                        true,
                        true, false,
                        false)),
                Arguments.of(new TestCase(
                        "Client Unencrypted to Server Encrypted (should fail)",
                        true,
                        new String[]{"-vi", "null", "-o", "{outputFile}", "-l", "{host}", "{port}", "certs/server.pem",
                                "certs/key.pem"},
                        new String[]{"-vi", "{inputFile}", "-o", "null", "-u", "{host}", "{port}"},
                        false,
                        false,
                        false, false,
                        false)),
                // TODO: Disabled because the server does not reply to the TLS handshake, and the client hangs.
                Arguments.of(new TestCase(
                        "Client Encrypted to Server Unencrypted (should fail)",
                        false,
                        new String[]{"-vi", "null", "-o", "{outputFile}", "-lu", "{host}", "{port}"},
                        new String[]{"-vi", "{inputFile}", "-o", "null", "-t", "{host}", "{port}"},
                        false,
                        false,
                        false, false,
                        false)),
                Arguments.of(new TestCase(
                        "Encrypted without -t flag (should fail)",
                        true,
                        new String[]{"-vi", "null", "-o", "{outputFile}", "-l", "{host}", "{port}", "certs/server.pem",
                                "certs/key.pem"},
                        new String[]{"-vi", "{inputFile}", "-o", "null", "{host}", "{port}"},
                        false,
                        false,
                        false, false,
                        false))
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("testCases")
    public void testBasics(TestCase testCase, @TempDir Path tempDir) throws Exception {
        final String testPrefix = "Test case '" + testCase.name + "': ";
        final long startTime = System.currentTimeMillis();
        if (testCase.active) {
            log("Starting test case: " + testCase.name);
        } else {
            log("Skipping inactive test case: " + testCase.name);
            return; // Skip inactive test cases
        }
        // Test data that will be transferred.
        final byte[] testData = sharedTestData;
        final byte[] testDataBig = sharedTestDataBig;

        // Temporary files. Note that the input file will have data now whereas the output file will be created
        // and filled with the same data as a result of invoking TLSNetcat.
        final Path inputFile = tempDir.resolve("input.dat");
        // TODO: The input file could probably be reused between tests. Maybe just check the size after each test.
        Files.write(inputFile, testData);
        final Path outputFile = tempDir.resolve("output.dat");

        // Capture initial metadata of input files to verify they aren't tampered with
        final long inputFileSize = Files.size(inputFile);
        final long inputFileMtime = Files.getLastModifiedTime(inputFile).toMillis();

        // Additional files for bidirectional tests
        final Path inputFileBig;
        final Path outputFileBig;
        final long inputFileBigSize;
        final long inputFileBigMtime;
        if (testCase.bidirectional) {
            inputFileBig = tempDir.resolve("inputBig.dat");
            Files.write(inputFileBig, testDataBig);
            outputFileBig = tempDir.resolve("outputBig.dat");
            inputFileBigSize = Files.size(inputFileBig);
            inputFileBigMtime = Files.getLastModifiedTime(inputFileBig).toMillis();
        } else {
            inputFileBig = null;
            outputFileBig = null;
            inputFileBigSize = -1;
            inputFileBigMtime = -1;
        }

        // Use localhost and a dynamically assigned port.
        final String host = "localhost";
        final int port = findAvailablePort();

        final ExecutorService executor = Executors.newFixedThreadPool(2);

        final long initialListenCount = TLSNetcat.listenCount.get();

        final AtomicReference<Boolean> serverSuccessful = new AtomicReference<>(null);
        final AtomicReference<Boolean> clientSuccessful = new AtomicReference<>(null);

        final Future<?> serverTask = executor.submit(() -> {
            boolean success = false;
            Exception exception = null;
            try {
                final String[] serverArgs = buildArgs(testCase.serverArgsTemplate, inputFile, outputFile, host, port, inputFileBig, outputFileBig);
                TLSNetcat.main(serverArgs);
                success = true;
            } catch (Exception e) {
                exception = e;
            } finally {
                final boolean serverBrokenPipeResetActual = isBrokenPipeResetException(exception);
                if ((!success) && testCase.serverBrokenPipeResetAllowed && serverBrokenPipeResetActual) {
                    log("Server thread encountered a broken pipe, which is allowed in test case " + testCase.name);
                    success = true;
                }
                logThreadEnd(testCase, exception, success);
                synchronized (TLSNetcat.stateLock) {
                    serverSuccessful.set(success);
                    TLSNetcat.stateLock.notifyAll();
                }
            }
        });

        final Future<?> clientTask = executor.submit(() -> {
            boolean success = false;
            Exception exception = null;
            try {
                // Wait for the server to be listening, but give up if the server failed.
                synchronized (TLSNetcat.stateLock) {
                    while (initialListenCount == TLSNetcat.listenCount.get() &&
                            !Boolean.FALSE.equals(serverSuccessful.get())) {
                        TLSNetcat.stateLock.wait(LONG_TIMEOUT_MILLIS);
                    }
                }

                final String[] clientArgs = buildArgs(testCase.clientArgsTemplate, inputFile, outputFile, host, port, inputFileBig, outputFileBig);
                TLSNetcat.main(clientArgs);
                success = true;
            } catch (final Exception e) {
                exception = e;
            } finally {
                final boolean clientBrokenPipeResetActual = isBrokenPipeResetException(exception);
                if ((!success) && testCase.clientBrokenPipeResetAllowed && clientBrokenPipeResetActual) {
                    log("Client thread encountered a broken pipe, which is allowed in test case " + testCase.name);
                    success = true;
                }
                logThreadEnd(testCase, exception, success);
                synchronized (TLSNetcat.stateLock) {
                    clientSuccessful.set(success);
                    TLSNetcat.stateLock.notifyAll();
                }
            }
        });

        // Wait for the threads to complete. The timeouts are way too long. There are each given a unique value
        // to make debugging easier.
        try {
            serverTask.get(LONG_TIMEOUT_SECONDS + 10, TimeUnit.SECONDS);
            clientTask.get(LONG_TIMEOUT_SECONDS + 20, TimeUnit.SECONDS);
        } catch (final Exception e) {
            // The exception was handled elsewhere.
        }

        // If it was expected to pass then both threads should be successful.
        final boolean bothSuccessful = Boolean.TRUE.equals(serverSuccessful.get()) &&
                Boolean.TRUE.equals(clientSuccessful.get());
        assertEquals(testCase.expectedToPass, bothSuccessful,
                testPrefix + "Both server and client should be successful if expected to pass (server="
                        + serverSuccessful.get() + ", client=" + clientSuccessful.get() + ")");

        // Validate output files based on expected results
        final FileState outputState;
        final FileState outputStateBig;
        if (testCase.expectedToPass) {
            final boolean biDirNoWait = testCase.bidirectional && !testCase.wait;
            outputState = biDirNoWait ? FileState.MIGHT_BE_TRUNCATED_NON_ZERO_LENGTH : FileState.COMPLETE;
            outputStateBig = biDirNoWait ? FileState.MUST_BE_TRUNCATED_NON_ZERO_LENGTH : FileState.COMPLETE;
        }
        else {
            outputState = FileState.DOES_NOT_EXIST;
            outputStateBig = FileState.DOES_NOT_EXIST;
        }

        // validate that outputFile matches outputState.
        validateOutputFile(outputFile, testData, outputState, testPrefix + "Output file");

        // validate that outputFileBig matches outputStateBig.
        if (testCase.bidirectional) {
            validateOutputFile(outputFileBig, testDataBig, outputStateBig, testPrefix + "Output big file");
        }

        // TODO: Move as close to the end as possible.
        final long beforeShutdownMillis = System.currentTimeMillis();
        executor.shutdownNow();
        assertTrue(executor.awaitTermination(LONG_TIMEOUT_SECONDS + 5, TimeUnit.SECONDS),
                testPrefix + "Executor should terminate within the timeout");
        log("Executor terminated " + (System.currentTimeMillis() - beforeShutdownMillis) + " millis after shutdown");

        // Verify input files were not tampered with
        assertEquals(inputFileSize, Files.size(inputFile),
                testPrefix + "Input file size should not have changed");
        assertEquals(inputFileMtime, Files.getLastModifiedTime(inputFile).toMillis(),
                testPrefix + "Input file mtime should not have changed");

        if (testCase.bidirectional) {
            assertEquals(inputFileBigSize, Files.size(inputFileBig),
                    testPrefix + "Input big file size should not have changed");
            assertEquals(inputFileBigMtime, Files.getLastModifiedTime(inputFileBig).toMillis(),
                    testPrefix + "Input big file mtime should not have changed");
        }

        final long endTime = System.currentTimeMillis();
        final long duration = endTime - startTime;
        log("Completed test case: " + testCase.name + " in " + duration + " ms");
    }

    // *** Private methods ***

    /**
     * Asserts that the prefix byte array is a valid prefix of the full byte array.
     * For optimization, when prefix length equals full length, no data copying is performed.
     *
     * @param prefix The prefix data to check
     * @param full The full data that should contain the prefix
     * @param errorMessage Error message for assertion failure
     */
    private void assertIsPrefix(final byte[] prefix, final byte[] full, final String errorMessage) {
        if (prefix.length == full.length) {
            // Optimization: when lengths are equal, just compare directly
            assertArrayEquals(full, prefix, errorMessage);
        } else {
            // Extract prefix from full data and compare
            final byte[] expectedPrefix = new byte[prefix.length];
            System.arraycopy(full, 0, expectedPrefix, 0, prefix.length);
            assertArrayEquals(expectedPrefix, prefix, errorMessage);
        }
    }

    /**
     * Builds argument array by replacing placeholders with actual values
     */
    private String[] buildArgs(final String[] template, final Path inputFile,
                               final Path outputFile, final String host,
                               final int port, final Path inputFileBig,
                               final Path outputFileBig) {
        String[] args = new String[template.length];
        for (int i = 0; i < template.length; i++) {
            args[i] = template[i]
                    .replace("{inputFile}", inputFile.toString())
                    .replace("{outputFile}", outputFile.toString())
                    .replace("{inputFileBig}", inputFileBig != null ? inputFileBig.toString() : "null")
                    .replace("{outputFileBig}", outputFileBig != null ? outputFileBig.toString() : "null")
                    .replace("{host}", host)
                    .replace("{port}", String.valueOf(port));
        }
        return args;
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
     * Generates random data of the specified size.
     *
     * @param size The size of the data to generate.
     * @return A byte array filled with random data.
     */
    private static byte[] generateRandomData(final int size) {
        byte[] data = new byte[size];
        new Random(42).nextBytes(data);
        return data;
    }

    /**
     * Checks if the given exception is a broken pipe or connection reset exception (connections that happen as a
     * result of the remote side shutting down suddenly).
     *
     * @param exception The exception to check.
     * @return true if the exception is a broken pipe or connection reset, false otherwise.
     */
    private static boolean isBrokenPipeResetException(final Exception exception) {
        return exception instanceof SocketException &&
                exception.getMessage() != null && (
                exception.getMessage().contains("Broken pipe") ||
                        exception.getMessage().contains("Connection reset by peer"));
    }

    /**
     * Custom logging method with consistent timestamp and thread name format
     */
    private static void log(final String message) {
        final String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS"));
        final String threadName = Thread.currentThread().getName();
        System.err.println(timestamp + " [" + threadName + "] " + message);
    }

    /**
     * Summarizes the end of a thread execution, logging the result and any exception.
     * @param testCase The test case being executed.
     * @param exception The exception that occurred during execution, if any.
     * @param success Indicates whether the thread execution was successful.
     */
    private static void logThreadEnd(final TestCase testCase, final Exception exception, final boolean success) {
        // Generate the callstack for the exception, but only if the exception was not expected.
        final StringWriter callstackSW = new StringWriter();
        if (exception != null && testCase.expectedToPass && !success) {
            final PrintWriter pw = new PrintWriter(callstackSW);
            pw.print(" callstack=");
            exception.printStackTrace(pw);
        }
        log("Thread completed with success=" + success + ", exception=" + exception + callstackSW);
    }

    /**
     * Validates that an output file exists as expected, is truncated as expected, and that any data that exists is correct.
     *
     * @param outputFile The output file to validate
     * @param expectedData The expected data that should have been written to the file
     * @param expectedState The expected state of the file
     * @param testPrefix Prefix for error messages
     * @throws Exception If file operations fail
     */
    private void validateOutputFile(final Path outputFile, final byte[] expectedData, final FileState expectedState,
                                    final String testPrefix) throws Exception {
        switch (expectedState) {
            case DOES_NOT_EXIST:
                assertFalse(Files.exists(outputFile), testPrefix + " should not exist");
                break;

            case MUST_BE_TRUNCATED_NON_ZERO_LENGTH:
                assertTrue(Files.exists(outputFile), testPrefix + " should exist");
                final byte[] mustTruncatedData = Files.readAllBytes(outputFile);
                assertTrue(mustTruncatedData.length > 0, testPrefix + " should have some data");
                assertTrue(mustTruncatedData.length < expectedData.length, testPrefix + " must be truncated");

                // Verify the file data matches is as expected.
                assertIsPrefix(mustTruncatedData, expectedData, testPrefix + " partial data should match");
                break;

            case MIGHT_BE_TRUNCATED_NON_ZERO_LENGTH:
                assertTrue(Files.exists(outputFile), testPrefix + " should exist");
                final byte[] mightTruncatedData = Files.readAllBytes(outputFile);
                assertTrue(mightTruncatedData.length > 0, testPrefix + " should have some data");
                assertTrue(mightTruncatedData.length <= expectedData.length, testPrefix + " should not exceed expected length");

                // Verify the file data matches is as expected.
                assertIsPrefix(mightTruncatedData, expectedData, testPrefix + " partial data should match");
                break;

            case COMPLETE:
                assertTrue(Files.exists(outputFile), testPrefix + " should exist");
                final byte[] completeData = Files.readAllBytes(outputFile);
                assertEquals(expectedData.length, completeData.length, testPrefix + " length should match exactly");

                // Verify the file data matches is as expected.
                assertIsPrefix(completeData, expectedData, testPrefix + " should match exactly");
                break;
        }
    }

    // *** Enumerations ***

    /**
     * The expected state of an output file after test execution.
     */
    enum FileState {
        /** File should not exist (test failed or no output expected) */
        DOES_NOT_EXIST,
        /** File exists with partial data (bidirectional test without wait) */
        MUST_BE_TRUNCATED_NON_ZERO_LENGTH,
        /** File might have partial data depending on timing */
        MIGHT_BE_TRUNCATED_NON_ZERO_LENGTH,
        /** File contains complete expected data */
        COMPLETE,
    }
}
