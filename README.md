# tls-netcat

A simple netcat-like program that supports both TLS encrypted and unencrypted connections. It's bidirectional, so it can also send data from server to client.

## Usage

### Server (listen mode)
```bash
# TLS encrypted server
java -cp target/classes org.selliott.netcat.TLSNetcat -lo /tmp/1MB-recv localhost 1234

# Unencrypted server
java -cp target/classes org.selliott.netcat.TLSNetcat -ulo /tmp/1MB-recv localhost 1234
```

### Client (connect mode)
```bash
# TLS encrypted client (trusting all certificates)
java -cp target/classes org.selliott.netcat.TLSNetcat -ti /tmp/1MB localhost 1234

# Unencrypted client
java -cp target/classes org.selliott.netcat.TLSNetcat -ui /tmp/1MB localhost 1234
```

## Options

- `-b block` - Block size for writes (default 8192)
- `-i in-file` - Input file to use instead of stdin
- `-l` - Listen (server mode)
- `-o out-file` - Output file to use instead of stdout
- `-q` - Quiet mode (no logging)
- `-t` - Trust all server certificates (client mode)
- `-u` - Unencrypted data (no TLS)
- `-v` - Verbose logging
- `-w` - Wait for both threads to complete

## Java Version Compatibility

tls-netcat requires Java 17 by default, but can be built for Java 11 without code changes by modifying the release version in `pom.xml`:

```xml
-    <maven.compiler.release>17</maven.compiler.release>
+    <maven.compiler.release>11</maven.compiler.release>
```

## Building

```bash
mvn compile
```

## Running

tls-netcat can be invoked in several ways:

```bash
# Using compiled classes
java -cp target/classes org.selliott.netcat.TLSNetcat -ulo /tmp/1MB-recv localhost 1234

# Using JAR file
java -cp target/tls-netcat-*.jar org.selliott.netcat.TLSNetcat -ulo /tmp/1MB-recv localhost 1234

# Using Maven exec plugin
mvn exec:java -Dexec.args="-ulo /tmp/1MB-recv localhost 1234"
```

## Advanced Usage

### Null File Handling

By default, tls-netcat reads from stdin and writes to stdout. Use `"null"` to disable reading or writing:

```bash
# Disable stdin reading (only receive data)
java -cp target/classes org.selliott.netcat.TLSNetcat -i null -ulo /tmp/1MB-recv localhost 1234

# Disable stdout writing (only send data)
java -cp target/classes org.selliott.netcat.TLSNetcat -o null -ui /tmp/1MB localhost 1234
```

### Bidirectional Transfer

For simultaneous sending and receiving, use the `-w` (wait) option to ensure both transfers complete:

```bash
# Server sends 2MB file while receiving 1MB file
java -cp target/classes org.selliott.netcat.TLSNetcat -w -i /tmp/2MB -ulo /tmp/1MB-recv localhost 1234

# Client sends 1MB file while receiving 2MB file
java -cp target/classes org.selliott.netcat.TLSNetcat -w -i /tmp/1MB -uo /tmp/2MB-recv localhost 1234
```

## Testing

```bash
mvn test
```

## TLS Certificates

For TLS mode, the server requires certificate files:
- `certs/server.pem` - Server certificate (default)
- `certs/key.pem` - Private key (default)

Custom certificate paths can be specified as positional arguments in server mode.
