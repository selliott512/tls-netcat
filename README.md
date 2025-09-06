# tls-netcat

A simple netcat-like program that supports both TLS encrypted and unencrypted connections. It can read and write from files or stdin and stdout. It's bidirectional, so it can send data in either direction, or both directions concurrently.

## Usage

### Server (listen mode)
```bash
# TLS encrypted server on specific interface
java -cp target/classes org.selliott.netcat.TLSNetcat -l [-o out-file] host port [certificate-pem [key-pem]]

# TLS encrypted server on all interfaces (host omitted)
java -cp target/classes org.selliott.netcat.TLSNetcat -l [-o out-file] port [certificate-pem [key-pem]]

# Unencrypted server on specific interface
java -cp target/classes org.selliott.netcat.TLSNetcat -ul [-o out-file] host port

# Unencrypted server on all interfaces (host omitted)
java -cp target/classes org.selliott.netcat.TLSNetcat -ul [-o out-file] port
```

### Client (connect mode)
```bash
# TLS encrypted client (trusting all certificates)
java -cp target/classes org.selliott.netcat.TLSNetcat -t [-i in-file] host port

# Unencrypted client
java -cp target/classes org.selliott.netcat.TLSNetcat -u [-i in-file] host port
```

## Options

- `-4` - force IPv4
- `-6` - force IPv6
- `-b block` - Block size for writes (default 8192)
- `-i in-file` - Input file to use instead of stdin
- `-l` - Listen (server mode)
- `-o out-file` - Output file to use instead of stdout
- `-q` - Quiet mode (no logging)
- `-r size` - Receive buffer size (default: OS default)
- `-s size` - Send buffer size (default: OS default)
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

tls-netcat is a Maven project that can be built in the usual way for Maven projects. If you just want the classes and JAR file, as referenced in the Running section below, then build with:

```bash
mvn package
```

If you don't have Maven you should be able to use javac directly to build just the class files:

```bash
javac -d target/classes src/main/java/org/selliott/netcat/TLSNetcat.java
```

## Running

tls-netcat can be invoked in several ways (using host `localhost` and port `1234` as examples as well as `/tmp/1MB-*` as example input and output files):

```bash
# Using compiled classes
java -cp target/classes org.selliott.netcat.TLSNetcat -ulo /tmp/1MB-out localhost 1234

# Using JAR file
java -cp target/tls-netcat-*.jar org.selliott.netcat.TLSNetcat -ulo /tmp/1MB-out localhost 1234

# Using Maven exec plugin
mvn exec:java -Dexec.args="-ulo /tmp/1MB-out localhost 1234"
```

## Advanced Usage

### Listen on All Interfaces

When running in server mode (`-l`), the host parameter is optional. If omitted, the server will bind to all available network interfaces:

```bash
# Listen on all interfaces on port 1234
java -cp target/classes org.selliott.netcat.TLSNetcat -ulo /tmp/1MB-out 1234

# Listen on specific interface (localhost) on port 1234
java -cp target/classes org.selliott.netcat.TLSNetcat -ulo /tmp/1MB-out localhost 1234
```

### Null File Handling

By default, tls-netcat reads from stdin and writes to stdout. Use `"null"` to disable reading or writing:

```bash
# Disable stdin reading (only receive data)
java -cp target/classes org.selliott.netcat.TLSNetcat -i null -ulo /tmp/1MB-out localhost 1234

# Disable stdout writing (only send data)
java -cp target/classes org.selliott.netcat.TLSNetcat -o null -ui /tmp/1MB-in localhost 1234
```

### Bidirectional Transfer

For simultaneous sending and receiving, use the `-w` (wait) option to ensure both transfers complete. In this case different size files are used to make things more deterministic (the smaller file almost always completes first):

```bash
# Server sends 2MB file while receiving 1MB file
java -cp target/classes org.selliott.netcat.TLSNetcat -w -i /tmp/2MB-in -ulo /tmp/1MB-out localhost 1234

# Client sends 1MB file while receiving 2MB file
java -cp target/classes org.selliott.netcat.TLSNetcat -w -i /tmp/1MB-in -uo /tmp/2MB-out localhost 1234
```

## Testing

tls-netcat includes unit tests that can be run with:

```bash
mvn test
```

## TLS Certificates

For TLS mode, the server requires certificate files. The following paths are used by default:
- `certs/server.pem` - Server certificate (default)
- `certs/key.pem` - Private key (default)

The provided certificates can be used for testing, but are insecure for production use since the private key is unencrypted and publicly visible. Custom certificate paths can be specified as positional arguments in server mode.
