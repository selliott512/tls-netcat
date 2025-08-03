# tls-netcat

A simple netcat-like program that supports both TLS encrypted and unencrypted connections.

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

## Building

```bash
mvn compile
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
