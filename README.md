# TSAM Assignment 3

## Group members

- regina24
- steinunnp24

## Development environment

The programs were developed and tested on macOS running on an ARM64
Apple Silicon processor.

The programs are written in C and compiled using Apple Clang.

## Included programs

### scanner

Scans a range of UDP ports and prints the ports that respond.

### secret_solver

Solves the S.E.C.R.E.T. puzzle. It generates a random 32-bit secret
number, receives the challenge, calculates the sigil using XOR, and
extracts the hidden port.

### evil_solver

Solves the Evil Port puzzle. It creates a raw IPv4 and UDP packet with
the IPv4 evil bit set and sends the group ID and S.E.C.R.E.T. sigil.

Because this program creates a raw socket, it must be run using sudo.

### guardian_solver

Solves the Guardian puzzle. It constructs an IPv6 and UDP packet inside
an outer IPv4 UDP message, calculates the required IPv6 UDP checksum,
and extracts the secret phrase from the matching Guardian response.

The Guardian can send unrelated phrase packets. The program compares
the inner IPv6 addresses and UDP ports so that it ignores unrelated
responses.

## Compiling

Run the following command in the directory containing the source files:

```bash
make
```

This compiles all programs and creates the following executables:

- `scanner`
- `secret_solver`
- `evil_solver`
- `guardian_solver`

To remove all compiled executables, run:

```bash
make clean
```

To perform a completely fresh build, run:

```bash
make clean
make
```