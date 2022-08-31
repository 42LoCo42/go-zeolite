# go-zeolite
Zeolite: simple & secure communications
based on [libsodium](https://doc.libsodium.org) with
[perfect forward secrecy](https://en.wikipedia.org/wiki/Forward_secrecy),
[XChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305)
and a mirrored protocol (no distinction between client & server).

## Protocol design
The protocol is completely identical for server & client.

### Handshake (performed in lockstep by both participants)
1. Protocol version (currently `zeolite1`, so 8 bytes)
2. Public key (32 bytes)
4. Ephemeral key (for PFS) signed with public key (96 bytes)
5. Symmetric key (for communication) encrypted with ephemeral key (72 bytes)
6. Stream header (24 bytes)

Total: 232 bytes
### Data Transmission
1. Message size (4 bytes)
2. Encrypted message (17 bytes + message size)

Total: 21 bytes + message size
