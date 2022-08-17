package zeolite

import (
	// #cgo LDFLAGS: -lsodium
	// #include <sodium.h>
	"C"

	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"unsafe"
)

const Protocol = "zeolite1"

var (
	ErrInit    = errors.New("Could not initialize libsodium")
	ErrEOS     = errors.New("End of stream reached")
	ErrRecv    = errors.New("Could not receive")
	ErrSend    = errors.New("Could not send")
	ErrProto   = errors.New("Protocol violation")
	ErrKeygen  = errors.New("Key generation failed")
	ErrTrust   = errors.New("No trust")
	ErrSign    = errors.New("Could not sign")
	ErrVerify  = errors.New("Could not verify")
	ErrEncrypt = errors.New("Could not encrypt")
	ErrDecrypt = errors.New("Could not decrypt")
)

type SignPK [C.crypto_sign_PUBLICKEYBYTES]byte
type SignSK [C.crypto_sign_SECRETKEYBYTES]byte
type EphPK [C.crypto_box_PUBLICKEYBYTES]byte
type EphSK [C.crypto_box_SECRETKEYBYTES]byte
type SymK [C.crypto_secretstream_xchacha20poly1305_KEYBYTES]byte

type TrustCB func(otherPK SignPK) (bool, error)

type Identity struct {
	Public SignPK
	Secret SignSK
}

type Stream struct {
	Conn      net.Conn
	OtherPK   SignPK
	SendState C.crypto_secretstream_xchacha20poly1305_state
	RecvState C.crypto_secretstream_xchacha20poly1305_state
}

func ptr(val []byte) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(&val[0]))
}

func size(val []byte) C.ulonglong {
	return C.ulonglong(len(val))
}

func Base64PK(pk SignPK) string {
	buf := strings.Builder{}
	enc := base64.NewEncoder(base64.StdEncoding, &buf)
	enc.Write(pk[:])
	enc.Close()
	return buf.String()
}

func Init() error {
	if C.sodium_init() < 0 {
		return ErrInit
	} else {
		return nil
	}
}

func NewIdentity() (ret Identity, err error) {
	if C.crypto_sign_keypair(ptr(ret.Public[:]), ptr(ret.Secret[:])) == 0 {
		return ret, nil
	} else {
		return ret, ErrKeygen
	}
}

func (identity Identity) NewStream(conn net.Conn, cb TrustCB) (ret Stream, err error) {
	ret.Conn = conn

	// exchange & check protocol
	buf := strings.Builder{}

	if _, err := io.WriteString(conn, Protocol); err != nil {
		return ret, ErrSend
	}
	if _, err := io.CopyN(&buf, conn, int64(len(Protocol))); err != nil {
		return ret, ErrRecv
	}
	if buf.String() != Protocol {
		return ret, ErrProto
	}

	// exchange public keys for identification
	if _, err := conn.Write(identity.Public[:]); err != nil {
		return ret, ErrSend
	}
	if _, err := io.ReadFull(conn, ret.OtherPK[:]); err != nil {
		return ret, ErrRecv
	}

	// check for trust
	if trust, err := cb(ret.OtherPK); err != nil || !trust {
		return ret, ErrTrust
	}

	// create, sign & send ephemeral keys
	ephPK := EphPK{}
	ephSK := EphSK{}
	ephMsg := [C.crypto_sign_BYTES + len(ephPK)]byte{}

	if C.crypto_box_keypair(ptr(ephPK[:]), ptr(ephSK[:])) != 0 {
		return ret, ErrKeygen
	}
	if C.crypto_sign(
		ptr(ephMsg[:]),
		nil,
		ptr(ephPK[:]),
		size(ephPK[:]),
		ptr(identity.Secret[:]),
	) != 0 {
		return ret, ErrSign
	}
	if _, err := conn.Write(ephMsg[:]); err != nil {
		return ret, ErrSend
	}

	// read & verify other ephemeral key
	otherEphPK := EphPK{}

	if _, err := io.ReadFull(conn, ephMsg[:]); err != nil {
		return ret, ErrRecv
	}
	if C.crypto_sign_open(
		ptr(otherEphPK[:]),
		nil,
		ptr(ephMsg[:]),
		size(ephMsg[:]),
		ptr(ret.OtherPK[:]),
	) != 0 {
		return ret, ErrVerify
	}

	// create, encrypt & send symmetric sender key
	sendK := SymK{}
	symMsg := [C.crypto_box_NONCEBYTES +
		C.crypto_box_MACBYTES +
		len(sendK)]byte{}
	nonce := symMsg[0:C.crypto_box_NONCEBYTES]
	cipher := symMsg[C.crypto_box_NONCEBYTES:]

	C.crypto_secretstream_xchacha20poly1305_keygen(ptr(sendK[:]))
	C.randombytes_buf(
		unsafe.Pointer(&nonce[0]),
		C.ulong(len(nonce)),
	)
	if C.crypto_box_easy(
		ptr(cipher[:]),
		ptr(sendK[:]),
		size(sendK[:]),
		ptr(nonce[:]),
		ptr(otherEphPK[:]),
		ptr(ephSK[:]),
	) != 0 {
		return ret, ErrEncrypt
	}
	if _, err := conn.Write(symMsg[:]); err != nil {
		return ret, ErrSend
	}

	// receive & decrypt symmetric receiver key
	recvK := SymK{}

	if _, err := io.ReadFull(conn, symMsg[:]); err != nil {
		return ret, ErrRecv
	}
	if C.crypto_box_open_easy(
		ptr(recvK[:]),
		ptr(cipher[:]),
		C.crypto_box_MACBYTES+size(sendK[:]),
		ptr(nonce[:]),
		ptr(otherEphPK[:]),
		ptr(ephSK[:]),
	) != 0 {
		return ret, ErrDecrypt
	}

	// init stream states
	header := [C.crypto_secretstream_xchacha20poly1305_HEADERBYTES]byte{}

	if C.crypto_secretstream_xchacha20poly1305_init_push(
		&ret.SendState,
		ptr(header[:]),
		ptr(sendK[:]),
	) != 0 {
		return ret, ErrEncrypt
	}
	if _, err := conn.Write(header[:]); err != nil {
		return ret, ErrSend
	}
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return ret, ErrRecv
	}
	if C.crypto_secretstream_xchacha20poly1305_init_pull(
		&ret.RecvState,
		ptr(header[:]),
		ptr(recvK[:]),
	) != 0 {
		return ret, ErrDecrypt
	}

	return ret, nil
}

func (stream Stream) Send(msg []byte) error {
	// send size
	buf := make([]byte, 4)

	binary.LittleEndian.PutUint32(buf[:], uint32(len(msg)))
	if _, err := stream.Conn.Write(buf[:]); err != nil {
		return err
	}

	// encrypt & send message
	buf = make([]byte, len(msg) + C.crypto_secretstream_xchacha20poly1305_ABYTES)

	if C.crypto_secretstream_xchacha20poly1305_push(
		&stream.SendState,
		ptr(buf),
		nil,
		ptr(msg),
		C.ulonglong(len(msg)),
		nil,
		0,
		0,
	) != 0 {
		return ErrEncrypt
	}
	_, err := stream.Conn.Write(buf)
	return err
}

func (stream Stream) Recv() (ret []byte, err error) {
	// receive size
	buf := make([]byte, 4)

	if _, err := io.ReadFull(stream.Conn, buf); err != nil {
		return ret, ErrRecv
	}

	// receive & decrypt message
	siz := binary.LittleEndian.Uint32(buf[:])
	buf = make([]byte, siz + C.crypto_secretstream_xchacha20poly1305_ABYTES)
	ret = make([]byte, siz)

	if _, err := io.ReadFull(stream.Conn, buf); err != nil {
		return ret, ErrRecv
	}
	if C.crypto_secretstream_xchacha20poly1305_pull(
		&stream.RecvState,
		ptr(ret),
		nil,
		nil,
		ptr(buf),
		size(buf),
		nil,
		0,
	) != 0 {
		return ret, ErrDecrypt
	}

	return ret, nil
}
