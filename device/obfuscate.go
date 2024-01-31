package device

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/database64128/swgp-go/fastrand"
	"golang.org/x/crypto/chacha20poly1305"
)

// zeroOverheadHandshakePacketMinimumOverhead is the minimum overhead of a handshake packet encrypted by zeroOverheadHandler.
// Additional overhead is the random-length padding.
const zeroOverheadHandshakePacketMinimumOverhead = 2 + chacha20poly1305.Overhead + chacha20poly1305.NonceSizeX

type Obfuscate struct {
	enabled      bool
	obfuscateKey NoisePresharedKey
	cb           cipher.Block
	aead         cipher.AEAD
}

func (o *Obfuscate) ObfuscateInit() error {
	return o.ObfuscateSetKey(nil)
}

func (o *Obfuscate) ObfuscateSetKey(psk []byte) error {
	if psk == nil {
		o.obfuscateKey = [len(o.obfuscateKey)]byte{}
	} else if len(psk) != len(o.obfuscateKey) {
		return errors.New("Invalid obfucsation key length")
	} else {
		copy(o.obfuscateKey[:], psk)
	}

	cb, err := aes.NewCipher(o.obfuscateKey[:])
	if err != nil {
		return err
	}

	aead, err := chacha20poly1305.NewX(o.obfuscateKey[:])
	if err != nil {
		return err
	}

	o.cb = cb
	o.aead = aead

	return nil
}

func (o *Obfuscate) EncryptZeroCopy(buf []byte, wgPacketStart, wgPacketLength int) (swgpPacketStart, swgpPacketLength int, err error) {
	swgpPacketStart = wgPacketStart
	swgpPacketLength = wgPacketLength

	// Skip small packets.
	if wgPacketLength < 16 {
		return
	}

	messageType := binary.LittleEndian.Uint32(buf[wgPacketStart:(wgPacketStart + 4)])

	// Encrypt first 16 bytes.
	o.cb.Encrypt(buf[wgPacketStart:], buf[wgPacketStart:])
	switch messageType {
	case MessageInitiationType, MessageResponseType, MessageCookieReplyType:
	default:
		return
	}

	// Return error if packet is so big that buffer has no room for AEAD overhead.
	rearHeadroom := len(buf) - wgPacketStart - wgPacketLength
	paddingHeadroom := rearHeadroom - 2 - chacha20poly1305.Overhead - chacha20poly1305.NonceSizeX
	if paddingHeadroom < 0 {
		err = fmt.Errorf("EncryptZeroCopy: handshake packet (length %d) is too large to process in buffer (length %d)", wgPacketLength, len(buf))
		return
	}

	var paddingLen int
	if paddingHeadroom > 0 {
		paddingLen = 1 + int(fastrand.Uint32n(uint32(paddingHeadroom)))
	}

	swgpPacketLength += paddingLen + zeroOverheadHandshakePacketMinimumOverhead

	// Calculate offsets.
	plaintextStart := wgPacketStart + 16
	payloadLengthBufStart := wgPacketStart + wgPacketLength + paddingLen
	plaintextEnd := payloadLengthBufStart + 2
	nonceStart := plaintextEnd + chacha20poly1305.Overhead
	nonceEnd := nonceStart + chacha20poly1305.NonceSizeX

	// Write payload length.
	payloadLength := wgPacketLength - 16
	payloadLengthBuf := buf[payloadLengthBufStart:plaintextEnd]
	binary.BigEndian.PutUint16(payloadLengthBuf, uint16(payloadLength))

	plaintext := buf[plaintextStart:plaintextEnd]
	nonce := buf[nonceStart:nonceEnd]
	_, err = rand.Read(nonce)
	if err != nil {
		return
	}

	o.aead.Seal(plaintext[:0], nonce, plaintext, nil)
	return
}

func (o *Obfuscate) DecryptZeroCopy(buf []byte, swgpPacketStart, swgpPacketLength int) (wgPacketStart, wgPacketLength int, err error) {
	wgPacketStart = swgpPacketStart
	wgPacketLength = swgpPacketLength

	// Skip small packets.
	if swgpPacketLength < 16 {
		return
	}

	o.cb.Decrypt(buf[swgpPacketStart:], buf[swgpPacketStart:])

	msgType := binary.LittleEndian.Uint32(buf[swgpPacketStart:(swgpPacketStart + 4)])
	switch msgType {
	case MessageInitiationType, MessageResponseType, MessageCookieReplyType:
		if swgpPacketLength < 16+zeroOverheadHandshakePacketMinimumOverhead {
			err = fmt.Errorf("DecryptZeroCopy: packet too short: %d", swgpPacketLength)
			return
		}

	default:
		return
	}

	// Calculate offsets.
	nonceEnd := swgpPacketStart + swgpPacketLength
	nonceStart := nonceEnd - chacha20poly1305.NonceSizeX
	plaintextEnd := nonceStart - chacha20poly1305.Overhead
	payloadLengthBufStart := plaintextEnd - 2
	plaintextStart := swgpPacketStart + 16

	ciphertext := buf[plaintextStart:nonceStart]
	nonce := buf[nonceStart:nonceEnd]
	_, err = o.aead.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		return
	}

	// Read and validate payload length.
	payloadLengthBuf := buf[payloadLengthBufStart:plaintextEnd]
	payloadLength := int(binary.BigEndian.Uint16(payloadLengthBuf))
	if payloadLength > payloadLengthBufStart-plaintextStart {
		err = fmt.Errorf("DecryptZeroCopy: payload length field value %d is out of range", payloadLength)
		return
	}

	wgPacketLength = 16 + payloadLength
	return
}
