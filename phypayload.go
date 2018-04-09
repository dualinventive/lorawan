//go:generate stringer -type=MType
//go:generate stringer -type=Major

package lorawan

import (
	"crypto/aes"
	"database/sql/driver"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jacobsa/crypto/cmac"
)

// MType represents the message type.
type MType byte

// MarshalText implements encoding.TextMarshaler.
func (m MType) MarshalText() ([]byte, error) {
	return []byte(m.String()), nil
}

// Major defines the major version of data message.
type Major byte

// Supported message types (MType)
const (
	JoinRequest MType = iota
	JoinAccept
	UnconfirmedDataUp
	UnconfirmedDataDown
	ConfirmedDataUp
	ConfirmedDataDown
	RejoinRequest
	Proprietary
)

// Supported major versions
const (
	LoRaWANR1 Major = 0
)

// MarshalText implements encoding.TextMarshaler.
func (m Major) MarshalText() ([]byte, error) {
	return []byte(m.String()), nil
}

// AES128Key represents a 128 bit AES key.
type AES128Key [16]byte

// String implements fmt.Stringer.
func (k AES128Key) String() string {
	return hex.EncodeToString(k[:])
}

// MarshalText implements encoding.TextMarshaler.
func (k AES128Key) MarshalText() ([]byte, error) {
	return []byte(k.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *AES128Key) UnmarshalText(text []byte) error {
	b, err := hex.DecodeString(string(text))
	if err != nil {
		return err
	}
	if len(b) != len(k) {
		return fmt.Errorf("lorawan: exactly %d bytes are expected", len(k))
	}
	copy(k[:], b)
	return nil
}

// Scan implements sql.Scanner.
func (k *AES128Key) Scan(src interface{}) error {
	b, ok := src.([]byte)
	if !ok {
		return errors.New("lorawan: []byte type expected")
	}
	if len(b) != len(k) {
		return fmt.Errorf("lorawan []byte must have length %d", len(k))
	}
	copy(k[:], b)
	return nil
}

// Value implements driver.Valuer.
func (k AES128Key) Value() (driver.Value, error) {
	return k[:], nil
}

// MIC represents the message integrity code.
type MIC [4]byte

// String implements fmt.Stringer.
func (m MIC) String() string {
	return hex.EncodeToString(m[:])
}

// MarshalText implements encoding.TextMarshaler.
func (m MIC) MarshalText() ([]byte, error) {
	return []byte(m.String()), nil
}

// MHDR represents the MAC header.
type MHDR struct {
	MType MType `json:"mType"`
	Major Major `json:"major"`
}

// MarshalBinary marshals the object in binary form.
func (h MHDR) MarshalBinary() ([]byte, error) {
	return []byte{byte(h.Major) ^ (byte(h.MType) << 5)}, nil
}

// UnmarshalBinary decodes the object from binary form.
func (h *MHDR) UnmarshalBinary(data []byte) error {
	if len(data) != 1 {
		return errors.New("lorawan: 1 byte of data is expected")
	}
	h.Major = Major(data[0] & 3)
	h.MType = MType((data[0] & 224) >> 5)
	return nil
}

// PHYPayload represents the physical payload.
type PHYPayload struct {
	MHDR       MHDR    `json:"mhdr"`
	MACPayload Payload `json:"macPayload"`
	MIC        MIC     `json:"mic"`
}

// calculateMIC calculates and returns the MIC.
func (p PHYPayload) calculateMIC(key AES128Key) ([]byte, error) {
	if p.MACPayload == nil {
		return []byte{}, errors.New("lorawan: MACPayload should not be empty")
	}

	macPayload, ok := p.MACPayload.(*MACPayload)
	if !ok {
		return []byte{}, errors.New("lorawan: MACPayload should be of type *MACPayload")
	}

	var b []byte
	var err error
	var micBytes []byte

	b, err = p.MHDR.MarshalBinary()
	if err != nil {
		return nil, err
	}
	micBytes = append(micBytes, b...)

	b, err = macPayload.MarshalBinary()
	if err != nil {
		return nil, err
	}
	micBytes = append(micBytes, b...)

	b0 := make([]byte, 16)
	b0[0] = 0x49
	if !p.isUplink() {
		b0[5] = 1
	}
	b, err = macPayload.FHDR.DevAddr.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(b0[6:10], b)
	binary.LittleEndian.PutUint32(b0[10:14], macPayload.FHDR.FCnt)
	b0[15] = byte(len(micBytes))

	hash, err := cmac.New(key[:])
	if err != nil {
		return nil, err
	}

	if _, err = hash.Write(b0); err != nil {
		return nil, err
	}
	if _, err = hash.Write(micBytes); err != nil {
		return nil, err
	}

	hb := hash.Sum([]byte{})
	if len(hb) < 4 {
		return nil, errors.New("lorawan: the hash returned less than 4 bytes")
	}
	return hb[0:4], nil
}

// calculateMACPayloadMIC generates and returns the MIC over the MHDR + the
// binary representation of the MACPayload field.
func (p PHYPayload) calculateMACPayloadMIC(key AES128Key) ([]byte, error) {
	if p.MACPayload == nil {
		return nil, errors.New("lorawan: MACPayload must not be empty")
	}

	var micBytes []byte

	b, err := p.MHDR.MarshalBinary()
	if err != nil {
		return nil, err
	}
	micBytes = append(micBytes, b...)

	b, err = p.MACPayload.MarshalBinary()
	if err != nil {
		return nil, err
	}
	micBytes = append(micBytes, b...)

	hash, err := cmac.New(key[:])
	if err != nil {
		return nil, err
	}
	if _, err = hash.Write(micBytes); err != nil {
		return nil, err
	}
	hb := hash.Sum([]byte{})
	if len(hb) < 4 {
		return nil, errors.New("lorawan: the hash returned less than 4 bytes")
	}
	return hb[0:4], nil
}

// SetMIC calculates and sets the MIC field.
func (p *PHYPayload) SetMIC(key AES128Key) error {
	var mic []byte
	var err error

	switch p.MACPayload.(type) {
	case *JoinRequestPayload:
		mic, err = p.calculateMACPayloadMIC(key)
	case *JoinAcceptPayload:
		mic, err = p.calculateMACPayloadMIC(key)
	case *RejoinRequestType02Payload:
		mic, err = p.calculateMACPayloadMIC(key)
	case *RejoinRequestType1Payload:
		mic, err = p.calculateMACPayloadMIC(key)
	default:
		mic, err = p.calculateMIC(key)
	}

	if err != nil {
		return err
	}
	if len(mic) != 4 {
		return errors.New("lorawan: a MIC of 4 bytes is expected")
	}
	for i, v := range mic {
		p.MIC[i] = v
	}
	return nil
}

// ValidateMIC returns if the MIC is valid.
// When using 32 bit frame counters, only the least-signification 16 bits are
// sent / received. In order to validate the MIC, the receiver needs to set
// the FCnt to the full 32 bit value (based on the observation of the traffic).
// See section '4.3.1.5 Frame counter (FCnt)' of the LoRaWAN 1.0 specification
// for more details.
func (p PHYPayload) ValidateMIC(key AES128Key) (bool, error) {
	var mic []byte
	var err error

	switch p.MACPayload.(type) {
	case *JoinRequestPayload:
		mic, err = p.calculateMACPayloadMIC(key)
	case *JoinAcceptPayload:
		mic, err = p.calculateMACPayloadMIC(key)
	case *RejoinRequestType02Payload:
		mic, err = p.calculateMACPayloadMIC(key)
	case *RejoinRequestType1Payload:
		mic, err = p.calculateMACPayloadMIC(key)
	default:
		mic, err = p.calculateMIC(key)
	}

	if err != nil {
		return false, err
	}
	if len(mic) != 4 {
		return false, errors.New("lorawan: a MIC of 4 bytes is expected")
	}
	for i, v := range mic {
		if p.MIC[i] != v {
			return false, nil
		}
	}
	return true, nil
}

// EncryptJoinAcceptPayload encrypts the join-accept payload with the given
// AppKey. Note that encrypted must be performed after calling SetMIC
// (sicne the MIC is part of the encrypted payload).
func (p *PHYPayload) EncryptJoinAcceptPayload(appKey AES128Key) error {
	if _, ok := p.MACPayload.(*JoinAcceptPayload); !ok {
		return errors.New("lorawan: MACPayload value must be of type *JoinAcceptPayload")
	}

	pt, err := p.MACPayload.MarshalBinary()
	if err != nil {
		return err
	}

	// in the 1.0 spec instead of DLSettings there is RFU field. the assumption
	// is made that this should have been DLSettings.

	pt = append(pt, p.MIC[0:4]...)
	if len(pt)%16 != 0 {
		return errors.New("lorawan: plaintext must be a multiple of 16 bytes")
	}

	block, err := aes.NewCipher(appKey[:])
	if err != nil {
		return err
	}
	if block.BlockSize() != 16 {
		return errors.New("lorawan: block-size of 16 bytes is expected")
	}
	ct := make([]byte, len(pt))
	for i := 0; i < len(ct)/16; i++ {
		offset := i * 16
		block.Decrypt(ct[offset:offset+16], pt[offset:offset+16])
	}
	p.MACPayload = &DataPayload{Bytes: ct[0 : len(ct)-4]}
	copy(p.MIC[:], ct[len(ct)-4:])
	return nil
}

// DecryptJoinAcceptPayload decrypts the join-accept payload with the given
// AppKey. Note that you need to decrypte before you can validate the MIC.
func (p *PHYPayload) DecryptJoinAcceptPayload(appKey AES128Key) error {
	dp, ok := p.MACPayload.(*DataPayload)
	if !ok {
		return errors.New("lorawan: MACPayload must be of type *DataPayload")
	}

	// append MIC to the ciphertext since it is encrypted too
	ct := append(dp.Bytes, p.MIC[:]...)

	if len(ct)%16 != 0 {
		return errors.New("lorawan: plaintext must be a multiple of 16 bytes")
	}

	block, err := aes.NewCipher(appKey[:])
	if err != nil {
		return err
	}
	if block.BlockSize() != 16 {
		return errors.New("lorawan: block-size of 16 bytes is expected")
	}
	pt := make([]byte, len(ct))
	for i := 0; i < len(pt)/16; i++ {
		offset := i * 16
		block.Encrypt(pt[offset:offset+16], ct[offset:offset+16])
	}

	p.MACPayload = &JoinAcceptPayload{}
	copy(p.MIC[:], pt[len(pt)-4:len(pt)]) // set the decrypted MIC
	return p.MACPayload.UnmarshalBinary(p.isUplink(), pt[0:len(pt)-4])
}

// EncryptFOpts encrypts the FOpts with the given key.
func (p *PHYPayload) EncryptFOpts(nwkSEncKey AES128Key) error {
	macPL, ok := p.MACPayload.(*MACPayload)
	if !ok {
		return errors.New("lorawan: MACPayload must be of type *MACPayload")
	}

	// nothing to encrypt
	if len(macPL.FHDR.FOpts) == 0 {
		return nil
	}

	var macB []byte
	for _, mac := range macPL.FHDR.FOpts {
		b, err := mac.MarshalBinary()
		if err != nil {
			return err
		}
		macB = append(macB, b...)
	}

	var aFCntDown bool
	if !p.isUplink() && macPL.FPort != nil && *macPL.FPort > 0 {
		aFCntDown = true
	}

	data, err := EncryptFOpts(nwkSEncKey, aFCntDown, p.isUplink(), macPL.FHDR.DevAddr, macPL.FHDR.FCnt, macB)
	if err != nil {
		return err
	}

	macPL.FHDR.FOpts = []Payload{
		&DataPayload{Bytes: data},
	}

	return nil
}

// DecryptFOpts decrypts the FOpts payload and decodes it into mac-command
// structures.
func (p *PHYPayload) DecryptFOpts(nwkSEncKey AES128Key) error {
	if err := p.EncryptFOpts(nwkSEncKey); err != nil {
		return nil
	}

	return p.DecodeFOptsToMACCommands()
}

// EncryptFRMPayload encrypts the FRMPayload with the given key.
func (p *PHYPayload) EncryptFRMPayload(key AES128Key) error {
	macPL, ok := p.MACPayload.(*MACPayload)
	if !ok {
		return errors.New("lorawan: MACPayload must be of type *MACPayload")
	}

	// nothing to encrypt
	if len(macPL.FRMPayload) == 0 {
		return nil
	}

	data, err := macPL.marshalPayload()
	if err != nil {
		return err
	}

	data, err = EncryptFRMPayload(key, p.isUplink(), macPL.FHDR.DevAddr, macPL.FHDR.FCnt, data)
	if err != nil {
		return err
	}

	// store the encrypted data in a DataPayload
	macPL.FRMPayload = []Payload{&DataPayload{Bytes: data}}

	return nil
}

// DecryptFRMPayload decrypts the FRMPayload with the given key.
func (p *PHYPayload) DecryptFRMPayload(key AES128Key) error {
	if err := p.EncryptFRMPayload(key); err != nil {
		return err
	}

	macPL, ok := p.MACPayload.(*MACPayload)
	if !ok {
		return errors.New("lorawan: MACPayload must be of type *MACPayload")
	}

	// the FRMPayload contains MAC commands, which we need to unmarshal
	var err error
	if macPL.FPort != nil && *macPL.FPort == 0 {
		macPL.FRMPayload, err = decodeDataPayloadToMACCommands(p.isUplink(), macPL.FRMPayload)
	}

	return err
}

// DecodeFRMPayloadToMACCommands decodes the (decrypted) FRMPayload bytes into
// MAC commands. Note that after calling DecryptFRMPayload, this method is
// called automatically when FPort=0.
func (p *PHYPayload) DecodeFRMPayloadToMACCommands() error {
	macPL, ok := p.MACPayload.(*MACPayload)
	if !ok {
		return errors.New("lorawan: MACPayload must be of type *MACPayload")
	}

	var err error
	macPL.FRMPayload, err = decodeDataPayloadToMACCommands(p.isUplink(), macPL.FRMPayload)
	return err
}

// DecodeFOptsToMACCommands decodes the (decrypted) FOpts bytes into
// MAC commands.
func (p *PHYPayload) DecodeFOptsToMACCommands() error {
	macPL, ok := p.MACPayload.(*MACPayload)
	if !ok {
		return errors.New("lorawan: MACPayload must be of type *MACPayload")
	}

	if len(macPL.FHDR.FOpts) == 0 {
		return nil
	}

	var err error
	macPL.FHDR.FOpts, err = decodeDataPayloadToMACCommands(p.isUplink(), macPL.FHDR.FOpts)
	return err
}

// MarshalBinary marshals the object in binary form.
func (p PHYPayload) MarshalBinary() ([]byte, error) {
	if p.MACPayload == nil {
		return []byte{}, errors.New("lorawan: MACPayload should not be nil")
	}

	var out []byte
	var b []byte
	var err error

	if b, err = p.MHDR.MarshalBinary(); err != nil {
		return []byte{}, err
	}
	out = append(out, b...)

	if b, err = p.MACPayload.MarshalBinary(); err != nil {
		return []byte{}, err
	}
	out = append(out, b...)
	out = append(out, p.MIC[0:len(p.MIC)]...)
	return out, nil
}

// UnmarshalBinary decodes the object from binary form.
func (p *PHYPayload) UnmarshalBinary(data []byte) error {
	if len(data) < 5 {
		return errors.New("lorawan: at least 5 bytes needed to decode PHYPayload")
	}

	// MHDR
	if err := p.MHDR.UnmarshalBinary(data[0:1]); err != nil {
		return err
	}

	// MACPayload
	switch p.MHDR.MType {
	case JoinRequest:
		p.MACPayload = &JoinRequestPayload{}
	case JoinAccept:
		p.MACPayload = &DataPayload{}
	case RejoinRequest:
		switch data[1] {
		case 0, 2:
			p.MACPayload = &RejoinRequestType02Payload{}
		case 1:
			p.MACPayload = &RejoinRequestType1Payload{}
		default:
			return fmt.Errorf("lorawan: invalid RejoinType %d", data[1])
		}
	case Proprietary:
		p.MACPayload = &DataPayload{}
	default:
		p.MACPayload = &MACPayload{}
	}

	isUplink := p.isUplink()
	if err := p.MACPayload.UnmarshalBinary(isUplink, data[1:len(data)-4]); err != nil {
		return err
	}

	// MIC
	for i := 0; i < 4; i++ {
		p.MIC[i] = data[len(data)-4+i]
	}
	return nil
}

// MarshalText encodes the PHYPayload into base64.
func (p PHYPayload) MarshalText() ([]byte, error) {
	b, err := p.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return []byte(base64.StdEncoding.EncodeToString(b)), nil
}

// UnmarshalText decodes the PHYPayload from base64.
func (p *PHYPayload) UnmarshalText(text []byte) error {
	b, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return err
	}
	return p.UnmarshalBinary(b)
}

// MarshalJSON encodes the PHYPayload into JSON.
func (p PHYPayload) MarshalJSON() ([]byte, error) {
	type phyAlias PHYPayload
	return json.Marshal(phyAlias(p))
}

// isUplink returns a bool indicating if the packet is uplink or downlink.
// Note that for MType Proprietary it can't derrive if the packet is uplink
// or downlink. This is fine (I think) since it is also unknown how to
// calculate the MIC and the format of the MACPayload. A pluggable
// MIC calculation and MACPayload for Proprietary MType is still TODO.
func (p PHYPayload) isUplink() bool {
	switch p.MHDR.MType {
	case JoinRequest, UnconfirmedDataUp, ConfirmedDataUp, RejoinRequest:
		return true
	default:
		return false
	}
}

// EncryptFRMPayload encrypts the FRMPayload (slice of bytes).
// Note that EncryptFRMPayload is used for both encryption and decryption.
func EncryptFRMPayload(key AES128Key, uplink bool, devAddr DevAddr, fCnt uint32, data []byte) ([]byte, error) {
	pLen := len(data)
	if pLen%16 != 0 {
		// append with empty bytes so that len(data) is a multiple of 16
		data = append(data, make([]byte, 16-(pLen%16))...)
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	if block.BlockSize() != 16 {
		return nil, errors.New("lorawan: block size of 16 was expected")
	}

	s := make([]byte, 16)
	a := make([]byte, 16)
	a[0] = 0x01
	if !uplink {
		a[5] = 0x01
	}

	b, err := devAddr.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(a[6:10], b)
	binary.LittleEndian.PutUint32(a[10:14], uint32(fCnt))

	for i := 0; i < len(data)/16; i++ {
		a[15] = byte(i + 1)
		block.Encrypt(s, a)

		for j := 0; j < len(s); j++ {
			data[i*16+j] = data[i*16+j] ^ s[j]
		}
	}

	return data[0:pLen], nil
}

// EncryptFOpts encrypts the FOpts mac-commands.
// For uplink:
//   Set the aFCntDown to false and use the FCntUp
// For downlink if FPort is not set or equals to 0:
//   Set the aFCntDown to false and use the NFCntDown
// For downlink if FPort > 0:
//   Set the aFCntDown to true and use the AFCntDown
func EncryptFOpts(nwkSEncKey AES128Key, aFCntDown, uplink bool, devAddr DevAddr, fCnt uint32, data []byte) ([]byte, error) {
	pLen := len(data)
	if pLen%16 != 0 {
		// make data a multiple of 16
		data = append(data, make([]byte, 16-(pLen%16))...)
	}

	block, err := aes.NewCipher(nwkSEncKey[:])
	if err != nil {
		return nil, err
	}
	if block.BlockSize() != 16 {
		return nil, errors.New("lorawan: block size of 16 was expected")
	}

	s := make([]byte, 16)
	a := make([]byte, 16)
	a[0] = 0x01
	if aFCntDown {
		a[1] = 0x02
	} else {
		a[1] = 0x01
	}

	if !uplink {
		a[5] = 0x01
	}

	b, err := devAddr.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(a[6:10], b)
	binary.LittleEndian.PutUint32(a[10:14], fCnt)

	for i := 0; i < len(data)/16; i++ {
		a[15] = byte(i + 1)
		block.Encrypt(s, a)

		for j := 0; j < len(s); j++ {
			data[i*16+j] = data[i*16+j] ^ s[j]
		}
	}

	return data[0:pLen], nil
}
