package lorawan

import (
	"database/sql/driver"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// JoinType defines the join-request type.
type JoinType uint8

// Join-request types.
const (
	JoinRequestType    JoinType = 0xff
	RejoinRequestType0 JoinType = 0x00
	RejoinRequestType1 JoinType = 0x01
	RejoinRequestType2 JoinType = 0x02
)

// EUI64 data type
type EUI64 [8]byte

// MarshalText implements encoding.TextMarshaler.
func (e EUI64) MarshalText() ([]byte, error) {
	return []byte(e.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (e *EUI64) UnmarshalText(text []byte) error {
	b, err := hex.DecodeString(string(text))
	if err != nil {
		return err
	}
	if len(e) != len(b) {
		return fmt.Errorf("lorawan: exactly %d bytes are expected", len(e))
	}
	copy(e[:], b)
	return nil
}

// String implement fmt.Stringer.
func (e EUI64) String() string {
	return hex.EncodeToString(e[:])
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (e EUI64) MarshalBinary() ([]byte, error) {
	out := make([]byte, len(e))
	// little endian
	for i, v := range e {
		out[len(e)-i-1] = v
	}
	return out, nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (e *EUI64) UnmarshalBinary(data []byte) error {
	if len(data) != len(e) {
		return fmt.Errorf("lorawan: %d bytes of data are expected", len(e))
	}
	for i, v := range data {
		// little endian
		e[len(e)-i-1] = v
	}
	return nil
}

// Scan implements sql.Scanner.
func (e *EUI64) Scan(src interface{}) error {
	b, ok := src.([]byte)
	if !ok {
		return errors.New("lorawan: []byte type expected")
	}
	if len(b) != len(e) {
		return fmt.Errorf("lorawan: []byte must have length %d", len(e))
	}
	copy(e[:], b)
	return nil
}

// Value implements driver.Valuer.
func (e EUI64) Value() (driver.Value, error) {
	return e[:], nil
}

// DevNonce represents the dev-nonce.
type DevNonce uint16

// MarshalBinary implements encoding.BinaryMarshaler.
func (n DevNonce) MarshalBinary() ([]byte, error) {
	out := make([]byte, 2)
	binary.LittleEndian.PutUint16(out, uint16(n))
	return out, nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (n *DevNonce) UnmarshalBinary(data []byte) error {
	if len(data) != 2 {
		return errors.New("lorawan: 2 bytes are expected")
	}
	*n = DevNonce(binary.LittleEndian.Uint16(data))
	return nil
}

// JoinNonce represents the join-nonce.
// Note that the max value is 2^24 - 1 = 16777215.
type JoinNonce uint32

// MarshalBinary implements encoding.BinaryMarshaler.
func (n JoinNonce) MarshalBinary() ([]byte, error) {
	if n >= (1 << 24) {
		return nil, errors.New("lorawan: max value is 2^24 - 1 (16777215)")
	}

	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(n))
	return b[:3], nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (n *JoinNonce) UnmarshalBinary(data []byte) error {
	if len(data) != 3 {
		return errors.New("lorawan: 3 bytes are expected")
	}

	b := make([]byte, 4)
	copy(b[:3], data)
	*n = JoinNonce(binary.LittleEndian.Uint32(b))

	return nil
}

// Payload is the interface that every payload needs to implement.
// Since it might be a MACPayload, an indication must be given if
// the direction is uplink or downlink (it has different payloads
// for the same CID, based on direction).
type Payload interface {
	MarshalBinary() (data []byte, err error)
	UnmarshalBinary(uplink bool, data []byte) error
}

// DataPayload represents a slice of bytes.
type DataPayload struct {
	Bytes []byte `json:"bytes"`
}

// MarshalBinary marshals the object in binary form.
func (p DataPayload) MarshalBinary() ([]byte, error) {
	return p.Bytes, nil
}

// UnmarshalBinary decodes the object from binary form.
func (p *DataPayload) UnmarshalBinary(uplink bool, data []byte) error {
	p.Bytes = make([]byte, len(data))
	copy(p.Bytes, data)
	return nil
}

// JoinRequestPayload represents the join-request message payload.
type JoinRequestPayload struct {
	JoinEUI  EUI64    `json:"joinEUI"`
	DevEUI   EUI64    `json:"devEUI"`
	DevNonce DevNonce `json:"devNonce"`
}

// MarshalBinary marshals the object in binary form.
func (p JoinRequestPayload) MarshalBinary() ([]byte, error) {
	out := make([]byte, 0, 18)
	b, err := p.JoinEUI.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out = append(out, b...)
	b, err = p.DevEUI.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out = append(out, b...)

	b, err = p.DevNonce.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out = append(out, b...)

	return out, nil
}

// UnmarshalBinary decodes the object from binary form.
func (p *JoinRequestPayload) UnmarshalBinary(uplink bool, data []byte) error {
	if len(data) != 18 {
		return errors.New("lorawan: 18 bytes of data are expected")
	}
	if err := p.JoinEUI.UnmarshalBinary(data[0:8]); err != nil {
		return err
	}
	if err := p.DevEUI.UnmarshalBinary(data[8:16]); err != nil {
		return err
	}
	if err := p.DevNonce.UnmarshalBinary(data[16:18]); err != nil {
		return err
	}

	return nil
}

// CFList represents a list of channel frequencies. Each frequency is in Hz
// and must be multiple of 100, (since the frequency will be divided by 100
// on encoding), the max allowed value is 2^24-1 * 100.
type CFList [5]uint32

// MarshalBinary marshals the object in binary form.
func (l CFList) MarshalBinary() ([]byte, error) {
	out := make([]byte, 0, 16)
	for _, f := range l {
		if f%100 != 0 {
			return nil, errors.New("lorawan: frequency must be a multiple of 100")
		}
		f = f / 100
		if f > 16777215 { // 2^24 - 1
			return nil, errors.New("lorawan: max value of frequency is 2^24-1")
		}
		b := make([]byte, 4, 4)
		binary.LittleEndian.PutUint32(b, f)
		out = append(out, b[:3]...)
	}
	// last byte is 0 / RFU
	return append(out, 0), nil
}

// UnmarshalBinary decodes the object from binary form.
func (l *CFList) UnmarshalBinary(data []byte) error {
	if len(data) != 16 {
		return errors.New("lorawan: 16 bytes of data are expected")
	}
	for i := 0; i < 5; i++ {
		l[i] = binary.LittleEndian.Uint32([]byte{
			data[i*3],
			data[i*3+1],
			data[i*3+2],
			0,
		}) * 100
	}

	return nil
}

// JoinAcceptPayload represents the join-accept message payload.
type JoinAcceptPayload struct {
	JoinNonce  JoinNonce  `json:"joinNonce"`
	HomeNetID  NetID      `json:"homeNetID"`
	DevAddr    DevAddr    `json:"devAddr"`
	DLSettings DLSettings `json:"dlSettings"`
	RXDelay    uint8      `json:"rxDelay"` // 0=1s, 1=1s, 2=2s, ... 15=15s
	CFList     *CFList    `json:"cFlist"`
}

// MarshalBinary marshals the object in binary form.
func (p JoinAcceptPayload) MarshalBinary() ([]byte, error) {
	if p.RXDelay > 15 {
		return nil, errors.New("lorawan: the max value of RXDelay is 15")
	}

	out := make([]byte, 0, 12)

	b, err := p.JoinNonce.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out = append(out, b...)

	b, err = p.HomeNetID.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out = append(out, b...)

	b, err = p.DevAddr.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out = append(out, b...)

	b, err = p.DLSettings.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out = append(out, b...)
	out = append(out, byte(p.RXDelay))

	if p.CFList != nil {
		b, err = p.CFList.MarshalBinary()
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}

	return out, nil
}

// UnmarshalBinary decodes the object from binary form.
func (p *JoinAcceptPayload) UnmarshalBinary(uplink bool, data []byte) error {
	l := len(data)
	if l != 12 && l != 28 {
		return errors.New("lorawan: 12 or 28 bytes of data are expected (28 bytes if CFList is present)")
	}

	if err := p.JoinNonce.UnmarshalBinary(data[0:3]); err != nil {
		return err
	}

	if err := p.HomeNetID.UnmarshalBinary(data[3:6]); err != nil {
		return err
	}

	if err := p.DevAddr.UnmarshalBinary(data[6:10]); err != nil {
		return err
	}
	if err := p.DLSettings.UnmarshalBinary(data[10:11]); err != nil {
		return err
	}
	p.RXDelay = uint8(data[11])

	if l == 28 {
		p.CFList = &CFList{}
		if err := p.CFList.UnmarshalBinary(data[12:]); err != nil {
			return err
		}
	}

	return nil
}

// RejoinRequestType02Payload represents a rejoin-request of type 0 or 2.
type RejoinRequestType02Payload struct {
	RejoinType uint8  `json:"rejoinType"`
	NetID      NetID  `json:"netID"`
	DevEUI     EUI64  `json:"devEUI"`
	RJCount0   uint16 `json:"rjCount0"`
}

// MarshalBinary marshals the object in binary form.
func (p RejoinRequestType02Payload) MarshalBinary() ([]byte, error) {
	if p.RejoinType != 0 && p.RejoinType != 2 {
		return nil, errors.New("lorawan: RejoinType must be 0 or 2")
	}

	out := make([]byte, 0, 14)

	out = append(out, p.RejoinType)

	b, err := p.NetID.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out = append(out, b...)

	b, err = p.DevEUI.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out = append(out, b...)

	b = make([]byte, 2)
	binary.LittleEndian.PutUint16(b, p.RJCount0)
	out = append(out, b...)

	return out, nil
}

// UnmarshalBinary decodes the object from binary form.
func (p *RejoinRequestType02Payload) UnmarshalBinary(uplink bool, data []byte) error {
	if len(data) != 14 {
		return errors.New("lorawan: 14 bytes of data are expected")
	}

	p.RejoinType = data[0]

	if err := p.NetID.UnmarshalBinary(data[1:4]); err != nil {
		return err
	}

	if err := p.DevEUI.UnmarshalBinary(data[4:12]); err != nil {
		return err
	}

	p.RJCount0 = binary.LittleEndian.Uint16(data[12:14])

	return nil
}

// RejoinRequestType1Payload represents a rejoin-request of type 1.
type RejoinRequestType1Payload struct {
	RejoinType uint8  `json:"rejoinRequest"`
	JoinEUI    EUI64  `json:"joinEUI"`
	DevEUI     EUI64  `json:"devEUI"`
	RJCount1   uint16 `json:"rjCount1"`
}

// MarshalBinary marshals the object in binary form.
func (p RejoinRequestType1Payload) MarshalBinary() ([]byte, error) {
	if p.RejoinType != 1 {
		return nil, errors.New("lorawan: RejoinType must be 1")
	}

	out := make([]byte, 0, 19)

	out = append(out, p.RejoinType)

	b, err := p.JoinEUI.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out = append(out, b...)

	b, err = p.DevEUI.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out = append(out, b...)

	b = make([]byte, 2)
	binary.LittleEndian.PutUint16(b, p.RJCount1)
	out = append(out, b...)

	return out, nil
}

// UnmarshalBinary decodes the object from binary form.
func (p *RejoinRequestType1Payload) UnmarshalBinary(uplink bool, data []byte) error {
	if len(data) != 19 {
		return errors.New("lorawan: 19 bytes of data are expected")
	}

	p.RejoinType = data[0]

	if err := p.JoinEUI.UnmarshalBinary(data[1:9]); err != nil {
		return err
	}

	if err := p.DevEUI.UnmarshalBinary(data[9:17]); err != nil {
		return err
	}

	p.RJCount1 = binary.LittleEndian.Uint16(data[17:19])

	return nil
}
