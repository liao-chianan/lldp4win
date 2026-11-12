package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"unicode/utf8"
)

// LLDP 常數
var lldpMulticast = net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e} // nearest-customer-bridge

const (
	etherTypeLLDP = 0x88cc

	tlvEnd         = 0
	tlvChassisID   = 1
	tlvPortID      = 2
	tlvTTL         = 3
	tlvPortDesc    = 4
	tlvSystemName  = 5
	tlvSystemDesc  = 6
	tlvSystemCaps  = 7
	tlvMgmtAddress = 8
	tlvOrgSpecific = 127

	chassisSubtypeLocal = 7
	portSubtypeMAC      = 3
	portSubtypeLocal    = 7

	mgmtAddrFamilyIPv4 = 1
	mgmtAddrFamilyIPv6 = 2
	ifSubtypeIfIndex   = 2

	capStation = 0x0080

	maxTLVValue = 511 // TLV 長度欄位為 9 bits
)

// Frame 描述要送出的一個 LLDPDU 內容。
type Frame struct {
	SrcMAC     net.HardwareAddr
	ChassisID  string // 主機 DNS 名稱
	PortID     string // 空字串 = 使用 MAC（subtype 3）；否則以文字送出（subtype 7）
	PortDesc   string // 網卡描述
	SystemName string
	SystemDesc string // 作業系統描述
	TTL        uint16
	IfIndex    uint32
	MgmtIPv4   net.IP // 可為 nil
	MgmtIPv6   net.IP // 可為 nil
	IncludeMED bool   // 是否加上 IEEE 802.3 / LLDP-MED TLV（與原版行為相同）
}

type builder struct{ b []byte }

func (w *builder) tlv(typ int, value []byte) {
	if len(value) > maxTLVValue {
		value = value[:maxTLVValue]
	}
	hdr := uint16(typ)<<9 | uint16(len(value))
	w.b = binary.BigEndian.AppendUint16(w.b, hdr)
	w.b = append(w.b, value...)
}

// truncate 將字串截到 max 位元組，避免切在 UTF-8 字元中間。
func truncate(s string, max int) []byte {
	b := []byte(s)
	if len(b) <= max {
		return b
	}
	b = b[:max]
	for i := 0; i < utf8.UTFMax && len(b) > 0 && !utf8.Valid(b); i++ {
		b = b[:len(b)-1]
	}
	return b
}

func mgmtAddrTLV(family byte, ip []byte, ifIndex uint32) []byte {
	v := []byte{byte(1 + len(ip)), family}
	v = append(v, ip...)
	v = append(v, ifSubtypeIfIndex)
	v = binary.BigEndian.AppendUint32(v, ifIndex)
	v = append(v, 0) // OID length
	return v
}

// Build 產生完整的乙太網路訊框（含 header）。
func (f *Frame) Build() ([]byte, error) {
	if len(f.SrcMAC) != 6 {
		return nil, fmt.Errorf("invalid source MAC %v", f.SrcMAC)
	}
	w := &builder{b: make([]byte, 0, 512)}
	w.b = append(w.b, lldpMulticast...)
	w.b = append(w.b, f.SrcMAC...)
	w.b = binary.BigEndian.AppendUint16(w.b, etherTypeLLDP)

	// 必要 TLV：Chassis ID / Port ID / TTL
	w.tlv(tlvChassisID, append([]byte{chassisSubtypeLocal}, truncate(f.ChassisID, 255)...))
	if f.PortID != "" {
		w.tlv(tlvPortID, append([]byte{portSubtypeLocal}, truncate(f.PortID, 255)...))
	} else {
		w.tlv(tlvPortID, append([]byte{portSubtypeMAC}, f.SrcMAC...))
	}
	w.tlv(tlvTTL, binary.BigEndian.AppendUint16(nil, f.TTL))

	// 選用 TLV
	if f.PortDesc != "" {
		w.tlv(tlvPortDesc, truncate(f.PortDesc, 255))
	}
	if f.SystemName != "" {
		w.tlv(tlvSystemName, truncate(f.SystemName, 255))
	}
	if f.SystemDesc != "" {
		w.tlv(tlvSystemDesc, truncate(f.SystemDesc, 255))
	}
	caps := binary.BigEndian.AppendUint16(nil, capStation)
	caps = binary.BigEndian.AppendUint16(caps, capStation)
	w.tlv(tlvSystemCaps, caps)

	if ip4 := f.MgmtIPv4.To4(); ip4 != nil {
		w.tlv(tlvMgmtAddress, mgmtAddrTLV(mgmtAddrFamilyIPv4, ip4, f.IfIndex))
	}
	if f.MgmtIPv6 != nil && f.MgmtIPv6.To4() == nil {
		if ip6 := f.MgmtIPv6.To16(); ip6 != nil {
			w.tlv(tlvMgmtAddress, mgmtAddrTLV(mgmtAddrFamilyIPv6, ip6, f.IfIndex))
		}
	}

	if f.IncludeMED {
		// IEEE 802.3 - MAC/PHY Configuration/Status
		w.tlv(tlvOrgSpecific, []byte{0x00, 0x12, 0x0f, 0x01, 0x02, 0x80, 0x00, 0x00, 0x1e})
		// IEEE 802.3 - Maximum Frame Size (1518)
		w.tlv(tlvOrgSpecific, []byte{0x00, 0x12, 0x0f, 0x04, 0x05, 0xee})
		// TIA TR-41 (LLDP-MED) - Media Capabilities, Endpoint Class III
		w.tlv(tlvOrgSpecific, []byte{0x00, 0x12, 0xbb, 0x01, 0x01, 0xee, 0x03})
		// TIA TR-41 (LLDP-MED) - Network Policy: Softphone Voice (unknown policy)
		w.tlv(tlvOrgSpecific, []byte{0x00, 0x12, 0xbb, 0x02, 0x06, 0x80, 0x00, 0x00})
		// TIA TR-41 (LLDP-MED) - Network Policy: Video Conferencing (unknown policy)
		w.tlv(tlvOrgSpecific, []byte{0x00, 0x12, 0xbb, 0x02, 0x07, 0x80, 0x00, 0x00})
	}

	w.tlv(tlvEnd, nil)

	// 乙太網路最小訊框 60 bytes（不含 FCS）
	for len(w.b) < 60 {
		w.b = append(w.b, 0)
	}
	return w.b, nil
}
