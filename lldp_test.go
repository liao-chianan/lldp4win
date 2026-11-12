package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

type parsedTLV struct {
	typ   int
	value []byte
}

func parseTLVs(t *testing.T, frame []byte) []parsedTLV {
	t.Helper()
	if len(frame) < 14 {
		t.Fatalf("frame too short: %d", len(frame))
	}
	if et := binary.BigEndian.Uint16(frame[12:14]); et != etherTypeLLDP {
		t.Fatalf("ethertype = %#x", et)
	}
	var out []parsedTLV
	p := frame[14:]
	for len(p) >= 2 {
		hdr := binary.BigEndian.Uint16(p)
		typ, l := int(hdr>>9), int(hdr&0x1ff)
		if len(p) < 2+l {
			t.Fatalf("TLV type %d truncated", typ)
		}
		out = append(out, parsedTLV{typ, p[2 : 2+l]})
		p = p[2+l:]
		if typ == tlvEnd {
			return out
		}
	}
	t.Fatal("missing End TLV")
	return nil
}

func TestBuildFrame(t *testing.T) {
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	f := Frame{
		SrcMAC:     mac,
		ChassisID:  "pc01.example.local",
		PortDesc:   "Intel(R) Ethernet Connection",
		SystemName: "pc01.example.local",
		SystemDesc: "Microsoft Windows 11 Pro 64-bit 10.0.26100",
		TTL:        120,
		IfIndex:    0x01020304,
		MgmtIPv4:   net.ParseIP("192.168.1.10"),
		MgmtIPv6:   net.ParseIP("2001:db8::1"),
		IncludeMED: true,
	}
	b, err := f.Build()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b[0:6], lldpMulticast) || !bytes.Equal(b[6:12], mac) {
		t.Fatalf("bad ethernet header % x", b[:14])
	}
	tlvs := parseTLVs(t, b)
	wantOrder := []int{tlvChassisID, tlvPortID, tlvTTL, tlvPortDesc, tlvSystemName, tlvSystemDesc, tlvSystemCaps,
		tlvMgmtAddress, tlvMgmtAddress, tlvOrgSpecific, tlvOrgSpecific, tlvOrgSpecific, tlvOrgSpecific, tlvOrgSpecific, tlvEnd}
	if len(tlvs) != len(wantOrder) {
		t.Fatalf("got %d TLVs, want %d", len(tlvs), len(wantOrder))
	}
	for i, typ := range wantOrder {
		if tlvs[i].typ != typ {
			t.Errorf("TLV %d type = %d, want %d", i, tlvs[i].typ, typ)
		}
	}
	if string(tlvs[0].value[1:]) != f.ChassisID || tlvs[0].value[0] != chassisSubtypeLocal {
		t.Errorf("chassis = %q", tlvs[0].value)
	}
	if !bytes.Equal(tlvs[1].value, append([]byte{portSubtypeMAC}, mac...)) {
		t.Errorf("port id = % x", tlvs[1].value)
	}
	if binary.BigEndian.Uint16(tlvs[2].value) != 120 {
		t.Errorf("ttl = % x", tlvs[2].value)
	}
	wantMgmt4 := []byte{5, 1, 192, 168, 1, 10, 2, 1, 2, 3, 4, 0}
	if !bytes.Equal(tlvs[7].value, wantMgmt4) {
		t.Errorf("mgmt v4 = % x, want % x", tlvs[7].value, wantMgmt4)
	}
	if len(tlvs[8].value) != 24 || tlvs[8].value[0] != 17 || tlvs[8].value[1] != 2 {
		t.Errorf("mgmt v6 = % x", tlvs[8].value)
	}
}

func TestMinimumFrameAndNoMED(t *testing.T) {
	f := Frame{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, ChassisID: "a", TTL: 120}
	b, err := f.Build()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 60 {
		t.Fatalf("frame len %d < 60", len(b))
	}
	for _, tl := range parseTLVs(t, b) {
		if tl.typ == tlvOrgSpecific || tl.typ == tlvMgmtAddress {
			t.Errorf("unexpected TLV type %d", tl.typ)
		}
	}
}

func TestPortIDText(t *testing.T) {
	f := Frame{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, ChassisID: "pc", PortID: "192.168.1.45", TTL: 120}
	b, err := f.Build()
	if err != nil {
		t.Fatal(err)
	}
	tl := parseTLVs(t, b)[1]
	if tl.typ != tlvPortID || tl.value[0] != portSubtypeLocal || string(tl.value[1:]) != "192.168.1.45" {
		t.Errorf("port id = %d % x", tl.typ, tl.value)
	}
}

func TestShortOSName(t *testing.T) {
	cases := []struct {
		product, release string
		major, build     uint32
		arch, want       string
	}{
		{"Windows 10 Enterprise", "25H2", 10, 26200, "x64", "Windows 11 25H2 x64"},
		{"Windows 10 Pro", "22H2", 10, 19045, "x64", "Windows 10 22H2 x64"},
		{"Windows 10 Pro", "", 10, 17763, "x86", "Windows 10 build 17763 x86"},
		{"Windows Server 2022 Datacenter", "21H2", 10, 20348, "x64", "Windows Server 2022 21H2 x64"},
		{"Windows Server 2012 R2 Standard", "", 6, 9600, "x64", "Windows Server 2012 R2 build 9600 x64"},
		{"Windows 10 Pro", "24H2", 10, 26100, "ARM64", "Windows 11 24H2 ARM64"},
	}
	for _, c := range cases {
		if got := shortOSName(c.product, c.release, c.major, c.build, c.arch); got != c.want {
			t.Errorf("shortOSName(%q,%q,%d) = %q, want %q", c.product, c.release, c.build, got, c.want)
		}
	}
}

func TestTruncateUTF8(t *testing.T) {
	s := "網路卡網路卡" // 每字 3 bytes
	for n, want := range map[int]string{5: "網", 6: "網路", 7: "網路", 8: "網路", 9: "網路卡", 100: s} {
		if got := string(truncate(s, n)); got != want {
			t.Errorf("truncate(%d) = %q, want %q", n, got, want)
		}
	}
}
