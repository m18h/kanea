package dpmap

import (
	"bytes"
	"testing"
)

// TestEncodedSizesMatchTheCSizeof pins every Marshal to the sizeof of the
// C struct it mirrors in kanea.c. A drift here is a map the kernel will
// refuse to write, or worse, one it writes at the wrong offsets.
func TestEncodedSizesMatchTheCSizeof(t *testing.T) {
	cases := []struct {
		name string
		got  []byte
		want int
	}{
		{"svc_key", SvcKey{}.Marshal(), 8},
		{"svc_val", SvcVal{}.Marshal(), 8},
		{"backend_key", BackendKey{}.Marshal(), 8},
		{"backend_val", BackendVal{}.Marshal(), 8},
		{"identity", Identity{}.Marshal(), 12},
		{"allow_key", AllowKey{}.Marshal(), 8},
		{"drop_key", DropKey{}.Marshal(), 8},
		{"ep_stats", EpStats{}.Marshal(), 32},
		{"dp_config", Config{}.Marshal(), 8},
		{"stats_ep key", IPKey([4]byte{}), 4},
		{"stats_svc key", SvcIDKey(0), 2},
		{"svc_key6", SvcKey6{}.Marshal(), 20},
		{"backend_val6", BackendVal6{}.Marshal(), 20},
		{"drop_key6", DropKey6{}.Marshal(), 20},
		{"dp_config6", Config6{}.Marshal(), 32},
		{"stats_ep6 / identity_v6 key", IP6Key([16]byte{}), 16},
	}
	for _, tc := range cases {
		if len(tc.got) != tc.want {
			t.Errorf("%s: encoded %d bytes, C sizeof is %d", tc.name, len(tc.got), tc.want)
		}
	}
}

// TestEndiannessPins fixes the exact bytes of known values: network order
// for IPs and __be16 ports, little-endian (the bpfel object) for
// host-endian integers, padding always zero.
func TestEndiannessPins(t *testing.T) {
	cases := []struct {
		name string
		got  []byte
		want []byte
	}{
		{
			// 10.0.0.1:443/TCP: the IP as wire bytes, 443 = 0x01BB
			// big-endian, proto 6, one pad byte.
			"svc_key",
			SvcKey{VIP: [4]byte{10, 0, 0, 1}, Port: 443, Proto: 6}.Marshal(),
			[]byte{10, 0, 0, 1, 0x01, 0xBB, 6, 0},
		},
		{
			// Host-endian fields little-endian: 0x0102 → 02 01.
			"svc_val",
			SvcVal{SvcID: 0x0102, Count: 3, Gen: 0x04050607}.Marshal(),
			[]byte{0x02, 0x01, 3, 0, 0x07, 0x06, 0x05, 0x04},
		},
		{
			"backend_key",
			BackendKey{SvcID: 7, Index: 2, Gen: 9}.Marshal(),
			[]byte{7, 0, 2, 0, 9, 0, 0, 0},
		},
		{
			// 192.168.1.10:8080; 8080 = 0x1F90 big-endian, two pad bytes.
			"backend_val",
			BackendVal{IP: [4]byte{192, 168, 1, 10}, Port: 8080}.Marshal(),
			[]byte{192, 168, 1, 10, 0x1F, 0x90, 0, 0},
		},
		{
			"identity",
			Identity{ProjectID: 0x0102, ServiceID: 0x0304, Flags: IdentityFlagHost}.Marshal(),
			[]byte{0x02, 0x01, 0, 0, 0x04, 0x03, 0, 0, 1, 0, 0, 0},
		},
		{
			"allow_key",
			AllowKey{DstServiceID: 5, SrcServiceID: 0x0100}.Marshal(),
			[]byte{5, 0, 0, 0, 0x00, 0x01, 0, 0},
		},
		{
			// The metadata address, reason METADATA, three pad bytes.
			"drop_key",
			DropKey{DstIP: [4]byte{169, 254, 169, 254}, Reason: DropReasonMetadata}.Marshal(),
			[]byte{169, 254, 169, 254, 2, 0, 0, 0},
		},
		{
			"ep_stats",
			EpStats{RxBytes: 1, RxPkts: 2, TxBytes: 0x0100, TxPkts: 3}.Marshal(),
			[]byte{
				1, 0, 0, 0, 0, 0, 0, 0,
				2, 0, 0, 0, 0, 0, 0, 0,
				0x00, 0x01, 0, 0, 0, 0, 0, 0,
				3, 0, 0, 0, 0, 0, 0, 0,
			},
		},
		{
			// 10.96.0.0/12 as wire bytes on both halves.
			"dp_config",
			Config{
				ServiceCIDRNet:  [4]byte{10, 96, 0, 0},
				ServiceCIDRMask: [4]byte{255, 240, 0, 0},
			}.Marshal(),
			[]byte{10, 96, 0, 0, 255, 240, 0, 0},
		},
		{
			"stats_ep key",
			IPKey([4]byte{10, 0, 1, 2}),
			[]byte{10, 0, 1, 2},
		},
		{
			"stats_svc key",
			SvcIDKey(0x0102),
			[]byte{0x02, 0x01},
		},
		{
			// [fd10:245::7]:443/TCP; the address as wire bytes, 443 =
			// 0x01BB big-endian, proto 6, one pad byte.
			"svc_key6",
			SvcKey6{
				VIP: [16]byte{
					0xfd, 0x10, 0x02, 0x45, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0x07,
				},
				Port: 443, Proto: 6,
			}.Marshal(),
			[]byte{
				0xfd, 0x10, 0x02, 0x45, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0x07,
				0x01, 0xBB, 6, 0,
			},
		},
		{
			// [fd10:244::a]:8080; 8080 = 0x1F90 big-endian, two pad bytes.
			"backend_val6",
			BackendVal6{
				IP: [16]byte{
					0xfd, 0x10, 0x02, 0x44, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0x0a,
				},
				Port: 8080,
			}.Marshal(),
			[]byte{
				0xfd, 0x10, 0x02, 0x44, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0x0a,
				0x1F, 0x90, 0, 0,
			},
		},
		{
			// fd00:ec2::254 (the IMDS ULA) reason METADATA, three pad bytes.
			"drop_key6",
			DropKey6{
				DstIP: [16]byte{
					0xfd, 0x00, 0x0e, 0xc2, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0x02, 0x54,
				},
				Reason: DropReasonMetadata,
			}.Marshal(),
			[]byte{
				0xfd, 0x00, 0x0e, 0xc2, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0x02, 0x54,
				2, 0, 0, 0,
			},
		},
		{
			// fd10:245::/64 as wire bytes on both halves.
			"dp_config6",
			Config6{
				ServiceCIDRNet: [16]byte{
					0xfd, 0x10, 0x02, 0x45, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0,
				},
				ServiceCIDRMask: [16]byte{
					0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
					0, 0, 0, 0, 0, 0, 0, 0,
				},
			}.Marshal(),
			[]byte{
				0xfd, 0x10, 0x02, 0x45, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0, 0, 0, 0, 0, 0, 0, 0,
			},
		},
	}
	for _, tc := range cases {
		if !bytes.Equal(tc.got, tc.want) {
			t.Errorf("%s: encoded % x, want % x", tc.name, tc.got, tc.want)
		}
	}
}

func TestRoundTrips(t *testing.T) {
	t.Run("svc_key", func(t *testing.T) {
		in := SvcKey{VIP: [4]byte{10, 96, 3, 4}, Port: 65535, Proto: 6}
		var out SvcKey
		if err := out.Unmarshal(in.Marshal()); err != nil {
			t.Fatal(err)
		}
		if out != in {
			t.Errorf("round trip: got %+v, want %+v", out, in)
		}
	})
	t.Run("svc_val", func(t *testing.T) {
		in := SvcVal{SvcID: 65535, Count: 1, Gen: 0xFFFFFFFF}
		var out SvcVal
		if err := out.Unmarshal(in.Marshal()); err != nil {
			t.Fatal(err)
		}
		if out != in {
			t.Errorf("round trip: got %+v, want %+v", out, in)
		}
	})
	t.Run("backend_key", func(t *testing.T) {
		in := BackendKey{SvcID: 1, Index: 16383, Gen: 2}
		var out BackendKey
		if err := out.Unmarshal(in.Marshal()); err != nil {
			t.Fatal(err)
		}
		if out != in {
			t.Errorf("round trip: got %+v, want %+v", out, in)
		}
	})
	t.Run("backend_val", func(t *testing.T) {
		in := BackendVal{IP: [4]byte{172, 16, 0, 9}, Port: 1}
		var out BackendVal
		if err := out.Unmarshal(in.Marshal()); err != nil {
			t.Fatal(err)
		}
		if out != in {
			t.Errorf("round trip: got %+v, want %+v", out, in)
		}
	})
	t.Run("identity", func(t *testing.T) {
		in := Identity{ProjectID: 42, ServiceID: 7, Flags: 0}
		var out Identity
		if err := out.Unmarshal(in.Marshal()); err != nil {
			t.Fatal(err)
		}
		if out != in {
			t.Errorf("round trip: got %+v, want %+v", out, in)
		}
	})
	t.Run("allow_key", func(t *testing.T) {
		in := AllowKey{DstServiceID: 9, SrcServiceID: 8}
		var out AllowKey
		if err := out.Unmarshal(in.Marshal()); err != nil {
			t.Fatal(err)
		}
		if out != in {
			t.Errorf("round trip: got %+v, want %+v", out, in)
		}
	})
	t.Run("drop_key", func(t *testing.T) {
		in := DropKey{DstIP: [4]byte{10, 0, 0, 7}, Reason: DropReasonNoBackend}
		var out DropKey
		if err := out.Unmarshal(in.Marshal()); err != nil {
			t.Fatal(err)
		}
		if out != in {
			t.Errorf("round trip: got %+v, want %+v", out, in)
		}
	})
	t.Run("ep_stats", func(t *testing.T) {
		in := EpStats{RxBytes: 1 << 40, RxPkts: 3, TxBytes: 9, TxPkts: 1 << 33}
		var out EpStats
		if err := out.Unmarshal(in.Marshal()); err != nil {
			t.Fatal(err)
		}
		if out != in {
			t.Errorf("round trip: got %+v, want %+v", out, in)
		}
	})
	t.Run("dp_config", func(t *testing.T) {
		in := Config{ServiceCIDRNet: [4]byte{10, 96, 0, 0}, ServiceCIDRMask: [4]byte{255, 240, 0, 0}}
		var out Config
		if err := out.Unmarshal(in.Marshal()); err != nil {
			t.Fatal(err)
		}
		if out != in {
			t.Errorf("round trip: got %+v, want %+v", out, in)
		}
	})
	t.Run("svc_key6", func(t *testing.T) {
		in := SvcKey6{VIP: [16]byte{0xfd, 0x10, 15: 0x09}, Port: 65535, Proto: 6}
		var out SvcKey6
		if err := out.Unmarshal(in.Marshal()); err != nil {
			t.Fatal(err)
		}
		if out != in {
			t.Errorf("round trip: got %+v, want %+v", out, in)
		}
	})
	t.Run("backend_val6", func(t *testing.T) {
		in := BackendVal6{IP: [16]byte{0xfd, 0x10, 15: 0x0a}, Port: 1}
		var out BackendVal6
		if err := out.Unmarshal(in.Marshal()); err != nil {
			t.Fatal(err)
		}
		if out != in {
			t.Errorf("round trip: got %+v, want %+v", out, in)
		}
	})
	t.Run("drop_key6", func(t *testing.T) {
		in := DropKey6{DstIP: [16]byte{0xfe, 0x80, 15: 0x01}, Reason: DropReasonLinkLocal}
		var out DropKey6
		if err := out.Unmarshal(in.Marshal()); err != nil {
			t.Fatal(err)
		}
		if out != in {
			t.Errorf("round trip: got %+v, want %+v", out, in)
		}
	})
	t.Run("dp_config6", func(t *testing.T) {
		in := Config6{
			ServiceCIDRNet:  [16]byte{0xfd, 0x10, 0x02, 0x45},
			ServiceCIDRMask: [16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		}
		var out Config6
		if err := out.Unmarshal(in.Marshal()); err != nil {
			t.Fatal(err)
		}
		if out != in {
			t.Errorf("round trip: got %+v, want %+v", out, in)
		}
	})
}

// TestBackendKeyIsSharedAcrossFamilies pins the design decision that
// svc_backends6 reuses struct backend_key verbatim: one generation-flip
// mechanism for both families (dpmap.FlipPlan needs no v6 twin).
func TestBackendKeyIsSharedAcrossFamilies(t *testing.T) {
	if BackendKeySize != 8 {
		t.Fatalf("backend_key size = %d; the v6 map declared the same 8-byte key", BackendKeySize)
	}
}

// TestUnmarshalRefusesWrongLengths: a short or long buffer is an error,
// never a partial decode.
func TestUnmarshalRefusesWrongLengths(t *testing.T) {
	long := make([]byte, 64)
	for _, n := range []int{0, 1, 7, 64} {
		b := long[:n]
		if err := (&SvcKey{}).Unmarshal(b); err == nil && n != SvcKeySize {
			t.Errorf("svc_key accepted %d bytes", n)
		}
		if err := (&SvcVal{}).Unmarshal(b); err == nil && n != SvcValSize {
			t.Errorf("svc_val accepted %d bytes", n)
		}
		if err := (&BackendKey{}).Unmarshal(b); err == nil && n != BackendKeySize {
			t.Errorf("backend_key accepted %d bytes", n)
		}
		if err := (&BackendVal{}).Unmarshal(b); err == nil && n != BackendValSize {
			t.Errorf("backend_val accepted %d bytes", n)
		}
		if err := (&Identity{}).Unmarshal(b); err == nil && n != IdentitySize {
			t.Errorf("identity accepted %d bytes", n)
		}
		if err := (&AllowKey{}).Unmarshal(b); err == nil && n != AllowKeySize {
			t.Errorf("allow_key accepted %d bytes", n)
		}
		if err := (&DropKey{}).Unmarshal(b); err == nil && n != DropKeySize {
			t.Errorf("drop_key accepted %d bytes", n)
		}
		if err := (&EpStats{}).Unmarshal(b); err == nil && n != EpStatsSize {
			t.Errorf("ep_stats accepted %d bytes", n)
		}
		if err := (&Config{}).Unmarshal(b); err == nil && n != ConfigSize {
			t.Errorf("dp_config accepted %d bytes", n)
		}
		if err := (&SvcKey6{}).Unmarshal(b); err == nil && n != SvcKey6Size {
			t.Errorf("svc_key6 accepted %d bytes", n)
		}
		if err := (&BackendVal6{}).Unmarshal(b); err == nil && n != BackendVal6Size {
			t.Errorf("backend_val6 accepted %d bytes", n)
		}
		if err := (&DropKey6{}).Unmarshal(b); err == nil && n != DropKey6Size {
			t.Errorf("drop_key6 accepted %d bytes", n)
		}
		if err := (&Config6{}).Unmarshal(b); err == nil && n != Config6Size {
			t.Errorf("dp_config6 accepted %d bytes", n)
		}
	}
}

func TestPinPath(t *testing.T) {
	if got, want := PinPath(MapSvcV4), "/sys/fs/bpf/kanea/svc_v4"; got != want {
		t.Errorf("PinPath(svc_v4) = %q, want %q", got, want)
	}
}
