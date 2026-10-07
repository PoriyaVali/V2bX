package sing

import "testing"

func TestConfigPortRefusesWhatWouldWrapAround(t *testing.T) {
	cases := []struct {
		in      string
		want    uint16
		wantErr bool
	}{
		{"443", 443, false},
		{" 8443 ", 8443, false},
		{"65535", 65535, false},
		{"", 0, false},      // unset: 0, as before
		{"https", 0, false}, // not a number: 0, as before
		{"-1", 0, false},    // used to become 65535
		{"70000", 0, true},  // used to become 4464
		{"4294967297", 0, true},
	}
	for _, c := range cases {
		got, err := configPort(c.in)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("configPort(%q) = %d, %v; want %d, error %v", c.in, got, err, c.want, c.wantErr)
		}
	}
}

func TestEarlyDataSizeNeverWrapsToGigabytes(t *testing.T) {
	cases := map[string]uint32{
		"2048":        2048,
		"":            0,
		"-1":          0, // used to become 4294967295
		"x":           0,
		"99999999999": 0,
	}
	for in, want := range cases {
		if got := earlyDataSize(in); got != want {
			t.Errorf("earlyDataSize(%q) = %d, want %d", in, got, want)
		}
	}
}
