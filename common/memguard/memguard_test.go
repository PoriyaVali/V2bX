package memguard

import "testing"

const sampleMeminfo = `MemTotal:        2014628 kB
MemFree:          112344 kB
MemAvailable:     743120 kB
Buffers:           61240 kB
`

func TestMeminfoField(t *testing.T) {
	if got := meminfoField(sampleMeminfo, "MemTotal"); got != 2014628*1024 {
		t.Fatalf("MemTotal = %d", got)
	}
	if got := meminfoField(sampleMeminfo, "MemAvailable"); got != 743120*1024 {
		t.Fatalf("MemAvailable = %d", got)
	}
	// "MemFree" must not match "MemFreeX" and a missing field is 0.
	if got := meminfoField(sampleMeminfo, "SwapTotal"); got != 0 {
		t.Fatalf("missing field = %d", got)
	}
	if got := meminfoField("VmRSS:\t  51200 kB\n", "VmRSS"); got != 51200*1024 {
		t.Fatalf("VmRSS = %d", got)
	}
}

func TestCgroupLimit(t *testing.T) {
	cases := map[string]uint64{
		"max\n":                 0, // cgroup v2, unlimited
		"9223372036854771712\n": 0, // cgroup v1, unlimited
		"":                      0,
		"garbage":               0,
		"1073741824\n":          1 << 30,
	}
	for in, want := range cases {
		if got := cgroupLimit(in); got != want {
			t.Errorf("cgroupLimit(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestSmaller(t *testing.T) {
	if smaller(0, 5) != 5 || smaller(5, 0) != 5 || smaller(3, 5) != 3 || smaller(0, 0) != 0 {
		t.Fatal("smaller picks wrong")
	}
}

func TestPressureOf(t *testing.T) {
	const gib = 1 << 30
	cases := []struct {
		ceiling, avail uint64
		want           Pressure
	}{
		{2 * gib, gib, PressureNone},
		{2 * gib, 150 << 20, PressureLow},     // ~7%
		{2 * gib, 80 << 20, PressureCritical}, // ~4%
		{0, 10, PressureNone},                 // ceiling unknown: never act
		{2 * gib, 0, PressureNone},            // availability unknown
	}
	for _, c := range cases {
		if got := pressureOf(c.ceiling, c.avail); got != c.want {
			t.Errorf("pressureOf(%d, %d) = %d, want %d", c.ceiling, c.avail, got, c.want)
		}
	}
}
