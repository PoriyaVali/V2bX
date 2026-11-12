package counter

import "testing"

func TestDepartedReportsARemovedUsersLastTrafficOnce(t *testing.T) {
	var d Departed
	first, again := &TrafficStorage{}, &TrafficStorage{}
	first.UpCounter.Store(10)
	first.DownCounter.Store(20)
	again.UpCounter.Store(1)
	d.Keep(7, first)
	d.Keep(7, again) // removed, added back and removed again before a report
	d.Keep(0, &TrafficStorage{})
	d.Keep(8, &TrafficStorage{})

	if got := d.Take(false); len(got) != 1 || got[0] != (Final{UID: 7, Upload: 11, Download: 20}) {
		t.Fatalf("a look took %+v", got)
	}
	if got := d.Take(true); len(got) != 1 || got[0] != (Final{UID: 7, Upload: 11, Download: 20}) {
		t.Fatalf("the report took %+v", got)
	}
	// The last bytes of a connection that was closing.
	first.DownCounter.Add(5)
	if got := d.Take(true); len(got) != 1 || got[0] != (Final{UID: 7, Download: 5}) {
		t.Fatalf("the next report took %+v", got)
	}
	if got := d.Take(true); got != nil || len(d.users) != 0 {
		t.Fatalf("then %+v, with %d counters kept", got, len(d.users))
	}
}
