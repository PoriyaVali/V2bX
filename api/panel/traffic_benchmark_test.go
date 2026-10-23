package panel

import (
	"encoding/json"
	"testing"
)

// Include JSON serialization: the HTTP layer must still send the same arrays.
// The baseline is the report payload construction used before this change.
func BenchmarkTrafficReportPayload(b *testing.B) {
	users := make([]UserTraffic, 10000)
	for i := range users {
		users[i] = UserTraffic{UID: i + 1, Upload: 12345, Download: 67890}
	}
	b.Run("baseline_slices", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			data := make(map[int][]int64, len(users))
			for _, user := range users {
				data[user.UID] = []int64{user.Upload, user.Download}
			}
			if _, err := json.Marshal(data); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("fixed_arrays", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := json.Marshal(trafficReportData(users)); err != nil {
				b.Fatal(err)
			}
		}
	})
}
