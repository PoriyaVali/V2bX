package limiter

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/PoriyaVali/V2bX/api/panel"
	"github.com/PoriyaVali/V2bX/common/format"
	"github.com/PoriyaVali/V2bX/conf"
)

// The per-connection path, as every core runs it: find the node's limiter,
// then check the user. Parallel, because a node serves many connections at
// once on every core of the machine.
func BenchmarkConnectionPath_Parallel(b *testing.B) {
	Init()
	const tag = "bench-node"
	users := make([]panel.UserInfo, 1000)
	alive := map[int]int{}
	for i := range users {
		users[i] = panel.UserInfo{Id: i + 1, Uuid: "uuid-" + strconv.Itoa(i), DeviceLimit: 3, SpeedLimit: 0}
		alive[i+1] = 1
	}
	AddLimiter(tag, &conf.LimitConfig{}, users, alive)
	l0, _ := GetLimiter(tag)
	for i := range users {
		l0.CheckLimit(format.UserTag(tag, users[i].Uuid), fmt.Sprintf("10.0.%d.%d", i/250, i%250), true, true)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			u := &users[i%len(users)]
			l, err := GetLimiter(tag)
			if err != nil {
				b.Fatal(err)
			}
			l.CheckLimit(format.UserTag(tag, u.Uuid), fmt.Sprintf("10.0.%d.%d", (i%len(users))/250, (i%len(users))%250), true, true)
			i++
		}
	})
}

func BenchmarkUserTag(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = format.UserTag("[https://panel.example.com]-vless:12", "3b1f6c1e-5d7a-4c55-9b0e-6f2d7e8a9c10")
	}
}

func BenchmarkGetLimiter_Parallel(b *testing.B) {
	Init()
	for i := 0; i < 8; i++ {
		AddLimiter("node-"+strconv.Itoa(i), &conf.LimitConfig{}, nil, nil)
	}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = GetLimiter("node-3")
		}
	})
}
