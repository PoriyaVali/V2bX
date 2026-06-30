package serverstatus

type SystemStatus struct {
	CPU  float64  `json:"cpu"`
	Mem  MemStat  `json:"mem"`
	Swap MemStat  `json:"swap"`
	Disk DiskStat `json:"disk"`
}

type MemStat struct {
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
}

type DiskStat struct {
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
}
