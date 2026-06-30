//go:build !linux

package serverstatus

func GetSystemStatus() (*SystemStatus, error) {
	return &SystemStatus{}, nil
}
