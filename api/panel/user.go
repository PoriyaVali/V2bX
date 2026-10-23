package panel

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"encoding/json/v2"

	"github.com/vmihailenco/msgpack/v5"
)

// ErrUserListNotModified reports a 304 from the panel: the list has not changed
// since the last poll, so the caller must keep the one it already holds.
//
// This has to be tellable apart from a successful reply carrying an EMPTY list,
// which means the opposite - nobody is authorised on this node any more and
// every user must be torn down. Both used to arrive as a nil slice and a nil
// error, and the caller could only test len() == 0, so it read "everyone was
// removed" as "nothing changed" and kept serving users the panel had already
// cut off. They stayed connected until the process restarted.
var ErrUserListNotModified = errors.New("user list not modified")

type OnlineUser struct {
	UID int
	IP  string
}

type UserInfo struct {
	Id          int    `json:"id" msgpack:"id"`
	Uuid        string `json:"uuid" msgpack:"uuid"`
	SpeedLimit  int    `json:"speed_limit" msgpack:"speed_limit"`
	DeviceLimit int    `json:"device_limit" msgpack:"device_limit"`
}

type UserListBody struct {
	Users []UserInfo `json:"users" msgpack:"users"`
}

type AliveMap struct {
	Alive map[int]int `json:"alive"`
}

// ResetUserCache makes the next poll fetch a full list after an application
// failure. A parsed response is not necessarily a successfully applied list.
func (c *Client) ResetUserCache() {
	c.userEtag = ""
}

// GetUserList will pull user from v2board
func (c *Client) GetUserList() ([]UserInfo, error) {
	const path = "/api/v1/server/UniProxy/user"
	r, err := c.client.R().
		SetHeader("If-None-Match", c.userEtag).
		SetHeader("X-Response-Format", "msgpack").
		SetDoNotParseResponse(true).
		Get(path)
	if r == nil || r.RawResponse == nil {
		return nil, fmt.Errorf("received nil response or raw response")
	}
	defer r.RawResponse.Body.Close()

	if r.StatusCode() == 304 {
		return nil, ErrUserListNotModified
	}

	if err = c.checkResponse(r, path, err); err != nil {
		return nil, err
	}
	limit := c.client.ResponseBodyLimit
	if limit <= 0 {
		limit = maxPanelResponseBytes
	}
	reader := &io.LimitedReader{R: r.RawResponse.Body, N: int64(limit) + 1}
	userlist := &UserListBody{}
	if strings.Contains(r.Header().Get("Content-Type"), "application/x-msgpack") {
		decoder := msgpack.NewDecoder(reader)
		if err := decodeMsgpackUserList(decoder, userlist); err != nil {
			return nil, fmt.Errorf("decode user list error: %w", err)
		}
	} else {
		// Decode the entire top-level envelope before remembering its ETag.
		// Scanning tokens for the first "users" also matched nested metadata or
		// a string value, and accepted truncated/trailing-invalid responses as
		// an empty list that would revoke every user's access.
		if err := json.UnmarshalRead(reader, userlist); err != nil {
			return nil, fmt.Errorf("decode user list error: %w", err)
		}
	}
	if reader.N == 0 {
		return nil, fmt.Errorf("user list exceeds %d bytes", limit)
	}
	if userlist.Users == nil {
		return nil, fmt.Errorf(`decode user list error: expected "users" array`)
	}
	for i, user := range userlist.Users {
		if user.Id <= 0 || strings.TrimSpace(user.Uuid) == "" {
			return nil, fmt.Errorf("decode user list error: invalid identity at index %d", i)
		}
	}
	c.userEtag = r.Header().Get("ETag")
	return userlist.Users, nil
}

func decodeMsgpackUserList(decoder *msgpack.Decoder, userlist *UserListBody) error {
	fields, err := decoder.DecodeMapLen()
	if err != nil {
		return err
	}
	if fields < 0 {
		return fmt.Errorf("expected user-list object")
	}
	seen := make(map[string]struct{})
	for i := 0; i < fields; i++ {
		name, err := decoder.DecodeString()
		if err != nil {
			return err
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("duplicate member %q", name)
		}
		seen[name] = struct{}{}
		if name == "users" {
			n, err := decoder.DecodeArrayLen()
			if err != nil {
				return err
			}
			if n < 0 {
				return fmt.Errorf("expected users array")
			}
			// A MessagePack array header alone can claim billions of users.
			// Grow as records arrive, rather than allocating from that claim.
			userlist.Users = make([]UserInfo, 0, min(n, 1024))
			for j := 0; j < n; j++ {
				userlist.Users = append(userlist.Users, UserInfo{})
				if err := decoder.Decode(&userlist.Users[j]); err != nil {
					return err
				}
			}
		} else if err := decoder.Skip(); err != nil {
			return err
		}
	}
	if _, err := decoder.PeekCode(); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("unexpected data after user-list object")
	}
	return nil
}

// GetUserAlive fetches the fleet-wide alive_ip count per user.
//
// A failure is returned as an error. It used to come back as an empty map with
// no error, which the caller installed - so a single failed poll reset every
// user's device count to zero until the next one.
func (c *Client) GetUserAlive() (map[int]int, error) {
	const path = "/api/v1/server/UniProxy/alivelist"
	r, err := c.client.R().
		ForceContentType("application/json").
		Get(path)
	if err = c.checkResponse(r, path, err); err != nil {
		return nil, err
	}
	alive := &AliveMap{}
	if err := json.Unmarshal(r.Body(), alive); err != nil {
		return nil, fmt.Errorf("decode alive list: %w", err)
	}
	if alive.Alive == nil {
		return nil, fmt.Errorf(`decode alive list: expected "alive" object`)
	}
	for uid, count := range alive.Alive {
		if uid <= 0 || count < 0 {
			return nil, fmt.Errorf("decode alive list: invalid user or device count")
		}
	}
	c.AliveMap = alive
	return alive.Alive, nil
}

type UserTraffic struct {
	UID      int
	Upload   int64
	Download int64
}

// ReportUserTraffic reports the user traffic without a report id.
func (c *Client) ReportUserTraffic(userTraffic []UserTraffic) error {
	return c.ReportUserTrafficWithID("", userTraffic)
}

// ReportIDHeader carries a report's id, so the panel can count a batch once
// however many times it arrives. A resend is otherwise indistinguishable from
// new traffic: the HTTP client retries on any error, including a timeout
// after the panel had already recorded the batch, and a failed batch is
// resent on the next cycle.
const ReportIDHeader = "X-Report-Id"

// ReportUserTrafficWithID reports one batch of user traffic. Send the same id
// for every attempt at the same batch.
func (c *Client) ReportUserTrafficWithID(reportID string, userTraffic []UserTraffic) error {
	data := trafficReportData(userTraffic)
	const path = "/api/v1/server/UniProxy/push"
	req := c.client.R().
		SetBody(data).
		ForceContentType("application/json")
	if reportID != "" {
		req.SetHeader(ReportIDHeader, reportID)
	}
	r, err := req.Post(path)
	return c.checkAcknowledgement(r, path, err)
}

func trafficReportData(userTraffic []UserTraffic) map[int][2]int64 {
	data := make(map[int][2]int64, len(userTraffic))
	for i := range userTraffic {
		v := data[userTraffic[i].UID]
		v[0] += userTraffic[i].Upload
		v[1] += userTraffic[i].Download
		data[userTraffic[i].UID] = v
	}
	return data
}

func (c *Client) ReportNodeOnlineUsers(data *map[int][]string) error {
	const path = "/api/v1/server/UniProxy/alive"
	r, err := c.client.R().
		SetBody(data).
		ForceContentType("application/json").
		Post(path)
	// Return the error. It was swallowed, so a failed report was logged as
	// "Reported" and nobody could tell the panel was not hearing from us.
	return c.checkAcknowledgement(r, path, err)
}
