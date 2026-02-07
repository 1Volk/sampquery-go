package sampquery

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/text/encoding/charmap"
)

const (
	OpInfo    byte = 'i'
	OpRules   byte = 'r'
	OpPlayers byte = 'c'
	OpPing    byte = 'p'
	OpOmp     byte = 'o'
)

type Query struct {
	addr    *net.UDPAddr
	conn    *net.UDPConn
	Timeout time.Duration
	mu      sync.Mutex
}

type ServerData struct {
	Address    string `json:"address"`
	Hostname   string `json:"hostname"`
	Players    int    `json:"players"`
	MaxPlayers int    `json:"max_players"`
	Gamemode   string `json:"gamemode"`
	Language   string `json:"language"`
	Password   bool   `json:"password"`
	Ping       int    `json:"ping"`
}

type ServerFullData struct {
	ServerData *ServerData       `json:"server_data"`
	Rules      map[string]string `json:"rules"`
	IsOmp      bool              `json:"is_omp"`
}

type Config struct {
	IP      string
	Port    int
	Timeout time.Duration
}

func NewQuery(config *Config) (*Query, error) {
	q := &Query{Timeout: config.Timeout}
	var err error

	if q.addr, err = ResolveHost(config.IP, config.Port); err != nil {
		return nil, err
	}

	if err = q.Connect(); err != nil {
		return nil, err
	}

	return q, nil
}

func (q *Query) Connect() error {
	if q.conn != nil {
		return nil
	}

	conn, err := net.DialUDP("udp", nil, q.addr)
	if err != nil {
		return err
	}
	q.conn = conn
	return nil
}

func (q *Query) Close() error {
	if q.conn != nil {
		err := q.conn.Close()
		q.conn = nil
		return err
	}
	return nil
}
func (q *Query) execute(opcode byte, payload []byte) ([]byte, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.conn == nil {
		return nil, errors.New("not connected. NewQuery must be called first")
	}

	reqLen := 11 + len(payload)
	var buf [512]byte

	copy(buf[0:4], "SAMP")

	ip := q.addr.IP.To4()
	if ip == nil {
		return nil, errors.New("address must be IPv4")
	}
	copy(buf[4:8], ip)

	port := q.addr.Port
	buf[8] = byte(port & 0xFF)
	buf[9] = byte((port >> 8) & 0xFF)
	buf[10] = opcode

	if len(payload) > 0 {
		copy(buf[11:], payload)
	}

	if q.Timeout > 0 {
		err := q.conn.SetDeadline(time.Now().Add(q.Timeout))
		if err != nil {
			return nil, err
		}
	}

	if _, err := q.conn.Write(buf[:reqLen]); err != nil {
		return nil, err
	}

	recvBuf := make([]byte, 4096)
	n, err := q.conn.Read(recvBuf)
	if err != nil {
		return nil, err
	}

	if n < 11 {
		return nil, errors.New("response too small")
	}

	return recvBuf[:n], nil
}

func (q *Query) GetPing() (time.Duration, error) {
	payload := make([]byte, 4)
	if _, err := rand.Read(payload); err != nil {
		return 0, err
	}

	start := time.Now()

	_, err := q.execute(OpPing, payload)
	if err != nil {
		return 0, err
	}

	return time.Since(start), nil
}

func (q *Query) GetData() (*ServerData, error) {
	ping := time.Now()

	resp, err := q.execute(OpInfo, nil)
	if err != nil {
		return nil, err
	}

	data := &ServerData{}
	data.Ping = int(time.Since(ping).Milliseconds())
	data.Address = q.addr.String()

	offset := 11

	if len(resp) < offset+5 {
		return nil, errors.New("malformed packet: fixed header too short")
	}

	data.Password = resp[offset] == 1
	offset++

	data.Players = int(binary.LittleEndian.Uint16(resp[offset : offset+2]))
	offset += 2

	data.MaxPlayers = int(binary.LittleEndian.Uint16(resp[offset : offset+2]))
	offset += 2

	readString := func() (string, error) {
		if len(resp) < offset+4 {
			return "", errors.New("malformed packet: string len unavailable")
		}
		strLen := int(binary.LittleEndian.Uint32(resp[offset : offset+4]))
		offset += 4

		if len(resp) < offset+strLen {
			return "", errors.New("malformed packet: string body unavailable")
		}

		rawBytes := resp[offset : offset+strLen]
		offset += strLen

		return decodeWin1251(rawBytes), nil
	}

	stringFields := []*string{
		&data.Hostname,
		&data.Gamemode,
		&data.Language,
	}

	for _, fieldPtr := range stringFields {
		val, err := readString()
		if err != nil {
			return nil, err
		}
		*fieldPtr = val
	}

	return data, nil
}

func (q *Query) GetRules() (map[string]string, error) {
	resp, err := q.execute(OpRules, nil)
	if err != nil {
		return nil, err
	}

	rules := make(map[string]string)
	offset := 11

	if len(resp) < offset+2 {
		return rules, nil
	}

	ruleCount := int(binary.LittleEndian.Uint16(resp[offset : offset+2]))
	offset += 2

	readRuleString := func() (string, error) {
		if len(resp) < offset+1 {
			return "", errors.New("malformed packet: string len unavailable")
		}
		strLen := int(resp[offset])
		offset++

		if len(resp) < offset+strLen {
			return "", errors.New("malformed packet: string body unavailable")
		}

		rawBytes := resp[offset : offset+strLen]
		offset += strLen

		return decodeWin1251(rawBytes), nil
	}

	for i := 0; i < ruleCount; i++ {
		key, err := readRuleString()
		if err != nil {
			return nil, err
		}
		val, err := readRuleString()
		if err != nil {
			return nil, err
		}
		rules[key] = val
	}

	return rules, nil
}

func (q *Query) GetPlayers() ([]string, error) {
	resp, err := q.execute(OpPlayers, nil)
	if err != nil {
		return nil, err
	}

	offset := 11
	if len(resp) < offset+2 {
		return []string{}, nil
	}

	count := int(binary.LittleEndian.Uint16(resp[offset : offset+2]))
	offset += 2

	players := make([]string, 0, count)

	for i := 0; i < count; i++ {
		if len(resp) < offset+1 {
			break
		}
		nameLen := int(resp[offset])
		offset++

		if len(resp) < offset+nameLen {
			break
		}
		rawName := resp[offset : offset+nameLen]
		offset += nameLen

		if len(resp) < offset+4 {
			break
		}
		offset += 4

		players = append(players, decodeWin1251(rawName))
	}

	return players, nil
}

func (q *Query) GetFullData() (*ServerFullData, error) {
	data, err := q.GetData()
	if err != nil {
		return nil, fmt.Errorf("failed to get data: %w", err)
	}

	fullData := &ServerFullData{
		ServerData: data,
		Rules:      make(map[string]string),
	}

	rules, err := q.GetRules()
	if err == nil {
		fullData.Rules = rules
	}

	isOmp := false

	if ver, ok := fullData.Rules["version"]; ok {
		if len(ver) >= 3 && (ver[:3] == "omp" || ver[:3] == "OMP") {
			isOmp = true
		}
	}

	if !isOmp {
		if _, ok := fullData.Rules["allow_DL"]; ok {
			isOmp = true
		}
	}

	if !isOmp {
		originalTimeout := q.Timeout

		q.Timeout = 200 * time.Millisecond

		ompResp, _ := q.execute(OpOmp, nil)
		if len(ompResp) > 0 {
			isOmp = true
		}

		q.Timeout = originalTimeout
	}

	fullData.IsOmp = isOmp

	return fullData, nil
}

func ResolveHost(host string, port int) (*net.UDPAddr, error) {
	if net.ParseIP(host) != nil {
		return &net.UDPAddr{IP: net.ParseIP(host), Port: port}, nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("dns resolve error: %w", err)
	}

	if len(ips) == 0 {
		return nil, errors.New("dns returned no ips")
	}

	var finalIP string
	for _, ip := range ips {
		if ip.To4() != nil {
			finalIP = ip.String()
			break
		}
	}

	if finalIP == "" {
		finalIP = ips[0].String()
	}

	return &net.UDPAddr{IP: net.ParseIP(finalIP), Port: port}, nil
}

func decodeWin1251(data []byte) string {
	decoded, _ := charmap.Windows1251.NewDecoder().Bytes(data)
	return string(decoded)
}
