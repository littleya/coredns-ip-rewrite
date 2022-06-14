package ip_rewrite

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin/pkg/log"
	pinger "github.com/go-ping/ping"
)

type latencyRet struct {
	loss    float32
	latency int
	host    string
}

func pingHost(host string) latencyRet {
	p, err := pinger.NewPinger(host)
	if err != nil {
		log.Errorf("failed to create pinger for %s: %v", host, err)
		return latencyRet{}
	}
	p.Count = 3
	p.Timeout = 3 * time.Second
	defer p.Stop()

	err = p.Run()
	if err != nil {
		log.Errorf("failed to run pinger for %s: %v", host, err)
		return latencyRet{}
	}
	r := latencyRet{
		loss:    float32(p.Statistics().PacketsRecv) / float32(p.Statistics().PacketsSent),
		latency: int(p.Statistics().AvgRtt),
		host:    host,
	}
	return r
}

func fetchHost(host, uri string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		log.Errorf("failed to parse url %s: %v", uri, err)
		return false
	}

	dialer := &net.Dialer{
		Timeout: 3 * time.Second,
	}
	transport := http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if strings.Contains(addr, u.Host) {
				if addr := net.ParseIP(addr); addr.To4() != nil {
					return dialer.DialContext(ctx, network, fmt.Sprintf("%s:443", host))
				} else {
					return dialer.DialContext(ctx, network, fmt.Sprintf("[%s]:443", host))
				}
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	c := http.Client{
		Transport: &transport,
	}
	resp, err := c.Get(uri)
	if err != nil {
		log.Errorf("failed to fetch %s via host %s: %v", uri, host, err)
		return false
	} else if resp.StatusCode/100 != 2 {
		return false
	}
	return true
}

func detect(hosts []net.IP, url string) net.IP {
	latencyRets := []latencyRet{}
	for _, ip := range hosts {
		if ret := pingHost(ip.String()); ret != (latencyRet{}) {
			latencyRets = append(latencyRets, ret)
		}
	}
	// Sort by loss DESC
	sort.SliceStable(latencyRets, func(i, j int) bool { return latencyRets[i].loss > latencyRets[j].loss })
	// Sort by latency ASC
	sort.SliceStable(latencyRets, func(i, j int) bool { return latencyRets[i].latency < latencyRets[j].latency })

	for _, l := range latencyRets {
		if ret := fetchHost(l.host, url); ret {
			return net.ParseIP(l.host)
		}
	}
	return nil
}
