package ip_rewrite

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/log"
	addressPush "github.com/littleya/coredns-address-push"
)

func init() { plugin.Register("ip_rewrite", setup) }

type config struct {
	networks            []net.IPNet
	apiClient           addressPush.ApiClient
	ipv4ListName        string
	ipv6ListName        string
	rewriteIPv4         net.IP
	rewriteIPv6         net.IP
	periodicSyncEnabled bool
	lock                *sync.RWMutex
}

var configs = map[string]*config{}

func setup(c *caddy.Controller) error {
	re, err := parseRewrite(c)
	if err != nil {
		panic(err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		re.Next = next
		return re
	})
	return nil
}

func parseRewrite(c *caddy.Controller) (*Rewrite, error) {
	keys := []string{}
	for c.Next() {
		rc, err := parseStanza(c)
		if err != nil {
			return nil, err
		}
		if !rc.Enabled {
			continue
		}
		var (
			conf *config
			ok   bool
		)
		if _, ok = configs[rc.Hash()]; !ok {
			client := rc.GetClient()
			conf = &config{
				networks:            []net.IPNet{},
				ipv4ListName:        rc.IPv4,
				ipv6ListName:        rc.IPv6,
				rewriteIPv4:         rc.RewriteIPv4,
				rewriteIPv6:         rc.RewriteIPv6,
				apiClient:           client,
				periodicSyncEnabled: false,
				lock:                &sync.RWMutex{},
			}
			conf.syncAddrList()
			configs[rc.Hash()] = conf
		}
		keys = append(keys, rc.Hash())
	}
	re := &Rewrite{Keys: keys}

	return re, nil
}

type RawConfig struct {
	addressPush.RawConfig
	RewriteIPv4 net.IP
	RewriteIPv6 net.IP
}

func parseStanza(c *caddy.Controller) (*RawConfig, error) {
	rc := &RawConfig{}
	rc.Enabled = true
	for c.NextBlock() {
		switch c.Val() {
		case Enabled:
			args := c.RemainingArgs()
			if len(args) != 1 {
				return rc, c.ArgErr()
			}
			if penabled, err := strconv.ParseBool(args[0]); err == nil {
				rc.Enabled = penabled
			} else {
				return rc, err
			}
		case Type:
			args := c.RemainingArgs()
			if len(args) == 0 {
				return rc, c.ArgErr()
			}
			if !(args[0] == "routeros" || args[0] == "vyos" || args[0] == "netmg" || args[0] == "ipsetapi") {
				return rc, c.ArgErr()
			}
			rc.Type = args[0]
		case Host:
			args := c.RemainingArgs()
			if len(args) != 1 {
				return rc, c.ArgErr()
			}
			if _, _, err := net.SplitHostPort(args[0]); err == nil {
				rc.Host = args[0]
			} else {
				return rc, err
			}
		case AuthUser:
			args := c.RemainingArgs()
			if len(args) != 1 {
				return rc, c.ArgErr()
			}
			rc.AuthUser = args[0]
		case AuthKey:
			args := c.RemainingArgs()
			if len(args) != 1 {
				return rc, c.ArgErr()
			}
			rc.AuthKey = args[0]
		case IPv4:
			args := c.RemainingArgs()
			if len(args) != 1 {
				return rc, c.ArgErr()
			}
			rc.IPv4 = args[0]
		case IPv6:
			args := c.RemainingArgs()
			if len(args) != 1 {
				return rc, c.ArgErr()
			}
			rc.IPv6 = args[0]
		case RewriteIPv4:
			args := c.RemainingArgs()
			if len(args) != 1 {
				return rc, c.ArgErr()
			}
			address := net.ParseIP(args[0])
			if address == nil || address.To4() == nil {
				return nil, c.ArgErr()
			}
			rc.RewriteIPv4 = address
		case RewriteIPv6:
			args := c.RemainingArgs()
			if len(args) != 1 {
				return rc, c.ArgErr()
			}
			address := net.ParseIP(args[0])
			if address == nil || address.To4() != nil {
				return nil, c.ArgErr()
			}
			rc.RewriteIPv6 = address
		default:
		}
	}
	if rc.Type == "" || rc.Host == "" || (rc.IPv4 == "" && rc.IPv6 == "") {
		return rc, errors.New("missing required fields")
	}
	if (rc.IPv4 == "" && rc.RewriteIPv4 == nil) && (rc.IPv6 == "" && rc.RewriteIPv6 == nil) {
		return rc, fmt.Errorf("rewrite ipv4 or ipv6 can't be set without ipv4 or ipv6. list: %s, %s. rewrite: %v, %v", rc.IPv4, rc.IPv6, rc.RewriteIPv4, rc.RewriteIPv6)
	}

	return rc, nil
}

func (rc *RawConfig) Hash() string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%v", rc)))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (c *config) syncAddrList() {
	if !c.periodicSyncEnabled {
		c.periodicSyncEnabled = true

		go func() {
			for {
				networks := []net.IPNet{}
				log.Infof("Syncing address list from plugin ip rewrite.")
				if c.ipv4ListName != "" {
					ipv4Networks := c.apiClient.FetchAddressFromList(c.ipv4ListName)
					if len(ipv4Networks) > 0 {
						networks = append(networks, ipv4Networks...)
					} else {
						log.Warningf("Failed get ipv4 networks or the network list is empty: %s", c.ipv4ListName)
					}
				}
				if c.ipv6ListName != "" {
					ipv6Networks := c.apiClient.FetchAddressFromList(c.ipv6ListName)
					if len(ipv6Networks) > 0 {
						networks = append(networks, ipv6Networks...)
					} else {
						log.Warningf("Failed get ipv6 networks or the network list is empty: %s", c.ipv6ListName)
					}
				}
				c.lock.Lock()
				c.networks = networks
				c.lock.Unlock()

				time.Sleep(time.Second * 15)
			}
		}()
	}
}
