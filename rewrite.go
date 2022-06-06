package ip_rewrite

import (
	"context"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/log"
	"github.com/miekg/dns"
)

type Rewrite struct {
	Next plugin.Handler
	Keys []string
}

func (re Rewrite) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	wrr := &ipRewriteResponseWriter{w, re}
	return plugin.NextOrFailure(re.Name(), re.Next, ctx, wrr, r)
}

func (re Rewrite) Name() string { return "ip_rewrite" }

type ipRewriteResponseWriter struct {
	dns.ResponseWriter
	Rewrite
}

func (re *ipRewriteResponseWriter) WriteMsg(res *dns.Msg) error {
	for _, key := range re.Keys {
		conf := configs[key]
		conf.lock.RLock()
		networks := conf.networks
		conf.lock.RUnlock()

		for _, answer := range res.Answer {
			switch rr := answer.(type) {
			case *dns.A:
				if conf.ipv4ListName != "" {
					addr := rr.A
					isRewrite := false
					for _, cidr := range networks {
						if isRewrite {
							break
						}
						if conf.ipv4ListName == "" {
							break
						}
						if cidr.Contains(addr) {
							//rewrite
							rr.A = conf.rewriteIPv4
							log.Infof("Address %s hit the cidr %s, replace with %s", addr, cidr, conf.rewriteIPv4)
							isRewrite = true
							break
						}
					}
				}
			case *dns.AAAA:
				if conf.ipv6ListName != "" {
					addr := rr.AAAA
					isRewrite := false
					for _, cidr := range networks {
						if isRewrite {
							break
						}
						if conf.ipv6ListName == "" {
							break
						}
						if cidr.Contains(addr) {
							//rewrite
							rr.AAAA = conf.rewriteIPv6
							log.Infof("Address %s hit the cidr %s, replace with %s", addr, cidr, conf.rewriteIPv6)
							isRewrite = true
							break
						}
					}
				}
			}
		}
	}
	return re.ResponseWriter.WriteMsg(res)
}

const (
	Enabled     = "enabled"
	Type        = "type"
	Host        = "host"
	AuthUser    = "auth_user"
	AuthKey     = "auth_key"
	IPv4        = "ipv4"
	IPv6        = "ipv6"
	RewriteIPv4 = "rewrite_ipv4"
	RewriteIPv6 = "rewrite_ipv6"
)
