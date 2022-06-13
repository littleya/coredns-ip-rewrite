# Address Push

## Name

Plugin *IPRewrite*

## Description

The plugin need configure after address_push, e.g.

``` conf
ip_rewrite:github.com/littleya/coredns-ip-rewrite
address_push:github.com/littleya/coredns-address-push
forward:forward
```

## Syntax

``` conf
{
    ip_rewrite {
        enabled         [true|false]
        type            [ipset|netmg|routeros|vyos]
        host            [host:port]
        auth_user       [username for auth]
        auth_key        [password or api key for auth]
        ipv4            [ipv4_address_list]
        ipv6            [ipv6_address_list]
        rewrite_ipv4    [A list of rewrite ipv4, sep by space]
        rewrite_ipv6    [A list of rewrite ipv6, sep by space]
        check_enable    [true|false]
        check_interval  [ping_interval fetch_interval]
        check_url       [URL to fetch]
    }
}
```

## Examples
