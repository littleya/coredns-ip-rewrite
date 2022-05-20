# Address Push

## Name

Plugin *IPRewrite*

## Description

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
        rewrite_ipv4    [rewrite ipv4 to]
        rewrite_ipv6    [rewrite ipv6 to]
    }
}
```

## Examples
