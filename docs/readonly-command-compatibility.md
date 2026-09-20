# Read-only command compatibility

Status: designed for common OpenWrt 24.x/BusyBox environments. Not yet validated against
a physical QWRT R26.1.1 router.

| Tools | Primary source | Safe fallback or failure behavior |
|---|---|---|
| system/interfaces/DHCP | `ubus` | unavailable typed observation |
| temperature | thermal sysfs | `available=false` when no readable zone |
| memory/storage/uptime | `/proc`, BusyBox `df` | partial/unavailable metadata |
| routes/address | `ip` | per-family unavailable markers |
| DNS | resolv files + `nslookup` | resolv fallback and lookup-failed marker |
| firewall | `nft` or `iptables` discovery + filtered UCI | `implementation=unknown` |
| USB devices | `lsusb` | debugfs, then USB sysfs without serial numbers |
| USB netdev | network sysfs | driver symlink and `operstate` discovery |
| logs | `dmesg`, `logread` | explicit unavailable marker |
| OpenClash | package list, process list, filtered UCI | unknown values; no fixed path |
| listeners | `ss` | `netstat` fallback |
| HTTP probe | `curl` | `wget`, then `uclient-fetch` |
| ICMP/trace | `ping`, `traceroute` | failed probe observation when absent |

All shell text is fixed in source. LLM input can only select a registered tool and, for
active probes, one exact allowlisted target mapped to a fixed command. No command string
or free-form argument is interpolated.

Exit failures, unsupported syntax, output limits, and normalization errors return
`_meta.available=false` observations. SSH connection or host-key failures remain
connection errors because no device observation exists.

