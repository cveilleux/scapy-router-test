# scapy-router-test

Runs an automated test to discover the capabilities/configuration 
of a typical home/small office router.

The script does not use the network stack of the host machine at 
all. Packets are crafted and replied directly in python/scapy.
This provides full visibility and flexibility, nothing is hidden
by the operating system.

## Status

This is an early release, expect bugs and rough edges.

## Features

- Obtains an IPv4 address and gateway automatically using a built-in DHCP client.
- Tests DNS is working.
- Checks if the router responds to pings.
- Checks internet connectivity.
- Detect captive portals.
- Perform an ARP scan to find hosts on the LAN.
- Can attempt to ping/connect to hosts outside of the LAN, for example to test proper VLAN or subnet isolation.

## Usage

You are expected to run this on a machine that has:

- A working network connection
- A free ethernet adapter that is not configured by the OS.

You then simply launch the script with:

```
router-test [interface]
```


