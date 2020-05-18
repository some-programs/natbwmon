# natbwmon

Small web ui for visaulising up/down bandwidth for NAT clients.

Note that this is **only tested on UniFi Dream Machine Pro** with one specific
port configuration so YMMV.

I just wrote this quickly to be able too get some basic idea of which
addresses is using internet bbandwidth.

The program generates and manages iptables rules to record per LAN client statistics.

I wanted to run this on an UniFi Dream Machine Pro which doesnt officially
support third party sofware so a static binary that does not link to anything
outside itself was the primary target.

look at the [run](run) script to see how the application is compiled and
transferred to the device. You just need go 1.14 or later for cross platform
builds.

Execute `go run . -h` to see command line flags.


# TODO

- remove hosts after no updates
- (maybe) fancier web ui
- (maybe) view conntrack
