# natbwmon

## what?

- A Small web IO for visaulising up/down bandwidth for NAT clients.

## features

- Show bandwidth per lan client between router host and the internet, updated
  muliple times per second on default settings.
- View tracked connections per client host.

## why?

- I wanted to run this on an UniFi Dream Machine Pro which doesnt officially
  support third party sofware so a static binary that does not link to anything
  outside itself was the primary target.
- This is **only tested on UniFi Dream Machine Pro** with one specific port
  configuration so YMMV, should work on most linux NAT gateway setups though.

## how to use

- The only requirement is Go 1.16 or later for mative and cross platform
  builds.

- Look at the [run](run) script to see how the application is compiled and
  transferred to the arm64 UDM pro device.
- Execute `go run . -h` to see command line flags.
