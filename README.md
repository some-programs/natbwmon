[![Go Reference](https://pkg.go.dev/badge/github.com/some-programs/natbwmon.svg)](https://pkg.go.dev/github.com/some-programs/natbwmon)
# natbwmon

## what?

- A Small web UI for visaulising up/down bandwidth for NAT clients.

## features

- Show bandwidth per lan client between router host and the internet, updated
  muliple times per second on default settings.

- View tracked connections per client host.

- Web based UI and a command line utility ([natbwmontop](natbwmontop))

## why?

- I wanted to run this on an UniFi Dream Machine Pro which doesnt officially
  support third party sofware so a static binary that does not link to anything
  outside itself was the primary target.

- This is **only tested on UniFi Dream Machine Pro** with one specific port
  configuration so YMMV, should work on most linux NAT gateway setups though.

- I use this program for an open simple statistic page on the home network that
  anyone can access. I have no idea how it performs on a network with hundreds
  or thousands of clients. It might or might not work well at larger scale use cases.

## non goals

- This is a purley personal project and I don't see why anyone would use it in
  a professional settings so no or very few tests are written.


## how to use

- The only requirement is Go 1.17 or later for mative and cross platform
  builds.

- Look at the [run](run) script to see how the application is compiled and
  transferred to the arm64 UDM pro device.

- Execute `go run . -h` to see command line flags.
