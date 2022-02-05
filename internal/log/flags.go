package log

import (
	"flag"
	"os"

	"github.com/rs/zerolog"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Flags is a collection of stdlib flags configuring logging
type Flags struct {
	Debug          bool
	Trace          bool
	Console        bool
	FileName       string
	FileMaxBackups int
	FileMaxSize    int
	FileMaxAge     int
}

// Register registers the flags in a flag.FlagSet
func (f *Flags) Register(fs *flag.FlagSet) {
	fs.BoolVar(&f.Debug, "log.debug", false, "debug logging")
	fs.BoolVar(&f.Trace, "log.trace", false, "trace logging")
	fs.BoolVar(&f.Console, "log.console", false, "console formatter")
	fs.StringVar(&f.FileName, "log.file.name", "", "log file name")
	fs.IntVar(&f.FileMaxBackups, "log.file.maxbackups", 10, "max log file backups")
	fs.IntVar(&f.FileMaxSize, "log.file.maxsize", 5, "max log file size (megabytes)")
	fs.IntVar(&f.FileMaxAge, "log.file.maxage", 60, "max log file age (days)")
}

// Setup sets up logging accorind to Flags values.
func (f Flags) Setup() error {
	switch {
	case f.Trace:
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	case f.Debug:
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	switch {
	case f.FileName != "":
		w := &lumberjack.Logger{
			Filename:   f.FileName,
			MaxBackups: f.FileMaxBackups,
			MaxSize:    f.FileMaxSize,
			MaxAge:     f.FileMaxAge,
		}
		SetBlockingLogger(w)
	case f.Console:
		SetConsoleLogger()
	default:
		SetBlockingLogger(os.Stderr)
	}
	return nil
}
