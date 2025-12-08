package certmanager

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"time"

	legolog "github.com/go-acme/lego/v4/log"
)

func init() {
	// Override the logger with one that uses slog
	legolog.Logger = slogLogger{}
}

type slogLogger struct{}

func (l slogLogger) Fatal(args ...any) {
	message := fmt.Append(nil, args...)
	l.logFatal(string(message))
}

func (l slogLogger) Fatalln(args ...any) {
	message := fmt.Appendln(nil, args...)
	l.logFatal(string(message))
}

func (l slogLogger) Fatalf(format string, args ...any) {
	message := fmt.Appendf(nil, format, args...)
	l.logFatal(string(message))
}

func (l slogLogger) logFatal(message string) {
	log := slog.Default()

	// Emit the log only if the level is enabled
	if !log.Enabled(context.Background(), slog.LevelError) {
		// Exit without a log
		os.Exit(1)
		return
	}

	// See https://pkg.go.dev/log/slog#example-package-Wrapping
	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Infof]
	r := slog.NewRecord(time.Now(), slog.LevelError, message, pcs[0])
	_ = log.Handler().Handle(context.Background(), r)

	os.Exit(1)
}

func (l slogLogger) Print(args ...any) {
	message := fmt.Append(nil, args...)
	l.log(string(message))
}

func (l slogLogger) Println(args ...any) {
	message := fmt.Appendln(nil, args...)
	l.log(string(message))
}

func (l slogLogger) Printf(format string, args ...any) {
	message := fmt.Appendf(nil, format, args...)
	l.log(string(message))
}

func (l slogLogger) log(message string) {
	after, ok := strings.CutPrefix(message, "[WARN] ")
	if ok {
		slog.Warn(after)
	} else {
		slog.Info(strings.TrimPrefix(message, "[INFO] "))
	}
}
