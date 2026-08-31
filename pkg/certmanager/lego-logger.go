package certmanager

import (
	"log/slog"

	legolog "github.com/go-acme/lego/v5/log"
)

// setLegoLogger sets the default slog logger as lego's logger
// This must be called after the application has installed its default logger, otherwise lego would be pinned to the stdlib default and ignore the configured level and format
func setLegoLogger() {
	legolog.SetDefault(slog.Default().With(slog.String("scope", "lego")))
}
