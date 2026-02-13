package buildinfo

import (
	"fmt"

	"github.com/italypaleale/le-cert-server/pkg/utils"
)

const AppNamespace = "italypaleale.me/le-cert-server"

// These variables will be set at build time
var (
	AppName    string = "le-cert-server"
	AppVersion string = "canary"
	BuildId    string
	CommitHash string
	BuildDate  string
	Production string
)

// BuildDescription set during initialization
var BuildDescription string

func init() {
	if BuildId != "" && BuildDate != "" && CommitHash != "" {
		BuildDescription = fmt.Sprintf("%s, %s (%s)", BuildId, BuildDate, CommitHash)
	} else {
		BuildDescription = "null"
	}

	if !utils.IsTruthy(Production) {
		BuildDescription += " (non-production)"
	}
}
