package config

import (
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
)

// parseAzureEnvironment resolves an Azure cloud name to the Azure SDK configuration for that cloud
// lego holds this as a cloud.Configuration, which cannot be expressed as a string, so the generated azuredns provider calls this with the value of the "environment" credential
// The accepted names are the ones lego accepts in AZURE_ENVIRONMENT
func parseAzureEnvironment(name string) (cloud.Configuration, error) {
	switch strings.ToLower(name) {
	case "public":
		return cloud.AzurePublic, nil
	case "usgovernment":
		return cloud.AzureGovernment, nil
	case "china":
		return cloud.AzureChina, nil
	default:
		return cloud.Configuration{}, fmt.Errorf("unknown Azure environment %q, must be one of \"public\", \"usgovernment\", \"china\"", name)
	}
}
