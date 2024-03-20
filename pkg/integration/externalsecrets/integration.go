package externalsecrets

import (
	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/spf13/viper"
)

type ExternalSecrets struct {
}

func NewExternalSecrets() *ExternalSecrets {
	return &ExternalSecrets{}
}

func (e *ExternalSecrets) Deploy(namespace string) error {
	return nil
}

func (e *ExternalSecrets) UnDeploy(namespace string) error {
	return nil
}

func (e *ExternalSecrets) AddAnalyzer(mergedMap *map[string]common.IAnalyzer) {
	(*mergedMap)["SecretStore"] = &ExternalSecretsAnalyzer{
		secretStoreAnalyzer: true,
	}
	(*mergedMap)["ClusterSecretStore"] = &ExternalSecretsAnalyzer{
		clusterSecretStoreAnalyzer: true,
	}
	(*mergedMap)["ExternalSecret"] = &ExternalSecretsAnalyzer{
		externalSecretAnalyzer: true,
	}
	(*mergedMap)["ClusterExternalSecret"] = &ExternalSecretsAnalyzer{
		clusterExternalSecretAnalyzer: true,
	}
	(*mergedMap)["PushSecret"] = &ExternalSecretsAnalyzer{
		pushSecretAnalyzer: true,
	}
}

func (e *ExternalSecrets) GetAnalyzerName() []string {

	return []string{
		"ClusterExternalSecret",
		"ClusterSecretStore",
		"ExternalSecret",
		"SecretStore",
		"PushSecret",
	}
}

func (e *ExternalSecrets) GetNamespace() (string, error) {

	return "", nil
}

func (e *ExternalSecrets) OwnsAnalyzer(s string) bool {
	for _, az := range e.GetAnalyzerName() {
		if s == az {
			return true
		}
	}
	return false
}

func (e *ExternalSecrets) isFilterActive() bool {
	activeFilters := viper.GetStringSlice("active_filters")

	for _, filter := range e.GetAnalyzerName() {
		for _, af := range activeFilters {
			if af == filter {
				return true
			}
		}
	}

	return false
}

func (e *ExternalSecrets) IsActivate() bool {
	if e.isFilterActive() {
		return true
	} else {
		return false
	}
}
