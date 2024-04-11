package keda

import (
	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/spf13/viper"
)

type KEDAAnalyzer struct {
	scaledObjectAnalyzer          bool
	triggerAuthenticationAnalyzer bool
}

type KEDA struct {
}

func NewKEDA() *KEDA {
	return &KEDA{}
}

func (e *KEDA) Deploy(namespace string) error {
	return nil
}

func (e *KEDA) UnDeploy(namespace string) error {
	return nil
}

func (e *KEDA) AddAnalyzer(mergedMap *map[string]common.IAnalyzer) {
	(*mergedMap)["ScaledObject"] = &KEDAAnalyzer{
		scaledObjectAnalyzer: true,
	}
	(*mergedMap)["TriggerAuthentication"] = &KEDAAnalyzer{
		triggerAuthenticationAnalyzer: true,
	}
}

func (e *KEDA) GetAnalyzerName() []string {

	return []string{
		"ScaledObject",
		"TriggerAuthentication",
	}
}

func (e *KEDA) GetNamespace() (string, error) {

	return "", nil
}

func (e *KEDA) OwnsAnalyzer(s string) bool {
	for _, az := range e.GetAnalyzerName() {
		if s == az {
			return true
		}
	}
	return false
}

func (e *KEDA) isFilterActive() bool {
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

func (a *KEDA) IsActivate() bool {
	if a.isFilterActive() {
		return true
	} else {
		return false
	}
}
func (ka KEDAAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {

	return make([]common.Result, 0), nil
}
