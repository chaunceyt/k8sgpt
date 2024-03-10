package argo

import (
	"context"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	"github.com/spf13/viper"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ArgoAnalyzer struct {
	applicationAnalyzer    bool
	applicationSetAnalyzer bool
}

type Argo struct{}

func NewArgo() *Argo {
	return &Argo{}
}

func (a *Argo) Deploy(namespace string) error {
	return nil
}

func (a *Argo) UnDeploy(namespace string) error {
	return nil
}

func (a *Argo) AddAnalyzer(mergedMap *map[string]common.IAnalyzer) {
	(*mergedMap)["Application"] = &ArgoAnalyzer{
		applicationAnalyzer: true,
	}
	(*mergedMap)["ApplicationSet"] = &ArgoAnalyzer{
		applicationSetAnalyzer: true,
	}
}

func (a *Argo) GetAnalyzerName() []string {

	return []string{
		"Application",
		"ApplicationSet",
	}
}

func (a *Argo) GetNamespace() (string, error) {

	return "", nil
}

func (a *Argo) OwnsAnalyzer(s string) bool {
	for _, az := range a.GetAnalyzerName() {
		if s == az {
			return true
		}
	}
	return false
}

func (a *Argo) isFilterActive() bool {
	activeFilters := viper.GetStringSlice("active_filters")

	for _, filter := range a.GetAnalyzerName() {
		for _, af := range activeFilters {
			if af == filter {
				return true
			}
		}
	}

	return false
}

func (a *Argo) IsActivate() bool {
	if a.isFilterActive() {
		return true
	} else {
		return false
	}
}

func (aa ArgoAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {
	if aa.applicationAnalyzer {
		aresult := make([]common.Result, 0)
		vresult, err := aa.application(a)
		if err != nil {
			return nil, err
		}
		aresult = append(aresult, vresult...)
		return aresult, nil
	}

	if aa.applicationSetAnalyzer {
		asresult := make([]common.Result, 0)
		vresult, err := aa.applicationSet(a)
		if err != nil {
			return nil, err
		}
		asresult = append(asresult, vresult...)
		return asresult, nil
	}

	return make([]common.Result, 0), nil
}

func fetchLatestEvent(ctx context.Context, kubernetesClient *kubernetes.Client, namespace string, name string) (*v1.Event, error) {
	// get the list of events
	events, err := kubernetesClient.GetClient().CoreV1().Events(namespace).List(ctx,
		metav1.ListOptions{
			FieldSelector: "involvedObject.name=" + name,
		})

	if err != nil {
		return nil, err
	}
	// find most recent event
	var latestEvent *v1.Event
	for _, event := range events.Items {
		if latestEvent == nil {
			// this is required, as a pointer to a loop variable would always yield the latest value in the range
			e := event
			latestEvent = &e
		}
		if event.LastTimestamp.After(latestEvent.LastTimestamp.Time) {
			// this is required, as a pointer to a loop variable would always yield the latest value in the range
			e := event
			latestEvent = &e
		}
	}
	return latestEvent, nil
}
