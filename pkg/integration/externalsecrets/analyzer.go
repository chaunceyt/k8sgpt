package externalsecrets

import (
	"context"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ExternalSecretsAnalyzer parameters for filters
type ExternalSecretsAnalyzer struct {
	clusterSecretStoreAnalyzer    bool
	clusterExternalSecretAnalyzer bool
	externalSecretAnalyzer        bool
	secretStoreAnalyzer           bool
	pushSecretAnalyzer            bool
}

// Analyze is responsible for checking status and adding event message to result.
func (e ExternalSecretsAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {
	if e.secretStoreAnalyzer {
		ss := make([]common.Result, 0)
		vresult, err := e.secretStore(a)
		if err != nil {
			return nil, err
		}
		ss = append(ss, vresult...)
		return ss, nil
	}

	if e.clusterSecretStoreAnalyzer {
		css := make([]common.Result, 0)
		vresult, err := e.clusterSecretStore(a)
		if err != nil {
			return nil, err
		}
		css = append(css, vresult...)
		return css, nil
	}

	if e.externalSecretAnalyzer {
		es := make([]common.Result, 0)
		vresult, err := e.externalSecret(a)
		if err != nil {
			return nil, err
		}
		es = append(es, vresult...)
		return es, nil
	}

	if e.clusterExternalSecretAnalyzer {
		es := make([]common.Result, 0)
		vresult, err := e.clusterExternalSecret(a)
		if err != nil {
			return nil, err
		}
		es = append(es, vresult...)
		return es, nil
	}

	if e.pushSecretAnalyzer {
		es := make([]common.Result, 0)
		vresult, err := e.pushSecret(a)
		if err != nil {
			return nil, err
		}
		es = append(es, vresult...)
		return es, nil
	}
	return make([]common.Result, 0), nil
}

// fetchLatestEvent fetch latest event(s) for what is being analyzed.
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
