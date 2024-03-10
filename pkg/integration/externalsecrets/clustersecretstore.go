package externalsecrets

import (
	"fmt"
	"sync"

	"github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/util"
	ctrl "sigs.k8s.io/controller-runtime/pkg/client"
)

func (ExternalSecretsAnalyzer) clusterSecretStore(a common.Analyzer) ([]common.Result, error) {
	var mutex = &sync.Mutex{}

	kind := "ClusterSecretStore"
	result := &v1beta1.ClusterSecretStoreList{}
	client := a.Client.CtrlClient
	k8sclient := a.Client

	mutex.Lock()
	err := v1beta1.AddToScheme(client.Scheme())
	if err != nil {
		return nil, err
	}
	mutex.Unlock()

	if err := client.List(a.Context, result, &ctrl.ListOptions{}); err != nil {
		return nil, err
	}

	var preAnalysis = map[string]common.PreAnalysis{}

	for _, css := range result.Items {
		var failures []common.Failure

		// parse the event log and append details
		evt, err := fetchLatestEvent(a.Context, k8sclient, css.Namespace, css.Name)
		if err != nil || evt == nil {
			continue
		}

		if evt.Reason == v1beta1.ReasonInvalidProviderConfig && evt.Message != "" {
			failures = append(failures, common.Failure{
				Text:      evt.Message,
				Sensitive: []common.Sensitive{},
			})
		}

		if len(failures) > 0 {
			preAnalysis[fmt.Sprintf("%s/%s", css.Namespace,
				css.Name)] = common.PreAnalysis{
				ClusterSecretStore: css,
				FailureDetails:     failures,
			}
		}

	}

	for key, value := range preAnalysis {
		var currentAnalysis = common.Result{
			Kind:  kind,
			Name:  key,
			Error: value.FailureDetails,
		}

		parent, _ := util.GetParent(a.Client, value.ClusterSecretStore.ObjectMeta)
		currentAnalysis.ParentObject = parent
		a.Results = append(a.Results, currentAnalysis)
	}
	return a.Results, nil

}
