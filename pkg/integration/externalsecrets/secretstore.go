package externalsecrets

import (
	"fmt"
	"sync"

	"github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/util"
	v1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime/pkg/client"
)

func (ExternalSecretsAnalyzer) secretStore(a common.Analyzer) ([]common.Result, error) {
	var mutex = &sync.Mutex{}

	kind := "SecretStore"
	result := &v1beta1.SecretStoreList{}
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

	for _, ss := range result.Items {
		var failures []common.Failure

		for _, condition := range ss.Status.Conditions {
			if condition.Status == v1.ConditionFalse {
				// parse the event log and append details
				evt, err := fetchLatestEvent(a.Context, k8sclient, ss.Namespace, ss.Name)
				if err != nil || evt == nil {
					continue
				}
				if evt.Reason == v1beta1.ReasonInvalidProviderConfig && evt.Message != "" {
					failures = append(failures, common.Failure{
						Text:      evt.Message,
						Sensitive: []common.Sensitive{},
					})
				}
				if evt.Reason == v1beta1.ReasonValidationFailed && evt.Message != "" {
					failures = append(failures, common.Failure{
						Text:      evt.Message,
						Sensitive: []common.Sensitive{},
					})
				}
				if evt.Reason == v1beta1.ReasonInvalidStore && evt.Message != "" {
					failures = append(failures, common.Failure{
						Text:      evt.Message,
						Sensitive: []common.Sensitive{},
					})
				}
				if len(failures) > 0 {
					preAnalysis[fmt.Sprintf("%s/%s", ss.Namespace,
						ss.Name)] = common.PreAnalysis{
						SecretStore:    ss,
						FailureDetails: failures,
					}
				}

			}
		}

	}

	for key, value := range preAnalysis {
		var currentAnalysis = common.Result{
			Kind:  kind,
			Name:  key,
			Error: value.FailureDetails,
		}

		parent, _ := util.GetParent(a.Client, value.SecretStore.ObjectMeta)
		currentAnalysis.ParentObject = parent
		a.Results = append(a.Results, currentAnalysis)
	}
	return a.Results, nil

}
