package argo

import (
	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
)

func (ArgoAnalyzer) applicationSet(a common.Analyzer) ([]common.Result, error) {
	return a.Results, nil
}
