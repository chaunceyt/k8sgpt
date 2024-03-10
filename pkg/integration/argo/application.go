package argo

import (
	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
)

func (ArgoAnalyzer) application(a common.Analyzer) ([]common.Result, error) {
	return a.Results, nil
}
