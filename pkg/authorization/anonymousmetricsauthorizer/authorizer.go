package anonymousmetricsauthorizer

import (
	"context"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

const metricsAPIGroup = "metrics.k8s.io"

func New() authorizer.Authorizer {
	return &anonymousMetricsAuthorizer{}
}

type anonymousMetricsAuthorizer struct{}

func (i *anonymousMetricsAuthorizer) Authorize(_ context.Context, a authorizer.Attributes) (authorized authorizer.Decision, reason string, err error) {
	if !a.IsResourceRequest() || a.GetAPIGroup() != metricsAPIGroup {
		return authorizer.DecisionNoOpinion, "", nil
	}

	userInfo := a.GetUser()
	if userInfo == nil || userInfo.GetName() != user.Anonymous {
		return authorizer.DecisionNoOpinion, "", nil
	}

	return authorizer.DecisionDeny, "anonymous access to metrics.k8s.io is forbidden", nil
}
