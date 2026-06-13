package anonymousmetricsauthorizer

import (
	"context"
	"testing"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func TestAuthorize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		attributes       authorizer.Attributes
		expectedDecision authorizer.Decision
	}{
		{
			name: "denies anonymous metrics resource requests",
			attributes: authorizer.AttributesRecord{
				User:            &user.DefaultInfo{Name: user.Anonymous},
				ResourceRequest: true,
				APIGroup:        metricsAPIGroup,
				Resource:        "pods",
				Verb:            "list",
			},
			expectedDecision: authorizer.DecisionDeny,
		},
		{
			name: "does not apply to non anonymous metrics requests",
			attributes: authorizer.AttributesRecord{
				User:            &user.DefaultInfo{Name: "alice"},
				ResourceRequest: true,
				APIGroup:        metricsAPIGroup,
				Resource:        "pods",
				Verb:            "list",
			},
			expectedDecision: authorizer.DecisionNoOpinion,
		},
		{
			name: "does not apply to anonymous non metrics requests",
			attributes: authorizer.AttributesRecord{
				User:            &user.DefaultInfo{Name: user.Anonymous},
				ResourceRequest: true,
				APIGroup:        "",
				Resource:        "pods",
				Verb:            "list",
			},
			expectedDecision: authorizer.DecisionNoOpinion,
		},
		{
			name: "does not apply to anonymous non resource requests",
			attributes: authorizer.AttributesRecord{
				User:            &user.DefaultInfo{Name: user.Anonymous},
				ResourceRequest: false,
				Path:            "/readyz",
				Verb:            "get",
			},
			expectedDecision: authorizer.DecisionNoOpinion,
		},
	}

	a := New()
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			decision, _, err := a.Authorize(context.Background(), tt.attributes)
			if err != nil {
				t.Fatalf("Authorize() returned unexpected error: %v", err)
			}
			if decision != tt.expectedDecision {
				t.Fatalf("Authorize() decision = %v, expected %v", decision, tt.expectedDecision)
			}
		})
	}
}
