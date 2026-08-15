package mission

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// RiskLevel is assigned by deterministic policy, not by the intent evaluator.
type RiskLevel string

const (
	RiskLow    RiskLevel = "low"
	RiskMedium RiskLevel = "medium"
	RiskHigh   RiskLevel = "high"
)

// IntentRequest gives an evaluator a user request plus already-resolved,
// canonical candidate calls. An evaluator selects from these candidates; it
// cannot introduce a new call or policy scope.
type IntentRequest struct {
	Requester  string
	Agent      string
	Prompt     string
	Candidates []MCPCall
}

// IntentEvaluation is deliberately narrow. It proposes calls and records why;
// policy and OpenFGA decide whether a Mission can be issued.
type IntentEvaluation struct {
	Calls     []MCPCall
	Rationale string
}

// IntentEvaluator can be implemented by a rules engine, a model-backed
// classifier, or an application-specific planner.
type IntentEvaluator interface {
	Evaluate(context.Context, IntentRequest) (IntentEvaluation, error)
}

// CallPolicy is the deterministic policy applied to a selected canonical call.
type CallPolicy struct {
	Risk             RiskLevel
	RequiresApproval bool
}

// PolicyResolver maps a canonical call to deterministic enforcement policy.
type PolicyResolver interface {
	PolicyFor(MCPCall) (CallPolicy, error)
}

// ToolPolicyResolver is a simple server/tool policy registry for a POC. A
// production connector can replace it with a richer policy implementation.
type ToolPolicyResolver struct {
	Rules   map[string]CallPolicy
	Default CallPolicy
}

func (resolver ToolPolicyResolver) PolicyFor(call MCPCall) (CallPolicy, error) {
	policy, exists := resolver.Rules[call.Server+"/"+call.Tool]
	if !exists {
		policy = resolver.Default
	}
	if err := policy.validate(); err != nil {
		return CallPolicy{}, err
	}
	return policy, nil
}

func (policy CallPolicy) validate() error {
	if policy.Risk == "" {
		policy.Risk = RiskLow
	}
	switch policy.Risk {
	case RiskLow, RiskMedium, RiskHigh:
	default:
		return fmt.Errorf("unknown risk level %q", policy.Risk)
	}
	if policy.Risk == RiskHigh && !policy.RequiresApproval {
		return fmt.Errorf("high-risk calls must require approval")
	}
	return nil
}

// StaticIntentEvaluator is useful for repeatable demonstrations and contract
// tests. It represents a previously resolved intent, not a policy decision.
type StaticIntentEvaluator struct {
	Calls     []MCPCall
	Rationale string
}

func (evaluator StaticIntentEvaluator) Evaluate(
	_ context.Context,
	_ IntentRequest,
) (IntentEvaluation, error) {
	return IntentEvaluation{
		Calls:     cloneCalls(evaluator.Calls),
		Rationale: evaluator.Rationale,
	}, nil
}

type ProposeMissionInput struct {
	MissionID     string
	Requester     string
	Agent         string
	Prompt        string
	Candidates    []MCPCall
	ExpiresAt     time.Time
	MaxDispatches int
}

// Propose evaluates an intent against a closed candidate set, applies
// deterministic policy, and verifies that both requester and agent can
// currently delegate every selected call before creating a draft Mission.
func (service *MissionService) Propose(
	ctx context.Context,
	evaluator IntentEvaluator,
	policies PolicyResolver,
	input ProposeMissionInput,
) (*Mission, error) {
	if evaluator == nil || policies == nil {
		return nil, fmt.Errorf("intent evaluator and policy resolver are required")
	}
	if strings.TrimSpace(input.Prompt) == "" {
		return nil, fmt.Errorf("user prompt is required")
	}
	if len(input.Candidates) == 0 {
		return nil, fmt.Errorf("at least one canonical candidate is required")
	}

	evaluation, err := evaluator.Evaluate(ctx, IntentRequest{
		Requester:  input.Requester,
		Agent:      input.Agent,
		Prompt:     input.Prompt,
		Candidates: cloneCalls(input.Candidates),
	})
	if err != nil {
		return nil, fmt.Errorf("evaluate intent: %w", err)
	}
	if len(evaluation.Calls) == 0 {
		return nil, fmt.Errorf("intent evaluation selected no calls")
	}

	candidates, err := callIndex(input.Candidates)
	if err != nil {
		return nil, err
	}
	grants := make([]CallGrant, 0, len(evaluation.Calls))
	for _, call := range evaluation.Calls {
		callID, err := call.ID()
		if err != nil {
			return nil, err
		}
		if _, exists := candidates[callID]; !exists {
			return nil, fmt.Errorf("intent evaluation selected a call outside the candidate set")
		}
		for _, principal := range []struct {
			name string
			id   string
		}{
			{name: "requester", id: input.Requester},
			{name: "agent", id: input.Agent},
		} {
			allowed, err := CanInvokeCall(ctx, service.fga, principal.id, call)
			if err != nil {
				return nil, err
			}
			if !allowed {
				return nil, fmt.Errorf("%s %s cannot delegate the selected call", principal.name, principal.id)
			}
		}

		policy, err := policies.PolicyFor(call)
		if err != nil {
			return nil, err
		}
		if policy.Risk == "" {
			policy.Risk = RiskLow
		}
		grants = append(grants, CallGrant{
			Call:             call,
			Risk:             policy.Risk,
			RequiresApproval: policy.RequiresApproval,
		})
	}

	return service.CreateDraft(CreateMissionInput{
		MissionID: input.MissionID,
		Requester: input.Requester,
		Agent:     input.Agent,
		Intent: IntentProposal{
			UserPrompt: input.Prompt,
			Rationale:  evaluation.Rationale,
			Grants:     grants,
		},
		ExpiresAt:     input.ExpiresAt,
		MaxDispatches: input.MaxDispatches,
	})
}

func callIndex(calls []MCPCall) (map[string]struct{}, error) {
	index := make(map[string]struct{}, len(calls))
	for _, call := range calls {
		callID, err := call.ID()
		if err != nil {
			return nil, err
		}
		index[callID] = struct{}{}
	}
	return index, nil
}

func cloneCalls(calls []MCPCall) []MCPCall {
	copy := make([]MCPCall, 0, len(calls))
	for _, call := range calls {
		clone := call
		clone.Scope = make(map[string]string, len(call.Scope))
		for key, value := range call.Scope {
			clone.Scope[key] = value
		}
		clone.Requirements = append([]ResourceRequirement(nil), call.Requirements...)
		copy = append(copy, clone)
	}
	return copy
}

// SortedCallIDs returns stable call IDs for presentation and audit output.
func SortedCallIDs(calls []MCPCall) ([]string, error) {
	ids := make([]string, 0, len(calls))
	for _, call := range calls {
		id, err := call.ID()
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}
