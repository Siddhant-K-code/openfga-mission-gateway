package mission

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestProposeAppliesPolicyAndRecordsTimeline(t *testing.T) {
	ctx := context.Background()
	fga, _, _, _, calls, err := DemoEnvironment(ctx)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewMissionTokenSigner([]byte("proposal-timeline-test-secret-32-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	missions := NewMissionService(fga, signer)

	proposed, err := missions.Propose(ctx,
		StaticIntentEvaluator{
			Calls:     []MCPCall{calls.ReadIssue, calls.PostSummary},
			Rationale: "Read the selected ticket and request approval before posting.",
		},
		ToolPolicyResolver{Rules: map[string]CallPolicy{
			"team-chat/post_message": {
				Risk:             RiskHigh,
				RequiresApproval: true,
			},
		}, Default: CallPolicy{Risk: RiskLow}},
		ProposeMissionInput{
			MissionID:     "proposal-demo",
			Requester:     "user:alice",
			Agent:         "agent:triage",
			Prompt:        "Read APOLLO-17 and send a summary to the product channel.",
			Candidates:    []MCPCall{calls.ReadIssue, calls.PostSummary},
			ExpiresAt:     time.Now().Add(time.Hour),
			MaxDispatches: 2,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if proposed.State != MissionDraft || len(proposed.Grants) != 2 {
		t.Fatalf("proposed Mission = %+v", proposed)
	}

	postID, err := calls.PostSummary.ID()
	if err != nil {
		t.Fatal(err)
	}
	postGrant, exists := proposed.Grant(postID)
	if !exists || postGrant.Risk != RiskHigh || !postGrant.RequiresApproval {
		t.Fatalf("post grant = %+v, exists = %t", postGrant, exists)
	}

	token, err := missions.Approve(ctx, "proposal-demo", "user:alice", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	gateway := NewGateway(fga, missions, signer)
	decision := gateway.Authorize(ctx, AuthorizationRequest{
		MissionToken: token,
		Agent:        "agent:triage",
		Call:         calls.ReadIssue,
	}, time.Now())
	if !decision.Allowed {
		t.Fatalf("decision = %+v", decision)
	}

	timeline, err := missions.Timeline("proposal-demo")
	if err != nil {
		t.Fatal(err)
	}
	if len(timeline) != 3 {
		t.Fatalf("timeline = %+v", timeline)
	}
	if timeline[0].Kind != TimelineProposed || timeline[1].Kind != TimelineActivated || timeline[2].Kind != TimelineDecision {
		t.Fatalf("timeline kinds = %+v", timeline)
	}
	if timeline[2].Decision == nil || !timeline[2].Decision.Allowed || timeline[2].Decision.Call == nil {
		t.Fatalf("decision event = %+v", timeline[2])
	}
}

func TestProposeRejectsCallsOutsideCandidateSet(t *testing.T) {
	ctx := context.Background()
	fga, _, _, _, calls, err := DemoEnvironment(ctx)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewMissionTokenSigner([]byte("proposal-candidate-test-secret-32-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	missions := NewMissionService(fga, signer)

	_, err = missions.Propose(ctx,
		StaticIntentEvaluator{Calls: []MCPCall{calls.PostSummary}},
		ToolPolicyResolver{Default: CallPolicy{Risk: RiskLow}},
		ProposeMissionInput{
			MissionID:  "outside-candidate-set",
			Requester:  "user:alice",
			Agent:      "agent:triage",
			Prompt:     "Post an update.",
			Candidates: []MCPCall{calls.ReadIssue},
			ExpiresAt:  time.Now().Add(time.Hour),
		},
	)
	if err == nil {
		t.Fatal("proposal accepted a call outside its candidate set")
	}
}

func TestGatewayChecksProjectResourcesAndDispatchBudget(t *testing.T) {
	ctx := context.Background()
	fga, _, _, _, calls, err := DemoEnvironment(ctx)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewMissionTokenSigner([]byte("project-resource-test-secret-32-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	missions := NewMissionService(fga, signer)
	_, err = missions.CreateDraft(CreateMissionInput{
		MissionID: "project-resource-demo",
		Requester: "user:alice",
		Agent:     "agent:triage",
		Intent: IntentProposal{Grants: []CallGrant{{
			Call: calls.ReadIssue,
		}}},
		ExpiresAt:     time.Now().Add(time.Hour),
		MaxDispatches: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := missions.Approve(ctx, "project-resource-demo", "user:alice", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	gateway := NewGateway(fga, missions, signer)

	first := gateway.Authorize(ctx, AuthorizationRequest{
		MissionToken: token,
		Agent:        "agent:triage",
		Call:         calls.ReadIssue,
	}, time.Now())
	if !first.Allowed {
		t.Fatalf("first decision = %+v", first)
	}
	second := gateway.Authorize(ctx, AuthorizationRequest{
		MissionToken: token,
		Agent:        "agent:triage",
		Call:         calls.ReadIssue,
	}, time.Now())
	assertDenied(t, second, "Mission dispatch budget exhausted")

	projectMembership := TupleKey{
		User: "agent:triage", Relation: "member", Object: "tracker_project:apollo",
	}
	if err := fga.Delete(ctx, []TupleKey{projectMembership}); err != nil {
		t.Fatal(err)
	}

	if err := fga.Write(ctx, []TupleKey{projectMembership}); err != nil {
		t.Fatal(err)
	}

	// A fresh Mission isolates relationship revocation from the dispatch budget.
	_, err = missions.CreateDraft(CreateMissionInput{
		MissionID: "project-resource-revoked",
		Requester: "user:alice",
		Agent:     "agent:triage",
		Intent: IntentProposal{Grants: []CallGrant{{
			Call: calls.ReadIssue,
		}}},
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceToken, err := missions.Approve(ctx, "project-resource-revoked", "user:alice", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := fga.Delete(ctx, []TupleKey{projectMembership}); err != nil {
		t.Fatal(err)
	}
	revoked := gateway.Authorize(ctx, AuthorizationRequest{
		MissionToken: resourceToken,
		Agent:        "agent:triage",
		Call:         calls.ReadIssue,
	}, time.Now())
	assertDenied(t, revoked, "denied by agent_resource_access")

	_, err = missions.CreateDraft(CreateMissionInput{
		MissionID: "project-resource-issuance-denied",
		Requester: "user:alice",
		Agent:     "agent:triage",
		Intent: IntentProposal{Grants: []CallGrant{{
			Call: calls.ReadIssue,
		}}},
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := missions.Approve(ctx, "project-resource-issuance-denied", "user:alice", time.Now()); err == nil {
		t.Fatal("Mission issuance ignored revoked project access")
	}
}

func TestMissionDispatchBudgetIsAtomic(t *testing.T) {
	ctx := context.Background()
	fga, _, _, _, calls, err := DemoEnvironment(ctx)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewMissionTokenSigner([]byte("atomic-dispatch-budget-test-secret-32-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	missions := NewMissionService(fga, signer)
	_, err = missions.CreateDraft(CreateMissionInput{
		MissionID: "atomic-budget-demo",
		Requester: "user:alice",
		Agent:     "agent:triage",
		Intent: IntentProposal{Grants: []CallGrant{{
			Call: calls.ReadIssue,
		}}},
		ExpiresAt:     time.Now().Add(time.Hour),
		MaxDispatches: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := missions.Approve(ctx, "atomic-budget-demo", "user:alice", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	gateway := NewGateway(fga, missions, signer)

	start := make(chan struct{})
	decisions := make(chan Decision, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			decisions <- gateway.Authorize(ctx, AuthorizationRequest{
				MissionToken: token,
				Agent:        "agent:triage",
				Call:         calls.ReadIssue,
			}, time.Now())
		}()
	}
	close(start)
	group.Wait()
	close(decisions)

	allowed := 0
	denied := 0
	for decision := range decisions {
		if decision.Allowed {
			allowed++
			continue
		}
		if decision.Reason != "Mission dispatch budget exhausted" {
			t.Fatalf("decision = %+v", decision)
		}
		denied++
	}
	if allowed != 1 || denied != 1 {
		t.Fatalf("allowed = %d, denied = %d", allowed, denied)
	}
}
