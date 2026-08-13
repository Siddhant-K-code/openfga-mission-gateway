package mission

import (
	"context"
	"testing"
	"time"
)

func TestFilterAuthorizedCandidates(t *testing.T) {
	fga, _, _, _, err := DemoEnvironment(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	candidates := []string{
		"jira_issue:APOLLO-17",
		"jira_issue:HERMES-1",
		"slack_channel:product",
	}
	allowed, err := FilterAuthorizedCandidates(
		context.Background(),
		fga,
		"user:alice",
		ReadJiraIssue,
		candidates,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(allowed) != 1 || allowed[0] != "jira_issue:APOLLO-17" {
		t.Fatalf("allowed candidates = %v", allowed)
	}
}

func TestGateway(t *testing.T) {
	ctx := context.Background()

	t.Run("allows scoped Jira read", func(t *testing.T) {
		_, _, gateway, token, err := DemoEnvironment(ctx)
		if err != nil {
			t.Fatal(err)
		}
		decision := gateway.Authorize(ctx, AuthorizationRequest{
			MissionToken: token,
			Agent:        "agent:triage",
			Action:       ReadJiraIssue,
			ResourceID:   "jira_issue:APOLLO-17",
		}, time.Now())
		if !decision.Allowed {
			t.Fatalf("decision = %+v", decision)
		}
	})

	t.Run("denies Jira issue outside Mission scope", func(t *testing.T) {
		_, _, gateway, token, err := DemoEnvironment(ctx)
		if err != nil {
			t.Fatal(err)
		}
		decision := gateway.Authorize(ctx, AuthorizationRequest{
			MissionToken: token,
			Agent:        "agent:triage",
			Action:       ReadJiraIssue,
			ResourceID:   "jira_issue:APOLLO-23",
		}, time.Now())
		assertDenied(t, decision, "denied by mission_action_and_resource_scope")
	})

	t.Run("denies Slack post until preview approval", func(t *testing.T) {
		_, _, gateway, token, err := DemoEnvironment(ctx)
		if err != nil {
			t.Fatal(err)
		}
		decision := gateway.Authorize(ctx, AuthorizationRequest{
			MissionToken: token,
			Agent:        "agent:triage",
			Action:       PostSlackMessage,
			ResourceID:   "slack_channel:product",
		}, time.Now())
		assertDenied(t, decision, "egress approval is required")
	})

	t.Run("allows Slack post after preview approval", func(t *testing.T) {
		_, missions, gateway, token, err := DemoEnvironment(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := missions.RequestEgressApproval(
			"apollo-17-product-summary-v1",
			"APOLLO-17 is delayed; no restricted fields included.",
		); err != nil {
			t.Fatal(err)
		}
		if err := missions.ApproveEgress(
			"apollo-17-product-summary-v1",
			"user:alice",
		); err != nil {
			t.Fatal(err)
		}

		decision := gateway.Authorize(ctx, AuthorizationRequest{
			MissionToken: token,
			Agent:        "agent:triage",
			Action:       PostSlackMessage,
			ResourceID:   "slack_channel:product",
		}, time.Now())
		if !decision.Allowed {
			t.Fatalf("decision = %+v", decision)
		}
	})

	t.Run("denies Slack channel outside Mission scope", func(t *testing.T) {
		_, missions, gateway, token, err := DemoEnvironment(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := missions.RequestEgressApproval(
			"apollo-17-product-summary-v1",
			"APOLLO-17 is delayed; no restricted fields included.",
		); err != nil {
			t.Fatal(err)
		}
		if err := missions.ApproveEgress(
			"apollo-17-product-summary-v1",
			"user:alice",
		); err != nil {
			t.Fatal(err)
		}

		decision := gateway.Authorize(ctx, AuthorizationRequest{
			MissionToken: token,
			Agent:        "agent:triage",
			Action:       PostSlackMessage,
			ResourceID:   "slack_channel:company",
		}, time.Now())
		assertDenied(t, decision, "denied by mission_action_and_resource_scope")
	})

	t.Run("denies after Jira access revocation", func(t *testing.T) {
		fga, _, gateway, token, err := DemoEnvironment(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := fga.Delete(ctx, []TupleKey{{
			User: "user:alice", Relation: "owner", Object: "jira_project:apollo",
		}}); err != nil {
			t.Fatal(err)
		}

		decision := gateway.Authorize(ctx, AuthorizationRequest{
			MissionToken: token,
			Agent:        "agent:triage",
			Action:       ReadJiraIssue,
			ResourceID:   "jira_issue:APOLLO-17",
		}, time.Now())
		assertDenied(t, decision, "denied by requester_base_access")
	})

	t.Run("denies after Mission revocation", func(t *testing.T) {
		_, missions, gateway, token, err := DemoEnvironment(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := missions.Revoke("apollo-17-product-summary-v1"); err != nil {
			t.Fatal(err)
		}

		decision := gateway.Authorize(ctx, AuthorizationRequest{
			MissionToken: token,
			Agent:        "agent:triage",
			Action:       ReadJiraIssue,
			ResourceID:   "jira_issue:APOLLO-17",
		}, time.Now())
		assertDenied(t, decision, "Mission is revoked")
	})

	t.Run("denies token used by a different agent", func(t *testing.T) {
		_, _, gateway, token, err := DemoEnvironment(ctx)
		if err != nil {
			t.Fatal(err)
		}

		decision := gateway.Authorize(ctx, AuthorizationRequest{
			MissionToken: token,
			Agent:        "agent:other",
			Action:       ReadJiraIssue,
			ResourceID:   "jira_issue:APOLLO-17",
		}, time.Now())
		assertDenied(t, decision, "Mission token is not bound to this agent")
	})

	t.Run("denies expired Mission token", func(t *testing.T) {
		_, _, gateway, token, err := DemoEnvironment(ctx)
		if err != nil {
			t.Fatal(err)
		}

		decision := gateway.Authorize(ctx, AuthorizationRequest{
			MissionToken: token,
			Agent:        "agent:triage",
			Action:       ReadJiraIssue,
			ResourceID:   "jira_issue:APOLLO-17",
		}, time.Now().Add(2*time.Hour))
		assertDenied(t, decision, "Mission token expired")
	})
}

func assertDenied(t *testing.T, decision Decision, reason string) {
	t.Helper()
	if decision.Allowed {
		t.Fatalf("decision unexpectedly allowed: %+v", decision)
	}
	if decision.Reason != reason {
		t.Fatalf("reason = %q, want %q", decision.Reason, reason)
	}
}
