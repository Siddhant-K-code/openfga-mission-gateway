package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/Siddhant-K-code/openfga-mission-gateway/internal/mission"
)

func main() {
	ctx := context.Background()
	fga, missions, gateway, token, err := mission.DemoEnvironment(ctx)
	if err != nil {
		log.Fatal(err)
	}

	candidates, err := mission.FilterAuthorizedCandidates(
		ctx,
		fga,
		"user:alice",
		mission.ReadJiraIssue,
		[]string{"jira_issue:APOLLO-17", "jira_issue:HERMES-1"},
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("FGA-filtered Jira candidates: %v\n\n", candidates)

	show("allowed Jira read", gateway.Authorize(ctx, mission.AuthorizationRequest{
		MissionToken: token,
		Agent:        "agent:triage",
		Action:       mission.ReadJiraIssue,
		ResourceID:   "jira_issue:APOLLO-17",
	}, time.Now()))

	show("denied Slack post until user reviews preview", gateway.Authorize(ctx, mission.AuthorizationRequest{
		MissionToken: token,
		Agent:        "agent:triage",
		Action:       mission.PostSlackMessage,
		ResourceID:   "slack_channel:product",
	}, time.Now()))

	if err := missions.RequestEgressApproval(
		"apollo-17-product-summary-v1",
		"APOLLO-17 is delayed; no restricted fields included.",
	); err != nil {
		log.Fatal(err)
	}
	if err := missions.ApproveEgress(
		"apollo-17-product-summary-v1",
		"user:alice",
	); err != nil {
		log.Fatal(err)
	}
	show("allowed Slack post after user approval", gateway.Authorize(ctx, mission.AuthorizationRequest{
		MissionToken: token,
		Agent:        "agent:triage",
		Action:       mission.PostSlackMessage,
		ResourceID:   "slack_channel:product",
	}, time.Now()))

	show("denied Slack post outside Mission scope", gateway.Authorize(ctx, mission.AuthorizationRequest{
		MissionToken: token,
		Agent:        "agent:triage",
		Action:       mission.PostSlackMessage,
		ResourceID:   "slack_channel:company",
	}, time.Now()))

	if err := fga.Delete(ctx, []mission.TupleKey{{
		User: "user:alice", Relation: "owner", Object: "jira_project:apollo",
	}}); err != nil {
		log.Fatal(err)
	}
	show("denied after Jira access revocation", gateway.Authorize(ctx, mission.AuthorizationRequest{
		MissionToken: token,
		Agent:        "agent:triage",
		Action:       mission.ReadJiraIssue,
		ResourceID:   "jira_issue:APOLLO-17",
	}, time.Now()))
}

func show(label string, decision mission.Decision) {
	body, err := json.MarshalIndent(decision, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n%s\n\n", label, body)
}
