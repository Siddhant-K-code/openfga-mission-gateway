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
	fga, missions, gateway, token, calls, err := mission.DemoEnvironment(ctx)
	if err != nil {
		log.Fatal(err)
	}

	candidates, err := mission.FilterAuthorizedCandidates(
		ctx,
		fga,
		"user:alice",
		[]mission.MCPCall{calls.ReadIssue, calls.Inaccessible},
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("FGA-filtered MCP call candidates: %d allowed\n\n", len(candidates))

	show("allowed scoped MCP call", gateway.Authorize(ctx, mission.AuthorizationRequest{
		MissionToken: token,
		Agent:        "agent:triage",
		Call:         calls.ReadIssue,
	}, time.Now()))

	show("denied call until preview approval", gateway.Authorize(ctx, mission.AuthorizationRequest{
		MissionToken: token,
		Agent:        "agent:triage",
		Call:         calls.PostSummary,
	}, time.Now()))

	callID, err := calls.PostSummary.ID()
	if err != nil {
		log.Fatal(err)
	}
	if err := missions.RequestApproval(
		"apollo-17-product-summary-v1",
		callID,
		"APOLLO-17 is delayed; no restricted fields included.",
	); err != nil {
		log.Fatal(err)
	}
	if err := missions.ApproveCall(
		"apollo-17-product-summary-v1",
		callID,
		"user:alice",
	); err != nil {
		log.Fatal(err)
	}
	show("allowed call after requester approval", gateway.Authorize(ctx, mission.AuthorizationRequest{
		MissionToken: token,
		Agent:        "agent:triage",
		Call:         calls.PostSummary,
	}, time.Now()))

	show("denied call outside Mission scope", gateway.Authorize(ctx, mission.AuthorizationRequest{
		MissionToken: token,
		Agent:        "agent:triage",
		Call:         calls.PostOtherTarget,
	}, time.Now()))

	serverID, err := calls.ReadIssue.ServerID()
	if err != nil {
		log.Fatal(err)
	}
	if err := fga.Delete(ctx, []mission.TupleKey{{
		User: "user:alice", Relation: "operator", Object: serverID,
	}}); err != nil {
		log.Fatal(err)
	}
	show("denied after source access revocation", gateway.Authorize(ctx, mission.AuthorizationRequest{
		MissionToken: token,
		Agent:        "agent:triage",
		Call:         calls.ReadIssue,
	}, time.Now()))
}

func show(label string, decision mission.Decision) {
	body, err := json.MarshalIndent(decision, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n%s\n\n", label, body)
}
