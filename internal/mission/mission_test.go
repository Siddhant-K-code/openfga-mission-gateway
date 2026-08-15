package mission

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMCPCallIDIsStableForEquivalentScope(t *testing.T) {
	left := MCPCall{
		Server: "work-tracker",
		Tool:   "get_issue",
		Scope:  map[string]string{"issue_id": "APOLLO-17", "workspace": "acme"},
		Requirements: []ResourceRequirement{
			{Relation: "can_read", Object: "tracker_ticket:APOLLO-17"},
			{Relation: "can_read", Object: "tracker_project:apollo"},
		},
	}
	right := MCPCall{
		Server: "work-tracker",
		Tool:   "get_issue",
		Scope:  map[string]string{"workspace": "acme", "issue_id": "APOLLO-17"},
		Requirements: []ResourceRequirement{
			{Relation: "can_read", Object: "tracker_project:apollo"},
			{Relation: "can_read", Object: "tracker_ticket:APOLLO-17"},
		},
	}

	leftID, err := left.ID()
	if err != nil {
		t.Fatal(err)
	}
	rightID, err := right.ID()
	if err != nil {
		t.Fatal(err)
	}
	if leftID != rightID {
		t.Fatalf("equivalent calls have different IDs: %q != %q", leftID, rightID)
	}
}

func TestMCPCallRejectsDuplicateResourceRequirements(t *testing.T) {
	_, err := (MCPCall{
		Server: "work-tracker",
		Tool:   "get_issue",
		Requirements: []ResourceRequirement{
			{Relation: "can_read", Object: "tracker_ticket:APOLLO-17"},
			{Relation: "can_read", Object: "tracker_ticket:APOLLO-17"},
		},
	}).ID()
	if err == nil {
		t.Fatal("duplicate resource requirements were accepted")
	}
}

func TestFilterAuthorizedCandidates(t *testing.T) {
	fga, _, _, _, calls, err := DemoEnvironment(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	allowed, err := FilterAuthorizedCandidates(
		context.Background(),
		fga,
		"user:alice",
		[]MCPCall{calls.ReadIssue, calls.Inaccessible},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(allowed) != 1 {
		t.Fatalf("allowed candidates = %d, want 1", len(allowed))
	}
	allowedID, err := allowed[0].ID()
	if err != nil {
		t.Fatal(err)
	}
	wantID, err := calls.ReadIssue.ID()
	if err != nil {
		t.Fatal(err)
	}
	if allowedID != wantID {
		t.Fatalf("allowed candidate = %q, want %q", allowedID, wantID)
	}
}

func TestMissionScopeIsContextual(t *testing.T) {
	fga, _, gateway, token, calls, err := DemoEnvironment(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	callID, err := calls.ReadIssue.ID()
	if err != nil {
		t.Fatal(err)
	}

	persisted, err := fga.Check(context.Background(), CheckRequest{
		User: callID, Relation: "allowed_call", Object: "mission:apollo-17-product-summary-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if persisted {
		t.Fatal("Mission scope must not be written as a durable tuple")
	}

	decision := gateway.Authorize(context.Background(), AuthorizationRequest{
		MissionToken: token,
		Agent:        "agent:triage",
		Call:         calls.ReadIssue,
	}, time.Now())
	if !decision.Allowed {
		t.Fatalf("contextual Mission scope was not enforced: %+v", decision)
	}
}

func TestCanonicalCallTopologyIsContextual(t *testing.T) {
	fga, _, _, _, calls, err := DemoEnvironment(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	callID, err := calls.ReadIssue.ID()
	if err != nil {
		t.Fatal(err)
	}
	toolID, err := calls.ReadIssue.ToolID()
	if err != nil {
		t.Fatal(err)
	}

	persisted, err := fga.Check(context.Background(), CheckRequest{
		User: toolID, Relation: "tool", Object: callID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if persisted {
		t.Fatal("resource-specific MCP call topology must not be durable")
	}

	allowed, err := CanInvokeCall(context.Background(), fga, "user:alice", calls.ReadIssue)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("trusted contextual tool topology did not authorize the call")
	}
}

func TestGateway(t *testing.T) {
	ctx := context.Background()

	t.Run("allows a scoped MCP call", func(t *testing.T) {
		_, _, gateway, token, calls, err := DemoEnvironment(ctx)
		if err != nil {
			t.Fatal(err)
		}
		decision := authorize(ctx, gateway, token, calls.ReadIssue, "agent:triage", time.Now())
		if !decision.Allowed {
			t.Fatalf("decision = %+v", decision)
		}
	})

	t.Run("denies a call outside Mission scope", func(t *testing.T) {
		_, _, gateway, token, calls, err := DemoEnvironment(ctx)
		if err != nil {
			t.Fatal(err)
		}
		decision := authorize(ctx, gateway, token, calls.PostOtherTarget, "agent:triage", time.Now())
		assertDenied(t, decision, "denied by mission_call_scope")
	})

	t.Run("denies a call until preview approval", func(t *testing.T) {
		_, _, gateway, token, calls, err := DemoEnvironment(ctx)
		if err != nil {
			t.Fatal(err)
		}
		decision := authorize(ctx, gateway, token, calls.PostSummary, "agent:triage", time.Now())
		assertDenied(t, decision, "call approval is required")
	})

	t.Run("allows a call after requester approval", func(t *testing.T) {
		_, missions, gateway, token, calls, err := DemoEnvironment(ctx)
		if err != nil {
			t.Fatal(err)
		}
		approveCall(t, missions, calls.PostSummary)

		decision := authorize(ctx, gateway, token, calls.PostSummary, "agent:triage", time.Now())
		if !decision.Allowed {
			t.Fatalf("decision = %+v", decision)
		}
	})

	t.Run("does not combine a permitted tool with another target", func(t *testing.T) {
		_, missions, gateway, token, calls, err := DemoEnvironment(ctx)
		if err != nil {
			t.Fatal(err)
		}
		approveCall(t, missions, calls.PostSummary)

		decision := authorize(ctx, gateway, token, calls.PostOtherTarget, "agent:triage", time.Now())
		assertDenied(t, decision, "denied by mission_call_scope")
	})

	t.Run("denies after source authority is revoked", func(t *testing.T) {
		fga, _, gateway, token, calls, err := DemoEnvironment(ctx)
		if err != nil {
			t.Fatal(err)
		}
		serverID, err := calls.ReadIssue.ServerID()
		if err != nil {
			t.Fatal(err)
		}
		if err := fga.Delete(ctx, []TupleKey{{
			User: "user:alice", Relation: "operator", Object: serverID,
		}}); err != nil {
			t.Fatal(err)
		}

		decision := authorize(ctx, gateway, token, calls.ReadIssue, "agent:triage", time.Now())
		assertDenied(t, decision, "denied by requester_base_access")
	})

	t.Run("denies after agent authority is revoked", func(t *testing.T) {
		fga, _, gateway, token, calls, err := DemoEnvironment(ctx)
		if err != nil {
			t.Fatal(err)
		}
		serverID, err := calls.ReadIssue.ServerID()
		if err != nil {
			t.Fatal(err)
		}
		if err := fga.Delete(ctx, []TupleKey{{
			User: "agent:triage", Relation: "operator", Object: serverID,
		}}); err != nil {
			t.Fatal(err)
		}

		decision := authorize(ctx, gateway, token, calls.ReadIssue, "agent:triage", time.Now())
		assertDenied(t, decision, "denied by agent_base_access")
	})

	t.Run("denies after Mission revocation", func(t *testing.T) {
		_, missions, gateway, token, calls, err := DemoEnvironment(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := missions.Revoke("apollo-17-product-summary-v1"); err != nil {
			t.Fatal(err)
		}

		decision := authorize(ctx, gateway, token, calls.ReadIssue, "agent:triage", time.Now())
		assertDenied(t, decision, "Mission is revoked")
	})

	t.Run("denies a token used by a different agent", func(t *testing.T) {
		_, _, gateway, token, calls, err := DemoEnvironment(ctx)
		if err != nil {
			t.Fatal(err)
		}
		decision := authorize(ctx, gateway, token, calls.ReadIssue, "agent:other", time.Now())
		assertDenied(t, decision, "Mission token is not bound to this agent")
	})

	t.Run("denies an expired Mission token", func(t *testing.T) {
		_, _, gateway, token, calls, err := DemoEnvironment(ctx)
		if err != nil {
			t.Fatal(err)
		}
		decision := authorize(ctx, gateway, token, calls.ReadIssue, "agent:triage", time.Now().Add(2*time.Hour))
		assertDenied(t, decision, "Mission token expired")
	})
}

func TestMissionApprovalRequiresAgentAuthority(t *testing.T) {
	ctx := context.Background()
	fga, _, _, _, calls, err := DemoEnvironment(ctx)
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := calls.ReadIssue.ServerID()
	if err != nil {
		t.Fatal(err)
	}
	if err := fga.Delete(ctx, []TupleKey{{
		User: "agent:triage", Relation: "operator", Object: serverID,
	}}); err != nil {
		t.Fatal(err)
	}

	signer, err := NewMissionTokenSigner([]byte("agent-authority-test-secret-32-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	missions := NewMissionService(fga, signer)
	_, err = missions.CreateDraft(CreateMissionInput{
		MissionID: "agent-authority-required",
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
	_, err = missions.Approve(ctx, "agent-authority-required", "user:alice", time.Now())
	if err == nil || !strings.Contains(err.Error(), "agent agent:triage cannot invoke") {
		t.Fatalf("approval error = %v", err)
	}
}

func TestOpenFGAHTTPIncludesContextualTuples(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/stores/store/check" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		var body struct {
			TupleKey         TupleKey `json:"tuple_key"`
			ContextualTuples struct {
				TupleKeys []TupleKey `json:"tuple_keys"`
			} `json:"contextual_tuples"`
			AuthorizationModelID string `json:"authorization_model_id"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.TupleKey != (TupleKey{User: "agent:triage", Relation: "executor", Object: "mission:demo"}) {
			t.Fatalf("tuple key = %+v", body.TupleKey)
		}
		if len(body.ContextualTuples.TupleKeys) != 1 {
			t.Fatalf("contextual tuple count = %d", len(body.ContextualTuples.TupleKeys))
		}
		if body.AuthorizationModelID != "model" {
			t.Fatalf("model ID = %q", body.AuthorizationModelID)
		}
		_, _ = writer.Write([]byte(`{"allowed":true}`))
	}))
	defer server.Close()

	client := OpenFGAHTTP{
		APIURL:               server.URL,
		StoreID:              "store",
		AuthorizationModelID: "model",
		Client:               server.Client(),
	}
	allowed, err := client.Check(context.Background(), CheckRequest{
		User:     "agent:triage",
		Relation: "executor",
		Object:   "mission:demo",
		ContextualTuples: []TupleKey{{
			User: "agent:triage", Relation: "executor", Object: "mission:demo",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("OpenFGA response was not returned")
	}
}

func authorize(
	ctx context.Context,
	gateway *Gateway,
	token string,
	call MCPCall,
	agent string,
	now time.Time,
) Decision {
	return gateway.Authorize(ctx, AuthorizationRequest{
		MissionToken: token,
		Agent:        agent,
		Call:         call,
	}, now)
}

func approveCall(t *testing.T, missions *MissionService, call MCPCall) {
	t.Helper()
	callID, err := call.ID()
	if err != nil {
		t.Fatal(err)
	}
	if err := missions.RequestApproval(
		"apollo-17-product-summary-v1",
		callID,
		"reviewed output",
	); err != nil {
		t.Fatal(err)
	}
	if err := missions.ApproveCall(
		"apollo-17-product-summary-v1",
		callID,
		"user:alice",
	); err != nil {
		t.Fatal(err)
	}
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
