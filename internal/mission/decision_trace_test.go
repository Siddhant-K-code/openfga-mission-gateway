package mission

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestDecisionTraceRecordsVerifiedGates(t *testing.T) {
	_, missions, gateway, token, calls, err := DemoEnvironment(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	decision := gateway.Authorize(context.Background(), AuthorizationRequest{
		MissionToken: token, Agent: "agent:triage", Call: calls.ReadIssue,
	}, time.Now())
	if !decision.Allowed {
		t.Fatalf("read denied: %+v", decision)
	}
	for _, name := range []string{"token_valid", "agent_binding", "mission_active", "mission_expiry", "mission_call_scope", "requester_base_access", "agent_base_access", "requester_resource_access", "agent_resource_access", "mission_dispatch_budget"} {
		check := findTraceCheck(t, decision, name)
		if !check.Allowed || check.Unknown {
			t.Fatalf("%s was not verified: %+v", name, check)
		}
	}
	current, _ := missions.Get(decision.MissionID)
	if current.DispatchCount != 1 {
		t.Fatalf("dispatch count = %d", current.DispatchCount)
	}

	wrongAgent := gateway.Authorize(context.Background(), AuthorizationRequest{
		MissionToken: token, Agent: "agent:other", Call: calls.ReadIssue,
	}, time.Now())
	if wrongAgent.Allowed || findTraceCheck(t, wrongAgent, "agent_binding").Allowed {
		t.Fatal("wrong agent passed")
	}
	if !findTraceCheck(t, wrongAgent, "token_valid").Allowed {
		t.Fatal("lost completed token check")
	}
	for _, check := range wrongAgent.Checks {
		if check.Name == "requester_base_access" {
			t.Fatal("unevaluated authority check recorded")
		}
	}

	badToken := gateway.Authorize(context.Background(), AuthorizationRequest{
		MissionToken: "invalid", Agent: "agent:triage", Call: calls.ReadIssue,
	}, time.Now())
	if badToken.Allowed || len(badToken.Checks) != 1 || badToken.Checks[0].Name != "token_valid" || badToken.Checks[0].Allowed {
		t.Fatalf("invalid token trace = %+v", badToken)
	}
}

type failingTraceStore struct {
	FGAStore
	failAt, calls int
}

func (store *failingTraceStore) Check(ctx context.Context, input CheckRequest) (bool, error) {
	store.calls++
	if store.calls == store.failAt {
		return true, fmt.Errorf("authority unavailable")
	}
	return store.FGAStore.Check(ctx, input)
}

func TestDecisionTraceKeepsEvidenceWhenAuthorityIsUnknown(t *testing.T) {
	gates := []string{"requester_base_access", "agent_base_access", "agent_bound_to_mission", "mission_call_scope", "requester_resource_access", "agent_resource_access"}
	for index, name := range gates {
		t.Run(name, func(t *testing.T) {
			fga, missions, gateway, token, calls, err := DemoEnvironment(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			gateway.fga = &failingTraceStore{FGAStore: fga, failAt: index + 1}
			decision := gateway.Authorize(context.Background(), AuthorizationRequest{
				MissionToken: token, Agent: "agent:triage", Call: calls.ReadIssue,
			}, time.Now())
			if decision.Allowed || decision.Reason != "authorization check failed" {
				t.Fatalf("did not fail closed: %+v", decision)
			}
			last := decision.Checks[len(decision.Checks)-1]
			if last.Name != name || !last.Unknown || last.Allowed {
				t.Fatalf("failed lookup = %+v", last)
			}
			for _, prior := range decision.Checks[:len(decision.Checks)-1] {
				if !prior.Allowed || prior.Unknown {
					t.Fatalf("completed check lost: %+v", prior)
				}
			}
			if index > 0 {
				findTraceCheck(t, decision, gates[index-1])
			}
			if index >= 4 && (last.Relation != "can_read" || last.Object != "tracker_ticket:APOLLO-17") {
				t.Fatalf("missing failed resource context: %+v", last)
			}
			current, _ := missions.Get(decision.MissionID)
			if current.DispatchCount != 0 {
				t.Fatal("unknown authority consumed a dispatch")
			}
			timeline, _ := missions.Timeline(decision.MissionID)
			recorded := timeline[len(timeline)-1].Decision
			if recorded == nil || !findTraceCheck(t, *recorded, name).Unknown {
				t.Fatal("timeline lost unknown result")
			}
		})
	}
}

func findTraceCheck(t *testing.T, decision Decision, name string) CheckResult {
	t.Helper()
	for _, check := range decision.Checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("missing %s in %+v", name, decision.Checks)
	return CheckResult{}
}
