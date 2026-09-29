package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/Siddhant-K-code/openfga-mission-gateway/internal/mission"
)

const missionID = "apollo-17-product-summary-v1"
const approvalPreview = "APOLLO-17: review the ticket for the latest status and next steps."

//go:embed web/*
var frontend embed.FS

type showcase struct {
	mu          sync.Mutex
	fga         *mission.InMemoryFGA
	missions    *mission.MissionService
	gateway     *mission.Gateway
	token       string
	calls       mission.DemoCalls
	localEvents []mission.TimelineEvent
}

type grantView struct {
	CallID           string                        `json:"call_id"`
	Server           string                        `json:"server"`
	Tool             string                        `json:"tool"`
	Scope            map[string]string             `json:"scope"`
	Requirements     []mission.ResourceRequirement `json:"requirements,omitempty"`
	Risk             mission.RiskLevel             `json:"risk"`
	RequiresApproval bool                          `json:"requires_approval"`
	Approved         bool                          `json:"approved"`
	Preview          string                        `json:"preview,omitempty"`
}

type authorityView struct {
	RequesterTool     bool `json:"requester_tool"`
	AgentTool         bool `json:"agent_tool"`
	RequesterResource bool `json:"requester_resource"`
	AgentResource     bool `json:"agent_resource"`
}

type stateView struct {
	Requester     string                  `json:"requester"`
	Agent         string                  `json:"agent"`
	Authority     authorityView           `json:"authority"`
	MissionID     string                  `json:"mission_id"`
	Prompt        string                  `json:"prompt"`
	Rationale     string                  `json:"rationale"`
	State         mission.MissionState    `json:"state"`
	ExpiresAt     time.Time               `json:"expires_at"`
	DispatchCount int                     `json:"dispatch_count"`
	MaxDispatches int                     `json:"max_dispatches"`
	Grants        []grantView             `json:"grants"`
	Timeline      []mission.TimelineEvent `json:"timeline"`
	SourceAccess  bool                    `json:"source_access"`
	LastDecision  *mission.Decision       `json:"last_decision,omitempty"`
}

type actionRequest struct {
	Action string `json:"action"`
}

func main() {
	address := flag.String("addr", "127.0.0.1:8088", "HTTP listen address")
	flag.Parse()

	app := &showcase{}
	if err := app.reset(); err != nil {
		log.Fatal(err)
	}

	mux := app.routes()

	server := &http.Server{
		Addr:              *address,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("showcase available at http://%s", *address)
	log.Fatal(server.ListenAndServe())
}

func (app *showcase) reset() error {
	fga, missions, gateway, token, calls, err := mission.DemoEnvironment(context.Background())
	if err != nil {
		return err
	}
	app.fga = fga
	app.missions = missions
	app.gateway = gateway
	app.token = token
	app.calls = calls
	app.localEvents = nil
	return nil
}

func (app *showcase) routes() http.Handler {
	mux := http.NewServeMux()
	assets, _ := fs.Sub(frontend, "web")
	mux.Handle("/", http.FileServer(http.FS(assets)))
	mux.HandleFunc("/api/state", app.state)
	mux.HandleFunc("/api/action", app.action)
	return mux
}

func (app *showcase) state(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	app.writeState(writer)
}

func (app *showcase) action(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var input actionRequest
	if err := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 4096)).Decode(&input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid action")
		return
	}

	app.mu.Lock()
	defer app.mu.Unlock()
	if err := app.apply(input.Action); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	app.writeState(writer)
}

func (app *showcase) apply(action string) error {
	ctx := context.Background()
	switch action {
	case "read":
		app.authorize(app.calls.ReadIssue)
	case "post":
		decision := app.authorize(app.calls.PostSummary)
		if decision.Reason == "call approval is required" {
			callID, _ := app.calls.PostSummary.ID()
			current, err := app.missions.Get(missionID)
			if err != nil {
				return err
			}
			if current.ApprovalPreviews[callID] == "" {
				return app.missions.RequestApproval(missionID, callID, approvalPreview)
			}
		}
	case "approve", "approve_retry":
		callID, err := app.calls.PostSummary.ID()
		if err != nil {
			return err
		}
		current, err := app.missions.Get(missionID)
		if err != nil {
			return err
		}
		if current.State != mission.MissionActive || !current.ExpiresAt.After(time.Now()) {
			return fmt.Errorf("this Mission is no longer active; reset the demo")
		}
		if current.ApprovalPreviews[callID] == "" {
			return fmt.Errorf("attempt the product post first to review its approval preview")
		}
		if !current.ApprovedCalls[callID] {
			if err := app.missions.ApproveCall(missionID, callID, current.Requester); err != nil {
				return err
			}
		}
		if action == "approve_retry" {
			return app.apply("post")
		}
	case "outside_scope":
		app.authorize(app.calls.PostOtherTarget)
	case "revoke_source", "restore_source":
		serverID, err := app.calls.ReadIssue.ServerID()
		if err != nil {
			return err
		}
		tuple := mission.TupleKey{User: "user:alice", Relation: "operator", Object: serverID}
		access, err := app.fga.Check(ctx, mission.CheckRequest{User: tuple.User, Relation: tuple.Relation, Object: tuple.Object})
		if err != nil {
			return err
		}
		restore := action == "restore_source"
		if access == restore {
			return nil
		}
		kind, summary := mission.TimelineKind("source_access_revoked"), "Alice’s work-tracker access revoked"
		if restore {
			err = app.fga.Write(ctx, []mission.TupleKey{tuple})
			kind, summary = "source_access_restored", "Alice’s work-tracker access restored"
		} else {
			err = app.fga.Delete(ctx, []mission.TupleKey{tuple})
		}
		if err != nil {
			return err
		}
		app.localEvents = append(app.localEvents, mission.TimelineEvent{
			Kind: kind, Timestamp: time.Now().UTC(), MissionID: missionID, Actor: "user:alice", Summary: summary,
		})
	case "reset":
		return app.reset()
	default:
		return fmt.Errorf("unknown action %q", action)
	}
	return nil
}

// The showcase knows which local session attempted the call even when an
// invalid token cannot be associated with a Mission by the gateway itself.
func (app *showcase) authorize(call mission.MCPCall) mission.Decision {
	decision := app.gateway.Authorize(context.Background(), mission.AuthorizationRequest{
		MissionToken: app.token, Agent: "agent:triage", Call: call,
	}, time.Now())
	if decision.MissionID == "" {
		callID, _ := call.ID()
		app.localEvents = append(app.localEvents, mission.TimelineEvent{
			Kind: mission.TimelineDecision, Timestamp: decision.Timestamp,
			MissionID: missionID, Actor: decision.Agent, CallID: callID,
			Summary: decision.Reason, Decision: &decision,
		})
	}
	return decision
}

func (app *showcase) writeState(writer http.ResponseWriter) {
	current, err := app.missions.Get(missionID)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, err.Error())
		return
	}
	timeline, err := app.missions.Timeline(missionID)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, err.Error())
		return
	}
	grants := make([]grantView, 0, len(current.Intent.Grants))
	for _, grant := range current.Intent.Grants {
		callID, err := grant.Call.ID()
		if err != nil {
			writeError(writer, http.StatusInternalServerError, err.Error())
			return
		}
		stored, _ := current.Grant(callID)
		grants = append(grants, grantView{
			CallID:           callID,
			Server:           grant.Call.Server,
			Tool:             grant.Call.Tool,
			Scope:            grant.Call.Scope,
			Requirements:     grant.Call.Requirements,
			Risk:             stored.Risk,
			RequiresApproval: stored.RequiresApproval,
			Approved:         current.ApprovedCalls[callID],
			Preview:          current.ApprovalPreviews[callID],
		})
	}

	serverID, err := app.calls.ReadIssue.ServerID()
	if err != nil {
		writeError(writer, http.StatusInternalServerError, err.Error())
		return
	}
	authority := authorityView{}
	for _, gate := range []struct {
		user, relation, object string
		target                 *bool
	}{
		{current.Requester, "operator", serverID, &authority.RequesterTool},
		{current.Agent, "operator", serverID, &authority.AgentTool},
		{current.Requester, "can_read", "tracker_ticket:APOLLO-17", &authority.RequesterResource},
		{current.Agent, "can_read", "tracker_ticket:APOLLO-17", &authority.AgentResource},
	} {
		allowed, err := app.fga.Check(context.Background(), mission.CheckRequest{User: gate.user, Relation: gate.relation, Object: gate.object})
		if err != nil {
			writeError(writer, http.StatusInternalServerError, err.Error())
			return
		}
		*gate.target = allowed
	}
	timeline = append(timeline, app.localEvents...)
	sort.SliceStable(timeline, func(i, j int) bool { return timeline[i].Timestamp.Before(timeline[j].Timestamp) })
	for index := range timeline {
		timeline[index].Sequence = index + 1
	}

	var lastDecision *mission.Decision
	for index := len(timeline) - 1; index >= 0; index-- {
		if timeline[index].Decision != nil {
			decision := *timeline[index].Decision
			lastDecision = &decision
			break
		}
	}
	writeJSON(writer, http.StatusOK, stateView{
		MissionID:     current.ID,
		Prompt:        current.Intent.UserPrompt,
		Rationale:     current.Intent.Rationale,
		State:         current.State,
		ExpiresAt:     current.ExpiresAt,
		DispatchCount: current.DispatchCount,
		MaxDispatches: current.MaxDispatches,
		Grants:        grants,
		Timeline:      timeline,
		Requester:     current.Requester,
		Agent:         current.Agent,
		Authority:     authority,
		SourceAccess:  authority.RequesterTool,
		LastDecision:  lastDecision,
	})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, map[string]string{"error": message})
}
