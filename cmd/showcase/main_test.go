package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestShowcaseActionsProduceExpectedTimeline(t *testing.T) {
	app := &showcase{}
	if err := app.reset(); err != nil {
		t.Fatal(err)
	}
	if err := app.apply("read"); err != nil {
		t.Fatal(err)
	}
	if err := app.apply("post"); err != nil {
		t.Fatal(err)
	}
	if err := app.apply("approve"); err != nil {
		t.Fatal(err)
	}
	if err := app.apply("post"); err != nil {
		t.Fatal(err)
	}
	if err := app.apply("revoke_source"); err != nil {
		t.Fatal(err)
	}
	if err := app.apply("read"); err != nil {
		t.Fatal(err)
	}

	timeline, err := app.missions.Timeline(missionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(timeline) < 8 {
		t.Fatalf("timeline length = %d, want at least 8", len(timeline))
	}
	last := timeline[len(timeline)-1]
	if last.Decision == nil || last.Decision.Allowed || last.Decision.Reason != "denied by requester_base_access" {
		t.Fatalf("last timeline event = %+v", last)
	}
}

func TestShowcaseHTTPWalkthrough(t *testing.T) {
	app := &showcase{}
	if err := app.reset(); err != nil {
		t.Fatal(err)
	}
	handler := app.routes()
	state := showcaseRequest(t, handler, "")
	if state.Requester != "user:alice" || state.Agent != "agent:triage" || len(state.Grants) != 2 {
		t.Fatalf("initial state: %+v", state)
	}
	state = showcaseRequest(t, handler, "read")
	assertShowcaseDecision(t, state, true, "authorized", 1)
	state = showcaseRequest(t, handler, "post")
	assertShowcaseDecision(t, state, false, "call approval is required", 1)
	if state.Grants[1].Preview != approvalPreview || state.Grants[1].Approved {
		t.Fatal("missing pending preview")
	}
	state = showcaseRequest(t, handler, "post")
	requests := 0
	for _, event := range state.Timeline {
		if event.Kind == "approval_requested" {
			requests++
		}
	}
	if requests != 1 {
		t.Fatalf("duplicate preview requests: %d", requests)
	}
	state = showcaseRequest(t, handler, "approve_retry")
	assertShowcaseDecision(t, state, true, "authorized", 2)
	if !state.Grants[1].Approved {
		t.Fatal("approval not reflected in grant")
	}
	state = showcaseRequest(t, handler, "outside_scope")
	assertShowcaseDecision(t, state, false, "denied by mission_call_scope", 2)
	state = showcaseRequest(t, handler, "revoke_source")
	if state.Authority.RequesterTool || !state.Authority.RequesterResource || !state.Authority.AgentTool {
		t.Fatalf("revocation changed the wrong edge: %+v", state.Authority)
	}
	if state.Timeline[len(state.Timeline)-1].Kind != "source_access_revoked" {
		t.Fatal("revocation missing from timeline")
	}
	state = showcaseRequest(t, handler, "read")
	assertShowcaseDecision(t, state, false, "denied by requester_base_access", 2)
	state = showcaseRequest(t, handler, "restore_source")
	if !state.SourceAccess {
		t.Fatal("restore failed")
	}
	state = showcaseRequest(t, handler, "read")
	assertShowcaseDecision(t, state, true, "authorized", 3)
	state = showcaseRequest(t, handler, "read")
	assertShowcaseDecision(t, state, false, "Mission dispatch budget exhausted", 3)
	for index, event := range state.Timeline {
		if event.Sequence != index+1 {
			t.Fatal("timeline order is not sequential")
		}
		if index > 0 && event.Timestamp.Before(state.Timeline[index-1].Timestamp) {
			t.Fatal("timeline is not chronological")
		}
	}
	state = showcaseRequest(t, handler, "reset")
	if state.LastDecision != nil || state.DispatchCount != 0 || len(state.Timeline) != 2 || !state.SourceAccess || state.Grants[1].Approved || state.Grants[1].Preview != "" {
		t.Fatalf("reset retained state: %+v", state)
	}
}

func TestShowcaseRecordsUnattributedTokenDenials(t *testing.T) {
	app := &showcase{}
	if err := app.reset(); err != nil {
		t.Fatal(err)
	}
	showcaseRequest(t, app.routes(), "read")
	app.token = "invalid-token"
	state := showcaseRequest(t, app.routes(), "read")
	if state.LastDecision == nil || state.LastDecision.Allowed || state.LastDecision.Checks[0].Name != "token_valid" || state.LastDecision.Checks[0].Allowed {
		t.Fatalf("stale allowed decision displayed: %+v", state.LastDecision)
	}
	if state.Timeline[len(state.Timeline)-1].Decision == nil {
		t.Fatal("token denial missing from timeline")
	}
}

func TestShowcaseAssetsAndInvalidActions(t *testing.T) {
	app := &showcase{}
	if err := app.reset(); err != nil {
		t.Fatal(err)
	}
	handler := app.routes()
	for _, path := range []string{"/", "/styles.css", "/app.js"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK || recorder.Body.Len() == 0 {
			t.Fatalf("asset %s: %d", path, recorder.Code)
		}
	}
	for _, test := range []struct {
		method, path, body string
		status             int
	}{
		{http.MethodGet, "/api/action", "", http.StatusMethodNotAllowed},
		{http.MethodPost, "/api/state", "", http.StatusMethodNotAllowed},
		{http.MethodPost, "/api/action", "{", http.StatusBadRequest},
		{http.MethodPost, "/api/action", `{"action":"nope"}`, http.StatusBadRequest},
		{http.MethodPost, "/api/action", `{"action":"approve_retry"}`, http.StatusBadRequest},
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(test.method, test.path, strings.NewReader(test.body)))
		if recorder.Code != test.status {
			t.Fatalf("%s %s %s: %d", test.method, test.path, test.body, recorder.Code)
		}
	}
}

func showcaseRequest(t *testing.T, handler http.Handler, action string) stateView {
	t.Helper()
	method, path, body := http.MethodGet, "/api/state", ""
	if action != "" {
		method, path, body = http.MethodPost, "/api/action", `{"action":"`+action+`"}`
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(method, path, strings.NewReader(body)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", action, recorder.Code, recorder.Body.String())
	}
	var state stateView
	if err := json.NewDecoder(recorder.Body).Decode(&state); err != nil {
		t.Fatal(err)
	}
	return state
}

func assertShowcaseDecision(t *testing.T, state stateView, allowed bool, reason string, dispatches int) {
	t.Helper()
	if state.LastDecision == nil || state.LastDecision.Allowed != allowed || state.LastDecision.Reason != reason || state.DispatchCount != dispatches {
		t.Fatalf("decision = %+v, dispatch count = %d; want allowed=%v reason=%s count=%d", state.LastDecision, state.DispatchCount, allowed, reason, dispatches)
	}
}
