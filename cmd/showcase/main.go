package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/Siddhant-K-code/openfga-mission-gateway/internal/mission"
)

const missionID = "apollo-17-product-summary-v1"

type showcase struct {
	mu       sync.Mutex
	fga      *mission.InMemoryFGA
	missions *mission.MissionService
	gateway  *mission.Gateway
	token    string
	calls    mission.DemoCalls
}

type grantView struct {
	CallID           string                        `json:"call_id"`
	Server           string                        `json:"server"`
	Tool             string                        `json:"tool"`
	Scope            map[string]string             `json:"scope"`
	Requirements     []mission.ResourceRequirement `json:"requirements,omitempty"`
	Risk             mission.RiskLevel             `json:"risk"`
	RequiresApproval bool                          `json:"requires_approval"`
}

type stateView struct {
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
	ResourceGraph []string                `json:"resource_graph"`
	LastDecision  *mission.Decision       `json:"last_decision,omitempty"`
}

type actionRequest struct {
	Action string `json:"action"`
}

func main() {
	address := flag.String("addr", ":8088", "HTTP listen address")
	flag.Parse()

	app := &showcase{}
	if err := app.reset(); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.index)
	mux.HandleFunc("/api/state", app.state)
	mux.HandleFunc("/api/action", app.action)

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
	return nil
}

func (app *showcase) index(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = writer.Write([]byte(indexHTML))
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
		app.gateway.Authorize(ctx, mission.AuthorizationRequest{
			MissionToken: app.token,
			Agent:        "agent:triage",
			Call:         app.calls.ReadIssue,
		}, time.Now())
	case "post":
		app.gateway.Authorize(ctx, mission.AuthorizationRequest{
			MissionToken: app.token,
			Agent:        "agent:triage",
			Call:         app.calls.PostSummary,
		}, time.Now())
	case "approve":
		callID, err := app.calls.PostSummary.ID()
		if err != nil {
			return err
		}
		current, err := app.missions.Get(missionID)
		if err != nil {
			return err
		}
		if current.ApprovalPreviews[callID] == "" {
			if err := app.missions.RequestApproval(missionID, callID, "APOLLO-17 summary for the product channel."); err != nil {
				return err
			}
		}
		if !current.ApprovedCalls[callID] {
			if err := app.missions.ApproveCall(missionID, callID, "user:alice"); err != nil {
				return err
			}
		}
	case "outside_scope":
		app.gateway.Authorize(ctx, mission.AuthorizationRequest{
			MissionToken: app.token,
			Agent:        "agent:triage",
			Call:         app.calls.PostOtherTarget,
		}, time.Now())
	case "revoke_source":
		serverID, err := app.calls.ReadIssue.ServerID()
		if err != nil {
			return err
		}
		return app.fga.Delete(ctx, []mission.TupleKey{{
			User: "user:alice", Relation: "operator", Object: serverID,
		}})
	case "reset":
		return app.reset()
	default:
		return fmt.Errorf("unknown action %q", action)
	}
	return nil
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
		})
	}

	serverID, err := app.calls.ReadIssue.ServerID()
	if err != nil {
		writeError(writer, http.StatusInternalServerError, err.Error())
		return
	}
	sourceAccess, err := app.fga.Check(context.Background(), mission.CheckRequest{
		User: "user:alice", Relation: "operator", Object: serverID,
	})
	if err != nil {
		writeError(writer, http.StatusInternalServerError, err.Error())
		return
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
		SourceAccess:  sourceAccess,
		ResourceGraph: []string{
			"user:alice -> member -> tracker_project:apollo",
			"agent:triage -> member -> tracker_project:apollo",
			"tracker_project:apollo -> project -> tracker_ticket:APOLLO-17",
		},
		LastDecision: lastDecision,
	})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, map[string]string{"error": message})
}

const indexHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Mission Gateway Showcase</title>
  <style>
    :root { --ink:#172033; --muted:#62708a; --line:#d9e0eb; --paper:#ffffff; --wash:#f5f7fb; --blue:#1967d2; --green:#147a52; --amber:#a76000; --red:#be3131; }
    * { box-sizing:border-box; }
    body { margin:0; background:var(--wash); color:var(--ink); font:14px/1.45 Inter, ui-sans-serif, system-ui, sans-serif; }
    header { min-height:64px; padding:14px 24px; display:flex; align-items:center; justify-content:space-between; background:#101b31; color:#fff; }
    header h1 { margin:0; font-size:18px; font-weight:700; letter-spacing:0; }
    header p { margin:2px 0 0; color:#bdc7da; font-size:12px; }
    main { max-width:1280px; margin:0 auto; padding:24px; display:grid; grid-template-columns:280px minmax(0, 1fr); gap:20px; }
    aside, section { background:var(--paper); border:1px solid var(--line); border-radius:6px; }
    aside { padding:18px; align-self:start; }
    .label { color:var(--muted); font-size:11px; font-weight:700; letter-spacing:0; text-transform:uppercase; }
    .mission-id { margin:7px 0 16px; font:600 13px ui-monospace, SFMono-Regular, Menlo, monospace; overflow-wrap:anywhere; }
    .state { display:inline-flex; padding:3px 8px; border-radius:4px; color:#fff; background:var(--green); font-size:12px; font-weight:700; }
    .metric { display:flex; justify-content:space-between; padding:9px 0; border-top:1px solid var(--line); }
    .metric strong { font-variant-numeric:tabular-nums; }
    .graph { margin:18px -18px -18px; padding:16px 18px; border-top:1px solid var(--line); background:#fbfcff; font:12px/1.55 ui-monospace, SFMono-Regular, Menlo, monospace; color:#33435f; }
    .graph div { overflow-wrap:anywhere; }
    .content { display:grid; gap:20px; }
    section { padding:18px; }
    h2 { margin:0 0 12px; font-size:16px; letter-spacing:0; }
    .prompt { margin:0; max-width:850px; font-size:17px; }
    .rationale { margin:8px 0 0; color:var(--muted); }
    .grants { width:100%; border-collapse:collapse; }
    .grants th, .grants td { padding:10px 8px; border-top:1px solid var(--line); text-align:left; vertical-align:top; }
    .grants th { color:var(--muted); font-size:11px; text-transform:uppercase; }
    code { font:12px ui-monospace, SFMono-Regular, Menlo, monospace; color:#203457; }
    .risk { font-size:12px; font-weight:700; text-transform:uppercase; }
    .risk.low { color:var(--green); } .risk.high { color:var(--red); } .risk.medium { color:var(--amber); }
    .actions { display:flex; flex-wrap:wrap; gap:8px; }
    button { padding:8px 10px; border:1px solid #9eacc2; border-radius:4px; background:#fff; color:#172033; cursor:pointer; font:600 13px inherit; }
    button.primary { border-color:var(--blue); background:var(--blue); color:#fff; }
    button.warn { border-color:#c5760e; color:#8a5100; } button.danger { border-color:#d58a8a; color:var(--red); }
    button:hover { filter:brightness(.97); } button:disabled { cursor:wait; opacity:.6; }
    .decision { display:none; margin-top:14px; padding:11px 12px; border-left:4px solid var(--line); background:#fbfcff; }
    .decision.allow { display:block; border-color:var(--green); } .decision.deny { display:block; border-color:var(--red); }
    .timeline { list-style:none; margin:0; padding:0; }
    .event { display:grid; grid-template-columns:150px minmax(0, 1fr); gap:12px; padding:12px 0; border-top:1px solid var(--line); }
    .event time { color:var(--muted); font:12px ui-monospace, SFMono-Regular, Menlo, monospace; }
    .event-kind { font-weight:700; } .event-summary { color:#394660; margin-top:2px; }
    .event-decision { margin-top:6px; font:12px ui-monospace, SFMono-Regular, Menlo, monospace; }
    .allowed { color:var(--green); } .denied { color:var(--red); }
    .error { display:none; margin:0 0 12px; padding:10px; border-left:4px solid var(--red); background:#fff1f1; color:#8a2424; }
    @media (max-width:760px) { main { padding:14px; grid-template-columns:1fr; } header { padding:14px; } .event { grid-template-columns:1fr; gap:3px; } .grants th:nth-child(3), .grants td:nth-child(3) { display:none; } }
  </style>
</head>
<body>
  <header><div><h1>Mission Gateway</h1><p>Relationship-aware MCP delegation</p></div><button id="reset">Reset demo</button></header>
  <main>
    <aside>
      <div class="label">Mission</div><div id="mission-id" class="mission-id"></div><span id="state" class="state"></span>
      <div class="metric"><span>Dispatches</span><strong id="dispatches"></strong></div>
      <div class="metric"><span>Source access</span><strong id="source-access"></strong></div>
      <div class="graph"><div class="label">Resource graph</div><div id="graph"></div></div>
    </aside>
    <div class="content">
      <section><div class="label">Approved intent</div><p id="prompt" class="prompt"></p><p id="rationale" class="rationale"></p></section>
      <section><h2>Delegated calls</h2><table class="grants"><thead><tr><th>Tool</th><th>Scope</th><th>Resource check</th><th>Risk</th></tr></thead><tbody id="grants"></tbody></table></section>
      <section><h2>Exercise gateway</h2><div id="error" class="error"></div><div class="actions"><button class="primary" data-action="read">Read APOLLO-17</button><button data-action="post">Post summary</button><button class="warn" data-action="approve">Approve summary</button><button class="danger" data-action="outside_scope">Try #company</button><button class="danger" data-action="revoke_source">Revoke source access</button></div><div id="decision" class="decision"></div></section>
      <section><h2>Timeline</h2><ol id="timeline" class="timeline"></ol></section>
    </div>
  </main>
  <script>
    const esc = value => String(value || '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
    const textTime = value => new Date(value).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
    let busy = false;
    async function request(path, options) { const response = await fetch(path, options); const body = await response.json(); if (!response.ok) throw new Error(body.error || 'Request failed'); return body; }
    function render(data) {
      document.querySelector('#mission-id').textContent = data.mission_id;
      document.querySelector('#state').textContent = data.state;
      document.querySelector('#dispatches').textContent = data.dispatch_count + ' / ' + data.max_dispatches;
      const source = document.querySelector('#source-access'); source.textContent = data.source_access ? 'active' : 'revoked'; source.className = data.source_access ? 'allowed' : 'denied';
      document.querySelector('#prompt').textContent = data.prompt;
      document.querySelector('#rationale').textContent = data.rationale;
      document.querySelector('#graph').innerHTML = data.resource_graph.map(item => '<div>' + esc(item) + '</div>').join('');
      document.querySelector('#grants').innerHTML = data.grants.map(grant => {
        const resource = grant.requirements && grant.requirements.length ? grant.requirements.map(item => esc(item.relation + ' ' + item.object)).join('<br>') : '—';
        return '<tr><td><code>' + esc(grant.server + '/' + grant.tool) + '</code></td><td><code>' + esc(JSON.stringify(grant.scope)) + '</code></td><td><code>' + resource + '</code></td><td><span class="risk ' + esc(grant.risk) + '">' + esc(grant.risk) + (grant.requires_approval ? ' · approval' : '') + '</span></td></tr>';
      }).join('');
      const decision = document.querySelector('#decision');
      if (data.last_decision) { decision.className = 'decision ' + (data.last_decision.allowed ? 'allow' : 'deny'); decision.innerHTML = '<strong>' + (data.last_decision.allowed ? 'Allowed' : 'Denied') + '</strong> · ' + esc(data.last_decision.reason); }
      document.querySelector('#timeline').innerHTML = data.timeline.map(event => {
        const result = event.decision ? '<div class="event-decision ' + (event.decision.allowed ? 'allowed' : 'denied') + '">' + (event.decision.allowed ? 'ALLOWED' : 'DENIED') + ' · ' + esc(event.decision.reason) + '</div>' : '';
        return '<li class="event"><time>' + esc(textTime(event.timestamp)) + '</time><div><div class="event-kind">' + esc(event.kind.replace(/_/g, ' ')) + '</div><div class="event-summary">' + esc(event.summary) + '</div>' + result + '</div></li>';
      }).join('');
    }
    async function load() { try { render(await request('/api/state')); } catch (error) { showError(error.message); } }
    function showError(message) { const box = document.querySelector('#error'); box.textContent = message; box.style.display = 'block'; }
    async function act(action) { if (busy) return; busy = true; document.querySelectorAll('button').forEach(button => button.disabled = true); document.querySelector('#error').style.display = 'none'; try { render(await request('/api/action', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action})})); } catch (error) { showError(error.message); } finally { busy = false; document.querySelectorAll('button').forEach(button => button.disabled = false); } }
    document.querySelectorAll('[data-action]').forEach(button => button.addEventListener('click', () => act(button.dataset.action)));
    document.querySelector('#reset').addEventListener('click', () => act('reset'));
    load();
  </script>
</body>
</html>`
