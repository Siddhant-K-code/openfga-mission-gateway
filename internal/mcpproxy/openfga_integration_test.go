//go:build integration

package mcpproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Siddhant-K-code/openfga-mission-gateway/internal/mission"
)

func TestOpenFGAIntegrationForMCPProxy(t *testing.T) {
	apiURL := requiredIntegrationEnv(t, "FGA_API_URL")
	storeID := requiredIntegrationEnv(t, "FGA_STORE_ID")
	modelID := requiredIntegrationEnv(t, "FGA_MODEL_ID")
	if apiURL == "" || storeID == "" || modelID == "" {
		return
	}

	ctx := context.Background()
	fga := &mission.OpenFGAHTTP{
		APIURL:               apiURL,
		StoreID:              storeID,
		AuthorizationModelID: modelID,
		Client:               http.DefaultClient,
	}
	readCall := mission.MCPCall{
		Server: "work-tracker",
		Tool:   "get_issue",
		Scope:  map[string]string{"issue_id": "APOLLO-17"},
	}
	postCall := mission.MCPCall{
		Server: "team-chat",
		Tool:   "post_message",
		Scope:  map[string]string{"channel_id": "product"},
	}
	otherTarget := mission.MCPCall{
		Server: "team-chat",
		Tool:   "post_message",
		Scope:  map[string]string{"channel_id": "company"},
	}

	tuples := append(durableTuples(t, readCall), durableTuples(t, postCall)...)
	tuples = append(tuples, durableTuples(t, otherTarget)...)
	for _, call := range []mission.MCPCall{readCall, postCall, otherTarget} {
		serverID, err := call.ServerID()
		if err != nil {
			t.Fatal(err)
		}
		tuples = append(tuples, mission.TupleKey{
			User: "user:alice", Relation: "operator", Object: serverID,
		})
	}
	tuples = uniqueTuples(tuples)
	if err := fga.Write(ctx, tuples); err != nil {
		t.Fatalf("seed OpenFGA tuples: %v", err)
	}
	t.Cleanup(func() {
		if err := fga.Delete(context.Background(), tuples); err != nil {
			t.Logf("cleanup OpenFGA tuples: %v", err)
		}
	})

	signer, err := mission.NewMissionTokenSigner([]byte("mcp-proxy-live-fga-secret-32-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	missions := mission.NewMissionService(fga, signer)
	_, err = missions.CreateDraft(mission.CreateMissionInput{
		MissionID: "mcp-live-fga-demo",
		Requester: "user:alice",
		Agent:     "agent:triage",
		Intent: mission.IntentProposal{Grants: []mission.CallGrant{
			{Call: readCall},
			{Call: postCall, RequiresApproval: true},
		}},
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := missions.Approve(ctx, "mcp-live-fga-demo", "user:alice", time.Now())
	if err != nil {
		t.Fatalf("approve Mission through live OpenFGA checks: %v", err)
	}

	fixture := &upstreamFixture{}
	upstreamMCP := fixture.server()
	upstreamServer := httptest.NewServer(mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return upstreamMCP },
		&mcp.StreamableHTTPOptions{JSONResponse: true},
	))
	defer upstreamServer.Close()
	upstreamSession := connectClient(t, ctx, upstreamServer.URL, http.DefaultClient)
	defer upstreamSession.Close()

	proxy, err := New(mission.NewGateway(fga, missions, signer), signer, SessionUpstream{Session: upstreamSession}, []ToolPolicy{
		{
			GatewayTool:  "work.get_issue",
			UpstreamTool: "get_issue",
			Server:       "work-tracker",
			Description:  "Read a work item.",
			InputSchema:  requiredStringSchema("issue_id"),
			ExtractScope: RequiredStringScope(map[string]string{"issue_id": "issue_id"}),
		},
		{
			GatewayTool:  "chat.post_message",
			UpstreamTool: "post_message",
			Server:       "team-chat",
			Description:  "Post a message.",
			InputSchema:  requiredStringSchema("channel_id"),
			ExtractScope: RequiredStringScope(map[string]string{"channel_id": "channel_id"}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	proxyServer := httptest.NewServer(proxy.HTTPHandler())
	defer proxyServer.Close()
	client := connectClient(t, ctx, proxyServer.URL, bearerClient(token))
	defer client.Close()

	allowed, err := client.CallTool(ctx, &mcp.CallToolParams{
		Name: "work.get_issue",
		Arguments: map[string]any{
			"issue_id": "APOLLO-17",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if allowed.IsError || fixture.callCount("get_issue") != 1 {
		t.Fatalf("live OpenFGA allowed result = %+v, upstream calls = %d", allowed, fixture.callCount("get_issue"))
	}

	denied, err := client.CallTool(ctx, &mcp.CallToolParams{
		Name: "chat.post_message",
		Arguments: map[string]any{
			"channel_id": "company",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !denied.IsError || resultText(denied) != "denied: denied by mission_call_scope" {
		t.Fatalf("live OpenFGA scope denial = %+v", denied)
	}
	if fixture.callCount("post_message") != 0 {
		t.Fatalf("denied call reached upstream %d times", fixture.callCount("post_message"))
	}

	readServerID, err := readCall.ServerID()
	if err != nil {
		t.Fatal(err)
	}
	if err := fga.Delete(ctx, []mission.TupleKey{{
		User: "user:alice", Relation: "operator", Object: readServerID,
	}}); err != nil {
		t.Fatal(err)
	}
	deniedAfterRevoke, err := client.CallTool(ctx, &mcp.CallToolParams{
		Name: "work.get_issue",
		Arguments: map[string]any{
			"issue_id": "APOLLO-17",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !deniedAfterRevoke.IsError || resultText(deniedAfterRevoke) != "denied: denied by requester_base_access" {
		t.Fatalf("live OpenFGA revocation denial = %+v", deniedAfterRevoke)
	}
	if fixture.callCount("get_issue") != 1 {
		t.Fatalf("revoked call reached upstream %d times", fixture.callCount("get_issue"))
	}
	if err := fga.Write(ctx, []mission.TupleKey{{
		User: "user:alice", Relation: "operator", Object: readServerID,
	}}); err != nil {
		t.Fatal(err)
	}
}

func requiredIntegrationEnv(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Skipf("set %s to run the live OpenFGA integration test", name)
	}
	return value
}
