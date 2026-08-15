package mcpproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Siddhant-K-code/openfga-mission-gateway/internal/mission"
)

func TestProxyForwardsOnlyAuthorizedMCPCalls(t *testing.T) {
	ctx := context.Background()
	fixture := &upstreamFixture{}
	upstreamMCP := fixture.server()
	upstreamServer := httptest.NewServer(fixture.streamableHandler(upstreamMCP))
	defer upstreamServer.Close()

	upstreamSession := connectClient(t, ctx, upstreamServer.URL, http.DefaultClient)
	defer upstreamSession.Close()

	proxy, missions, token := newProxyEnvironment(t, SessionUpstream{Session: upstreamSession})
	proxyServer := httptest.NewServer(proxy.HTTPHandler())
	defer proxyServer.Close()

	client := connectClient(t, ctx, proxyServer.URL, bearerClient(token, "agent:triage"))
	defer client.Close()

	tools, err := client.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 2 {
		t.Fatalf("tool count = %d, want 2", len(tools.Tools))
	}

	readResult, err := client.CallTool(ctx, &mcp.CallToolParams{
		Name: "work.get_issue",
		Arguments: map[string]any{
			"issue_id": "APOLLO-17",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if readResult.IsError {
		t.Fatalf("read result = %+v", readResult)
	}
	if got := fixture.callCount("get_issue"); got != 1 {
		t.Fatalf("get_issue upstream calls = %d, want 1", got)
	}
	if !fixture.allInboundAuthorizationEmpty() {
		t.Fatal("Mission bearer token was forwarded to the upstream MCP server")
	}

	wrongAgent := connectClient(t, ctx, proxyServer.URL, bearerClient(token, "agent:other"))
	defer wrongAgent.Close()
	wrongAgentResult, err := wrongAgent.CallTool(ctx, &mcp.CallToolParams{
		Name: "work.get_issue",
		Arguments: map[string]any{
			"issue_id": "APOLLO-17",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !wrongAgentResult.IsError || resultText(wrongAgentResult) != "denied: Mission token is not bound to this agent" {
		t.Fatalf("wrong agent result = %+v", wrongAgentResult)
	}
	if got := fixture.callCount("get_issue"); got != 1 {
		t.Fatalf("wrong agent call reached upstream %d times", got)
	}

	blockedPost, err := client.CallTool(ctx, &mcp.CallToolParams{
		Name: "chat.post_message",
		Arguments: map[string]any{
			"channel_id": "product",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !blockedPost.IsError || resultText(blockedPost) != "denied: call approval is required" {
		t.Fatalf("blocked post = %+v", blockedPost)
	}
	if got := fixture.callCount("post_message"); got != 0 {
		t.Fatalf("post_message upstream calls = %d, want 0", got)
	}

	postCall := mission.MCPCall{
		Server: "team-chat",
		Tool:   "post_message",
		Scope:  map[string]string{"channel_id": "product"},
	}
	postCallID, err := postCall.ID()
	if err != nil {
		t.Fatal(err)
	}
	if err := missions.RequestApproval("mcp-demo", postCallID, "safe summary"); err != nil {
		t.Fatal(err)
	}
	if err := missions.ApproveCall("mcp-demo", postCallID, "user:alice"); err != nil {
		t.Fatal(err)
	}

	approvedPost, err := client.CallTool(ctx, &mcp.CallToolParams{
		Name: "chat.post_message",
		Arguments: map[string]any{
			"channel_id": "product",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if approvedPost.IsError {
		t.Fatalf("approved post = %+v", approvedPost)
	}
	if got := fixture.callCount("post_message"); got != 1 {
		t.Fatalf("post_message upstream calls = %d, want 1", got)
	}

	otherTarget, err := client.CallTool(ctx, &mcp.CallToolParams{
		Name: "chat.post_message",
		Arguments: map[string]any{
			"channel_id": "company",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !otherTarget.IsError || resultText(otherTarget) != "denied: denied by mission_call_scope" {
		t.Fatalf("other target = %+v", otherTarget)
	}
	if got := fixture.callCount("post_message"); got != 1 {
		t.Fatalf("post_message upstream calls = %d, want 1", got)
	}

	if err := missions.Revoke("mcp-demo"); err != nil {
		t.Fatal(err)
	}
	revoked, err := client.CallTool(ctx, &mcp.CallToolParams{
		Name: "work.get_issue",
		Arguments: map[string]any{
			"issue_id": "APOLLO-17",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !revoked.IsError || resultText(revoked) != "denied: Mission is revoked" {
		t.Fatalf("revoked result = %+v", revoked)
	}
	if got := fixture.callCount("get_issue"); got != 1 {
		t.Fatalf("get_issue upstream calls = %d, want 1", got)
	}
}

func newProxyEnvironment(t *testing.T, upstream Upstream) (*Proxy, *mission.MissionService, string) {
	t.Helper()
	readCall := mission.MCPCall{
		Server: "work-tracker",
		Tool:   "get_issue",
		Scope:  map[string]string{"issue_id": "APOLLO-17"},
		Requirements: []mission.ResourceRequirement{{
			Relation: "can_read",
			Object:   "tracker_ticket:APOLLO-17",
		}},
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
	tuples = append(tuples,
		mission.TupleKey{User: "tracker_project:apollo", Relation: "project", Object: "tracker_ticket:APOLLO-17"},
		mission.TupleKey{User: "user:alice", Relation: "member", Object: "tracker_project:apollo"},
		mission.TupleKey{User: "agent:triage", Relation: "member", Object: "tracker_project:apollo"},
	)
	for _, call := range []mission.MCPCall{readCall, postCall, otherTarget} {
		serverID, err := call.ServerID()
		if err != nil {
			t.Fatal(err)
		}
		for _, principal := range []string{"user:alice", "agent:triage"} {
			tuples = append(tuples, mission.TupleKey{
				User: principal, Relation: "operator", Object: serverID,
			})
		}
	}
	tuples = uniqueTuples(tuples)
	fga := mission.NewInMemoryFGA(tuples)
	signer, err := mission.NewMissionTokenSigner([]byte("mcp-proxy-demo-secret-32-bytes!"))
	if err != nil {
		t.Fatal(err)
	}
	missions := mission.NewMissionService(fga, signer)
	_, err = missions.CreateDraft(mission.CreateMissionInput{
		MissionID: "mcp-demo",
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
	token, err := missions.Approve(context.Background(), "mcp-demo", "user:alice", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := New(mission.NewGateway(fga, missions, signer), signer, upstream, []ToolPolicy{
		{
			GatewayTool:      "work.get_issue",
			UpstreamTool:     "get_issue",
			Server:           "work-tracker",
			Description:      "Read a work item.",
			InputSchema:      requiredStringSchema("issue_id"),
			ExtractScope:     RequiredStringScope(map[string]string{"issue_id": "issue_id"}),
			ResolveResources: trackerTicketResource,
		},
		{
			GatewayTool:  "chat.post_message",
			UpstreamTool: "post_message",
			Server:       "team-chat",
			Description:  "Post a message.",
			InputSchema:  requiredStringSchema("channel_id"),
			ExtractScope: RequiredStringScope(map[string]string{"channel_id": "channel_id"}),
		},
	}, testAgentIdentity)
	if err != nil {
		t.Fatal(err)
	}
	return proxy, missions, token
}

func trackerTicketResource(arguments map[string]any) ([]mission.ResourceRequirement, error) {
	issueID, ok := arguments["issue_id"].(string)
	if !ok || issueID == "" {
		return nil, fmt.Errorf("issue_id must be a non-empty string")
	}
	return []mission.ResourceRequirement{{
		Relation: "can_read",
		Object:   "tracker_ticket:" + issueID,
	}}, nil
}

func durableTuples(t *testing.T, call mission.MCPCall) []mission.TupleKey {
	t.Helper()
	serverID, err := call.ServerID()
	if err != nil {
		t.Fatal(err)
	}
	toolID, err := call.ToolID()
	if err != nil {
		t.Fatal(err)
	}
	return []mission.TupleKey{
		{User: serverID, Relation: "server", Object: toolID},
	}
}

func uniqueTuples(tuples []mission.TupleKey) []mission.TupleKey {
	unique := make([]mission.TupleKey, 0, len(tuples))
	seen := make(map[mission.TupleKey]struct{}, len(tuples))
	for _, tuple := range tuples {
		if _, exists := seen[tuple]; exists {
			continue
		}
		seen[tuple] = struct{}{}
		unique = append(unique, tuple)
	}
	return unique
}

func connectClient(
	t *testing.T,
	ctx context.Context,
	endpoint string,
	httpClient *http.Client,
) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "gateway-test-client", Version: "v0.1.0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             endpoint,
		HTTPClient:           httpClient,
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func requiredStringSchema(name string) map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			name: map[string]any{"type": "string"},
		},
		"required":             []string{name},
		"additionalProperties": false,
	}
}

type bearerRoundTripper struct {
	token string
	agent string
	base  http.RoundTripper
}

func bearerClient(token, agent string) *http.Client {
	return &http.Client{Transport: bearerRoundTripper{
		token: token,
		agent: agent,
		base:  http.DefaultTransport,
	}}
}

func (transport bearerRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.Header = request.Header.Clone()
	copy.Header.Set("Authorization", "Bearer "+transport.token)
	copy.Header.Set("X-MCP-Agent-ID", transport.agent)
	return transport.base.RoundTrip(copy)
}

// testAgentIdentity models a trusted authentication layer that has already
// verified a workload credential and supplies the principal to this proxy.
// A raw HTTP header alone is not suitable for production authentication.
func testAgentIdentity(request *http.Request) (string, error) {
	return request.Header.Get("X-MCP-Agent-ID"), nil
}

type upstreamFixture struct {
	mu             sync.Mutex
	calls          []string
	authorizations []string
}

func (fixture *upstreamFixture) streamableHandler(server *mcp.Server) http.Handler {
	return mcp.NewStreamableHTTPHandler(func(request *http.Request) *mcp.Server {
		fixture.mu.Lock()
		fixture.authorizations = append(fixture.authorizations, request.Header.Get("Authorization"))
		fixture.mu.Unlock()
		return server
	}, &mcp.StreamableHTTPOptions{JSONResponse: true})
}

func (fixture *upstreamFixture) server() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "upstream-fixture", Version: "v0.1.0"}, nil)
	for _, name := range []string{"get_issue", "post_message"} {
		name := name
		server.AddTool(&mcp.Tool{
			Name:        name,
			Description: "Test upstream tool.",
			InputSchema: map[string]any{"type": "object"},
		}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			fixture.mu.Lock()
			fixture.calls = append(fixture.calls, request.Params.Name)
			fixture.mu.Unlock()
			return &mcp.CallToolResult{Content: []mcp.Content{
				&mcp.TextContent{Text: "upstream called"},
			}}, nil
		})
	}
	return server
}

func (fixture *upstreamFixture) callCount(name string) int {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	count := 0
	for _, call := range fixture.calls {
		if call == name {
			count++
		}
	}
	return count
}

func (fixture *upstreamFixture) allInboundAuthorizationEmpty() bool {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	for _, authorization := range fixture.authorizations {
		if authorization != "" {
			return false
		}
	}
	return true
}

func resultText(result *mcp.CallToolResult) string {
	if result == nil || len(result.Content) == 0 {
		return ""
	}
	text, _ := result.Content[0].(*mcp.TextContent)
	if text == nil {
		return ""
	}
	return text.Text
}

func TestRequiredStringScope(t *testing.T) {
	extractor := RequiredStringScope(map[string]string{"channel_id": "channel"})
	scope, err := extractor(map[string]any{"channel": "product"})
	if err != nil {
		t.Fatal(err)
	}
	if scope["channel_id"] != "product" {
		t.Fatalf("scope = %v", scope)
	}
	if _, err := extractor(map[string]any{"channel": 1}); err == nil {
		t.Fatal("non-string scope argument was accepted")
	}
}

func TestProxyRejectsInvalidBearerToken(t *testing.T) {
	proxy, _, _ := newProxyEnvironment(t, upstreamStub{})
	server := httptest.NewServer(proxy.HTTPHandler())
	defer server.Close()

	response, err := http.Post(server.URL, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusUnauthorized)
	}
}

func TestProxyRejectsMissionTokenWithoutAgentIdentity(t *testing.T) {
	proxy, _, token := newProxyEnvironment(t, upstreamStub{})
	server := httptest.NewServer(proxy.HTTPHandler())
	defer server.Close()

	response, err := bearerClient(token, "").Post(server.URL, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusUnauthorized)
	}
}

type upstreamStub struct{}

func (upstreamStub) CallTool(context.Context, *mcp.CallToolParams) (*mcp.CallToolResult, error) {
	return nil, nil
}

func TestToolPolicyRejectsInvalidArguments(t *testing.T) {
	policy := ToolPolicy{
		GatewayTool:  "chat.post_message",
		UpstreamTool: "post_message",
		Server:       "team-chat",
		InputSchema:  requiredStringSchema("channel_id"),
		ExtractScope: RequiredStringScope(map[string]string{"channel_id": "channel_id"}),
	}
	_, err := policy.canonicalCall(map[string]any{"channel_id": ""})
	if err == nil {
		t.Fatal("empty protected argument was accepted")
	}
}

func TestBearerRoundTripperAddsAuthorization(t *testing.T) {
	var received string
	var receivedAgent string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		received = request.Header.Get("Authorization")
		receivedAgent = request.Header.Get("X-MCP-Agent-ID")
		_, _ = writer.Write([]byte("ok"))
	}))
	defer server.Close()

	response, err := bearerClient("token", "agent:triage").Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if received != "Bearer token" {
		t.Fatalf("authorization = %q", received)
	}
	if receivedAgent != "agent:triage" {
		t.Fatalf("agent identity = %q", receivedAgent)
	}
}

func TestFixtureReturnsJSONResult(t *testing.T) {
	fixture := &upstreamFixture{}
	upstreamMCP := fixture.server()
	server := httptest.NewServer(fixture.streamableHandler(upstreamMCP))
	defer server.Close()

	client := connectClient(t, context.Background(), server.URL, http.DefaultClient)
	defer client.Close()
	result, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "get_issue",
		Arguments: map[string]any{"issue_id": "APOLLO-17"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError || resultText(result) != "upstream called" {
		body, _ := json.Marshal(result)
		t.Fatalf("result = %s", body)
	}
}
