// Package mcpproxy exposes a Mission gateway as an MCP server.
package mcpproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Siddhant-K-code/openfga-mission-gateway/internal/mission"
)

// Upstream is the minimum MCP client surface the proxy needs.
type Upstream interface {
	CallTool(context.Context, *mcp.CallToolParams) (*mcp.CallToolResult, error)
}

// AgentIdentityVerifier returns the authenticated workload identity for an
// inbound request. It must derive that identity independently of the Mission
// token, for example from verified mTLS, workload OIDC, or a trusted gateway.
type AgentIdentityVerifier func(*http.Request) (string, error)

// SessionUpstream forwards calls to a connected MCP client session.
type SessionUpstream struct {
	Session *mcp.ClientSession
}

func (upstream SessionUpstream) CallTool(
	ctx context.Context,
	params *mcp.CallToolParams,
) (*mcp.CallToolResult, error) {
	if upstream.Session == nil {
		return nil, fmt.Errorf("upstream MCP session is required")
	}
	return upstream.Session.CallTool(ctx, params)
}

// ScopeExtractor returns the policy-relevant subset of a tool's arguments.
// It must fail closed when it cannot derive a safe scope.
type ScopeExtractor func(arguments map[string]any) (map[string]string, error)

// RequiredStringScope builds an extractor for tools whose protected fields are
// required string arguments. The map key is the canonical scope key and its
// value is the MCP argument name.
func RequiredStringScope(fields map[string]string) ScopeExtractor {
	return func(arguments map[string]any) (map[string]string, error) {
		scope := make(map[string]string, len(fields))
		keys := make([]string, 0, len(fields))
		for scopeKey := range fields {
			keys = append(keys, scopeKey)
		}
		sort.Strings(keys)

		for _, scopeKey := range keys {
			argumentName := fields[scopeKey]
			value, exists := arguments[argumentName]
			stringValue, isString := value.(string)
			if !exists || !isString || strings.TrimSpace(stringValue) == "" {
				return nil, fmt.Errorf(
					"scope argument %q must be a non-empty string",
					argumentName,
				)
			}
			scope[scopeKey] = stringValue
		}
		return scope, nil
	}
}

type ToolPolicy struct {
	GatewayTool  string
	UpstreamTool string
	Server       string
	Description  string
	InputSchema  any
	ExtractScope ScopeExtractor
}

func (policy ToolPolicy) canonicalCall(arguments map[string]any) (mission.MCPCall, error) {
	if policy.ExtractScope == nil {
		return mission.MCPCall{}, fmt.Errorf("tool %q has no scope extractor", policy.GatewayTool)
	}
	scope, err := policy.ExtractScope(arguments)
	if err != nil {
		return mission.MCPCall{}, err
	}
	return mission.MCPCall{
		Server: policy.Server,
		Tool:   policy.UpstreamTool,
		Scope:  scope,
	}, nil
}

func (policy ToolPolicy) validate() error {
	if strings.TrimSpace(policy.GatewayTool) == "" {
		return fmt.Errorf("gateway tool is required")
	}
	if strings.TrimSpace(policy.UpstreamTool) == "" {
		return fmt.Errorf("upstream tool is required")
	}
	if strings.TrimSpace(policy.Server) == "" {
		return fmt.Errorf("MCP server is required")
	}
	if policy.InputSchema == nil {
		return fmt.Errorf("tool %q needs an input schema", policy.GatewayTool)
	}
	if policy.ExtractScope == nil {
		return fmt.Errorf("tool %q needs a scope extractor", policy.GatewayTool)
	}
	return nil
}

type Proxy struct {
	gateway       *mission.Gateway
	signer        *mission.MissionTokenSigner
	upstream      Upstream
	agentIdentity AgentIdentityVerifier
	server        *mcp.Server
}

func New(
	gateway *mission.Gateway,
	signer *mission.MissionTokenSigner,
	upstream Upstream,
	policies []ToolPolicy,
	agentIdentity AgentIdentityVerifier,
) (*Proxy, error) {
	if gateway == nil || signer == nil || upstream == nil {
		return nil, fmt.Errorf("gateway, signer, and upstream are required")
	}
	if agentIdentity == nil {
		return nil, fmt.Errorf("an independent agent identity verifier is required")
	}
	if len(policies) == 0 {
		return nil, fmt.Errorf("at least one tool policy is required")
	}

	proxy := &Proxy{
		gateway:       gateway,
		signer:        signer,
		upstream:      upstream,
		agentIdentity: agentIdentity,
		server: mcp.NewServer(&mcp.Implementation{
			Name:    "openfga-mission-gateway",
			Version: "v0.1.0",
		}, nil),
	}

	seen := make(map[string]struct{}, len(policies))
	for _, policy := range policies {
		if err := policy.validate(); err != nil {
			return nil, err
		}
		if _, exists := seen[policy.GatewayTool]; exists {
			return nil, fmt.Errorf("duplicate gateway tool %q", policy.GatewayTool)
		}
		seen[policy.GatewayTool] = struct{}{}

		policy := policy
		proxy.server.AddTool(&mcp.Tool{
			Name:        policy.GatewayTool,
			Description: policy.Description,
			InputSchema: policy.InputSchema,
		}, proxy.handleTool(policy))
	}
	return proxy, nil
}

// HTTPHandler serves a Streamable HTTP MCP endpoint protected by a Mission
// bearer token and an independent workload identity. The Mission token is
// consumed at this boundary and is never sent to the upstream MCP server.
func (proxy *Proxy) HTTPHandler() http.Handler {
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return proxy.server
	}, &mcp.StreamableHTTPOptions{JSONResponse: true})
	return auth.RequireBearerToken(proxy.verifyToken, nil)(handler)
}

func (proxy *Proxy) verifyToken(
	_ context.Context,
	token string,
	request *http.Request,
) (*auth.TokenInfo, error) {
	claims, err := proxy.signer.Verify(token, time.Now())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", auth.ErrInvalidToken, err)
	}
	agentID, err := proxy.agentIdentity(request)
	if err != nil {
		return nil, fmt.Errorf("%w: agent authentication failed: %v", auth.ErrInvalidToken, err)
	}
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return nil, fmt.Errorf("%w: agent authentication returned no identity", auth.ErrInvalidToken)
	}
	return &auth.TokenInfo{
		Expiration: time.Unix(claims.ExpiresAt, 0),
		UserID:     agentID,
		Extra: map[string]any{
			"mission_token": token,
		},
	}, nil
}

func (proxy *Proxy) handleTool(policy ToolPolicy) mcp.ToolHandler {
	return func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if request == nil || request.Params == nil || request.Extra == nil || request.Extra.TokenInfo == nil {
			return deniedResult("missing Mission bearer token"), nil
		}
		token, ok := request.Extra.TokenInfo.Extra["mission_token"].(string)
		if !ok || token == "" {
			return deniedResult("missing Mission bearer token"), nil
		}

		arguments := make(map[string]any)
		if len(request.Params.Arguments) > 0 {
			if err := json.Unmarshal(request.Params.Arguments, &arguments); err != nil {
				return deniedResult("tool arguments must be a JSON object"), nil
			}
		}
		call, err := policy.canonicalCall(arguments)
		if err != nil {
			return deniedResult(err.Error()), nil
		}

		decision := proxy.gateway.Authorize(ctx, mission.AuthorizationRequest{
			MissionToken: token,
			Agent:        request.Extra.TokenInfo.UserID,
			Call:         call,
		}, time.Now())
		if !decision.Allowed {
			return deniedResult(decision.Reason), nil
		}

		return proxy.upstream.CallTool(ctx, &mcp.CallToolParams{
			Name:           policy.UpstreamTool,
			Arguments:      arguments,
			InputResponses: request.Params.InputResponses,
			RequestState:   request.Params.RequestState,
		})
	}
}

func deniedResult(reason string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: "denied: " + reason}},
	}
}
