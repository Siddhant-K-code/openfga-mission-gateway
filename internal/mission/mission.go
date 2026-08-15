// Package mission implements a reference Mission control plane and gateway.
package mission

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type MissionState string

const (
	MissionDraft     MissionState = "draft"
	MissionActive    MissionState = "active"
	MissionRevoked   MissionState = "revoked"
	MissionCompleted MissionState = "completed"
)

type TupleKey struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

type CheckRequest struct {
	User             string
	Relation         string
	Object           string
	ContextualTuples []TupleKey
}

type FGAStore interface {
	Check(ctx context.Context, request CheckRequest) (bool, error)
	Write(ctx context.Context, tuples []TupleKey) error
	Delete(ctx context.Context, tuples []TupleKey) error
}

// InMemoryFGA evaluates the model in model.fga for contract tests. It is not
// a general OpenFGA implementation.
type InMemoryFGA struct {
	mu     sync.RWMutex
	tuples map[TupleKey]struct{}
}

func NewInMemoryFGA(tuples []TupleKey) *InMemoryFGA {
	store := &InMemoryFGA{tuples: make(map[TupleKey]struct{}, len(tuples))}
	for _, tuple := range tuples {
		store.tuples[tuple] = struct{}{}
	}
	return store
}

func (store *InMemoryFGA) Check(
	ctx context.Context,
	request CheckRequest,
) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	store.mu.RLock()
	tuples := make(map[TupleKey]struct{}, len(store.tuples)+len(request.ContextualTuples))
	for tuple := range store.tuples {
		tuples[tuple] = struct{}{}
	}
	store.mu.RUnlock()

	for _, tuple := range request.ContextualTuples {
		tuples[tuple] = struct{}{}
	}

	switch {
	case strings.HasPrefix(request.Object, "mcp_server:"):
		return checkServer(tuples, request.User, request.Relation, request.Object), nil
	case strings.HasPrefix(request.Object, "mcp_tool:"):
		return checkTool(tuples, request.User, request.Relation, request.Object), nil
	case strings.HasPrefix(request.Object, "mcp_call:"):
		return checkCall(tuples, request.User, request.Relation, request.Object), nil
	case strings.HasPrefix(request.Object, "tracker_project:"):
		return checkTrackerProject(tuples, request.User, request.Relation, request.Object), nil
	case strings.HasPrefix(request.Object, "tracker_ticket:"):
		return checkTrackerTicket(tuples, request.User, request.Relation, request.Object), nil
	case strings.HasPrefix(request.Object, "mission:"):
		return checkMission(tuples, request.User, request.Relation, request.Object), nil
	default:
		return false, fmt.Errorf(
			"unsupported FGA check: %s %s %s",
			request.User,
			request.Relation,
			request.Object,
		)
	}
}

func (store *InMemoryFGA) Write(ctx context.Context, tuples []TupleKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	for _, tuple := range tuples {
		store.tuples[tuple] = struct{}{}
	}
	return nil
}

func (store *InMemoryFGA) Delete(ctx context.Context, tuples []TupleKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	for _, tuple := range tuples {
		delete(store.tuples, tuple)
	}
	return nil
}

func checkServer(
	tuples map[TupleKey]struct{},
	user, relation, server string,
) bool {
	return relation == "operator" && hasTuple(tuples, user, relation, server)
}

func checkTool(
	tuples map[TupleKey]struct{},
	user, relation, tool string,
) bool {
	switch relation {
	case "server":
		return hasTuple(tuples, user, relation, tool)
	case "invoker":
		if hasTuple(tuples, user, relation, tool) {
			return true
		}
		for tuple := range tuples {
			if tuple.Relation == "server" && tuple.Object == tool &&
				checkServer(tuples, user, "operator", tuple.User) {
				return true
			}
		}
		return false
	case "can_invoke":
		return checkTool(tuples, user, "invoker", tool)
	default:
		return false
	}
}

func checkCall(
	tuples map[TupleKey]struct{},
	user, relation, call string,
) bool {
	switch relation {
	case "tool":
		return hasTuple(tuples, user, relation, call)
	case "invoker":
		if hasTuple(tuples, user, relation, call) {
			return true
		}
		for tuple := range tuples {
			if tuple.Relation == "tool" && tuple.Object == call &&
				checkTool(tuples, user, "can_invoke", tuple.User) {
				return true
			}
		}
		return false
	case "can_invoke":
		return checkCall(tuples, user, "invoker", call)
	default:
		return false
	}
}

func checkTrackerProject(
	tuples map[TupleKey]struct{},
	user, relation, project string,
) bool {
	switch relation {
	case "member":
		return hasTuple(tuples, user, relation, project)
	case "viewer", "can_read":
		return checkTrackerProject(tuples, user, "member", project)
	default:
		return false
	}
}

func checkTrackerTicket(
	tuples map[TupleKey]struct{},
	user, relation, ticket string,
) bool {
	switch relation {
	case "project":
		return hasTuple(tuples, user, relation, ticket)
	case "viewer":
		if hasTuple(tuples, user, relation, ticket) {
			return true
		}
		for tuple := range tuples {
			if tuple.Relation == "project" && tuple.Object == ticket &&
				checkTrackerProject(tuples, user, "viewer", tuple.User) {
				return true
			}
		}
		return false
	case "can_read":
		return checkTrackerTicket(tuples, user, "viewer", ticket)
	default:
		return false
	}
}

func checkMission(
	tuples map[TupleKey]struct{},
	user, relation, mission string,
) bool {
	switch relation {
	case "requester", "executor", "allowed_call":
		return hasTuple(tuples, user, relation, mission)
	default:
		return false
	}
}

func hasTuple(
	tuples map[TupleKey]struct{},
	user, relation, object string,
) bool {
	_, exists := tuples[TupleKey{User: user, Relation: relation, Object: object}]
	return exists
}

type tupleSet struct {
	TupleKeys []TupleKey `json:"tuple_keys"`
}

// OpenFGAHTTP is a small adapter for OpenFGA Check and Write APIs.
type OpenFGAHTTP struct {
	APIURL               string
	StoreID              string
	AuthorizationModelID string
	Client               *http.Client
}

func (client *OpenFGAHTTP) Check(
	ctx context.Context,
	request CheckRequest,
) (bool, error) {
	body := struct {
		TupleKey             TupleKey  `json:"tuple_key"`
		ContextualTuples     *tupleSet `json:"contextual_tuples,omitempty"`
		AuthorizationModelID string    `json:"authorization_model_id,omitempty"`
	}{
		TupleKey:             TupleKey{User: request.User, Relation: request.Relation, Object: request.Object},
		AuthorizationModelID: client.AuthorizationModelID,
	}
	if len(request.ContextualTuples) > 0 {
		body.ContextualTuples = &tupleSet{TupleKeys: request.ContextualTuples}
	}

	var response struct {
		Allowed bool `json:"allowed"`
	}
	if err := client.do(ctx, "check", body, &response); err != nil {
		return false, err
	}
	return response.Allowed, nil
}

func (client *OpenFGAHTTP) Write(ctx context.Context, tuples []TupleKey) error {
	return client.writeOrDelete(ctx, "writes", tuples)
}

func (client *OpenFGAHTTP) Delete(ctx context.Context, tuples []TupleKey) error {
	return client.writeOrDelete(ctx, "deletes", tuples)
}

func (client *OpenFGAHTTP) writeOrDelete(
	ctx context.Context,
	field string,
	tuples []TupleKey,
) error {
	body := struct {
		Writes               *tupleSet `json:"writes,omitempty"`
		Deletes              *tupleSet `json:"deletes,omitempty"`
		AuthorizationModelID string    `json:"authorization_model_id,omitempty"`
	}{
		AuthorizationModelID: client.AuthorizationModelID,
	}
	if field == "writes" {
		body.Writes = &tupleSet{TupleKeys: tuples}
	} else {
		body.Deletes = &tupleSet{TupleKeys: tuples}
	}
	return client.do(ctx, "write", body, nil)
}

func (client *OpenFGAHTTP) do(
	ctx context.Context,
	path string,
	body, response any,
) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode OpenFGA request: %w", err)
	}

	httpClient := client.Client
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		strings.TrimRight(client.APIURL, "/")+"/stores/"+client.StoreID+"/"+path,
		bytes.NewReader(payload),
	)
	if err != nil {
		return fmt.Errorf("create OpenFGA request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")

	httpResponse, err := httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("call OpenFGA: %w", err)
	}
	defer httpResponse.Body.Close()

	responseBody, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return fmt.Errorf("read OpenFGA response: %w", err)
	}
	if httpResponse.StatusCode < http.StatusOK || httpResponse.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("OpenFGA %s failed: %s", path, responseBody)
	}
	if response == nil || len(responseBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(responseBody, response); err != nil {
		return fmt.Errorf("decode OpenFGA response: %w", err)
	}
	return nil
}

// MCPCall is the policy-relevant shape of a tool invocation. Scope must
// contain only normalized fields that affect authorization.
type MCPCall struct {
	Server       string                `json:"server"`
	Tool         string                `json:"tool"`
	Scope        map[string]string     `json:"scope,omitempty"`
	Requirements []ResourceRequirement `json:"requirements,omitempty"`
}

type scopeEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ResourceRequirement is a connector-derived OpenFGA check for a concrete
// resource affected by an MCP call. It is part of a call's canonical identity.
type ResourceRequirement struct {
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

func (call MCPCall) ServerID() (string, error) {
	if err := call.validateIdentity(); err != nil {
		return "", err
	}
	return canonicalObjectID("mcp_server", struct {
		Server string `json:"server"`
	}{Server: call.Server})
}

func (call MCPCall) ToolID() (string, error) {
	if err := call.validateIdentity(); err != nil {
		return "", err
	}
	return canonicalObjectID("mcp_tool", struct {
		Server string `json:"server"`
		Tool   string `json:"tool"`
	}{Server: call.Server, Tool: call.Tool})
}

func (call MCPCall) ID() (string, error) {
	if err := call.validate(); err != nil {
		return "", err
	}
	return canonicalObjectID("mcp_call", struct {
		Server       string                `json:"server"`
		Tool         string                `json:"tool"`
		Scope        []scopeEntry          `json:"scope"`
		Requirements []ResourceRequirement `json:"requirements"`
	}{
		Server:       call.Server,
		Tool:         call.Tool,
		Scope:        call.canonicalScope(),
		Requirements: call.canonicalRequirements(),
	})
}

func (call MCPCall) validateIdentity() error {
	if strings.TrimSpace(call.Server) == "" {
		return fmt.Errorf("MCP server is required")
	}
	if strings.TrimSpace(call.Tool) == "" {
		return fmt.Errorf("MCP tool is required")
	}
	return nil
}

func (call MCPCall) validate() error {
	if err := call.validateIdentity(); err != nil {
		return err
	}
	for key := range call.Scope {
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("MCP call scope keys cannot be empty")
		}
	}
	seenRequirements := make(map[ResourceRequirement]struct{}, len(call.Requirements))
	for _, requirement := range call.Requirements {
		if strings.TrimSpace(requirement.Relation) == "" || strings.TrimSpace(requirement.Object) == "" {
			return fmt.Errorf("MCP call resource requirements need a relation and object")
		}
		if _, exists := seenRequirements[requirement]; exists {
			return fmt.Errorf("MCP call resource requirements cannot be duplicated")
		}
		seenRequirements[requirement] = struct{}{}
	}
	return nil
}

func (call MCPCall) canonicalScope() []scopeEntry {
	entries := make([]scopeEntry, 0, len(call.Scope))
	for key, value := range call.Scope {
		entries = append(entries, scopeEntry{Key: key, Value: value})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Key < entries[j].Key
	})
	return entries
}

func (call MCPCall) canonicalRequirements() []ResourceRequirement {
	requirements := append([]ResourceRequirement(nil), call.Requirements...)
	sort.Slice(requirements, func(i, j int) bool {
		if requirements[i].Object == requirements[j].Object {
			return requirements[i].Relation < requirements[j].Relation
		}
		return requirements[i].Object < requirements[j].Object
	})
	return requirements
}

func canonicalObjectID(prefix string, value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode canonical object: %w", err)
	}
	sum := sha256.Sum256(payload)
	return prefix + ":" + hex.EncodeToString(sum[:]), nil
}

type CallGrant struct {
	Call             MCPCall   `json:"call"`
	Risk             RiskLevel `json:"risk,omitempty"`
	RequiresApproval bool      `json:"requires_approval"`
}

type IntentProposal struct {
	UserPrompt string      `json:"user_prompt"`
	Rationale  string      `json:"rationale,omitempty"`
	Grants     []CallGrant `json:"grants"`
}

type MissionGrant struct {
	CallID           string    `json:"call_id"`
	Risk             RiskLevel `json:"risk,omitempty"`
	RequiresApproval bool      `json:"requires_approval"`
}

type Mission struct {
	ID               string
	Requester        string
	Agent            string
	Intent           IntentProposal
	ExpiresAt        time.Time
	Grants           []MissionGrant
	State            MissionState
	Version          int
	MaxDispatches    int
	DispatchCount    int
	ApprovalPreviews map[string]string
	ApprovedCalls    map[string]bool
}

func (mission *Mission) Grant(callID string) (MissionGrant, bool) {
	for _, grant := range mission.Grants {
		if grant.CallID == callID {
			return grant, true
		}
	}
	return MissionGrant{}, false
}

func (mission *Mission) CallIDs() []string {
	callIDs := make([]string, 0, len(mission.Grants))
	for _, grant := range mission.Grants {
		callIDs = append(callIDs, grant.CallID)
	}
	return callIDs
}

type MissionTokenSigner struct {
	secret []byte
}

type MissionTokenClaims struct {
	MissionID string   `json:"mission_id"`
	Agent     string   `json:"agent"`
	Version   int      `json:"version"`
	ExpiresAt int64    `json:"expires_at"`
	CallIDs   []string `json:"call_ids"`
}

func NewMissionTokenSigner(secret []byte) (*MissionTokenSigner, error) {
	if len(secret) < 16 {
		return nil, fmt.Errorf("Mission token secret must be at least 16 bytes")
	}
	return &MissionTokenSigner{secret: append([]byte(nil), secret...)}, nil
}

func NewRandomMissionTokenSigner() (*MissionTokenSigner, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate Mission token secret: %w", err)
	}
	return NewMissionTokenSigner(secret)
}

func (signer *MissionTokenSigner) Issue(mission *Mission) (string, error) {
	claims := MissionTokenClaims{
		MissionID: mission.ID,
		Agent:     mission.Agent,
		Version:   mission.Version,
		ExpiresAt: mission.ExpiresAt.Unix(),
		CallIDs:   mission.CallIDs(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encode Mission token: %w", err)
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signature := signer.sign(encodedPayload)
	return encodedPayload + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (signer *MissionTokenSigner) Verify(
	token string,
	now time.Time,
) (MissionTokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return MissionTokenClaims{}, fmt.Errorf("invalid Mission token format")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return MissionTokenClaims{}, fmt.Errorf("invalid Mission token signature")
	}
	if !hmac.Equal(signer.sign(parts[0]), signature) {
		return MissionTokenClaims{}, fmt.Errorf("invalid Mission token signature")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return MissionTokenClaims{}, fmt.Errorf("invalid Mission token payload")
	}
	var claims MissionTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return MissionTokenClaims{}, fmt.Errorf("invalid Mission token payload")
	}
	if claims.MissionID == "" || claims.Agent == "" || claims.Version < 1 || len(claims.CallIDs) == 0 {
		return MissionTokenClaims{}, fmt.Errorf("invalid Mission token claims")
	}
	if claims.ExpiresAt <= now.Unix() {
		return MissionTokenClaims{}, fmt.Errorf("Mission token expired")
	}
	return claims, nil
}

func (signer *MissionTokenSigner) sign(payload string) []byte {
	mac := hmac.New(sha256.New, signer.secret)
	_, _ = mac.Write([]byte(payload))
	return mac.Sum(nil)
}

// FilterAuthorizedCandidates removes resolved calls the requester cannot
// currently invoke. It does not resolve natural-language tool arguments.
func FilterAuthorizedCandidates(
	ctx context.Context,
	fga FGAStore,
	requester string,
	candidates []MCPCall,
) ([]MCPCall, error) {
	allowed := make([]MCPCall, 0, len(candidates))
	for _, candidate := range candidates {
		canInvoke, err := CanInvokeCall(ctx, fga, requester, candidate)
		if err != nil {
			return nil, err
		}
		if canInvoke {
			allowed = append(allowed, candidate)
		}
	}
	return allowed, nil
}

// CanInvokeCall checks both the generic MCP tool authority and every concrete
// resource requirement derived by the connector.
func CanInvokeCall(
	ctx context.Context,
	fga FGAStore,
	principal string,
	call MCPCall,
) (bool, error) {
	callID, err := call.ID()
	if err != nil {
		return false, err
	}
	topology, err := callTopologyTuples(call)
	if err != nil {
		return false, err
	}
	canInvoke, err := fga.Check(ctx, CheckRequest{
		User: principal, Relation: "can_invoke", Object: callID, ContextualTuples: topology,
	})
	if err != nil || !canInvoke {
		return canInvoke, err
	}
	for _, requirement := range call.canonicalRequirements() {
		allowed, err := fga.Check(ctx, CheckRequest{
			User:     principal,
			Relation: requirement.Relation,
			Object:   requirement.Object,
		})
		if err != nil || !allowed {
			return allowed, err
		}
	}
	return true, nil
}

// callTopologyTuples derives the final tool-to-call edge from a connector's
// trusted canonicalization. It avoids persisting one graph tuple for every
// scoped resource call.
func callTopologyTuples(call MCPCall) ([]TupleKey, error) {
	toolID, err := call.ToolID()
	if err != nil {
		return nil, err
	}
	callID, err := call.ID()
	if err != nil {
		return nil, err
	}
	return []TupleKey{{User: toolID, Relation: "tool", Object: callID}}, nil
}

type MissionService struct {
	fga       FGAStore
	signer    *MissionTokenSigner
	mu        sync.RWMutex
	missions  map[string]*Mission
	timelines map[string][]TimelineEvent
	nextEvent int
}

type CreateMissionInput struct {
	MissionID     string
	Requester     string
	Agent         string
	Intent        IntentProposal
	ExpiresAt     time.Time
	MaxDispatches int
}

func NewMissionService(fga FGAStore, signer *MissionTokenSigner) *MissionService {
	return &MissionService{
		fga:       fga,
		signer:    signer,
		missions:  make(map[string]*Mission),
		timelines: make(map[string][]TimelineEvent),
	}
}

func (service *MissionService) CreateDraft(
	input CreateMissionInput,
) (*Mission, error) {
	if input.MissionID == "" {
		return nil, fmt.Errorf("Mission ID is required")
	}
	if input.Requester == "" || input.Agent == "" {
		return nil, fmt.Errorf("requester and agent are required")
	}
	if !input.ExpiresAt.After(time.Now()) {
		return nil, fmt.Errorf("Mission expiry must be in the future")
	}
	if input.MaxDispatches < 0 {
		return nil, fmt.Errorf("Mission dispatch budget cannot be negative")
	}

	grants, err := normalizeGrants(input.Intent.Grants)
	if err != nil {
		return nil, err
	}

	service.mu.Lock()
	defer service.mu.Unlock()
	if _, exists := service.missions[input.MissionID]; exists {
		return nil, fmt.Errorf("Mission %s already exists", input.MissionID)
	}
	mission := &Mission{
		ID:               input.MissionID,
		Requester:        input.Requester,
		Agent:            input.Agent,
		Intent:           cloneIntent(input.Intent),
		ExpiresAt:        input.ExpiresAt.UTC(),
		Grants:           grants,
		State:            MissionDraft,
		Version:          1,
		MaxDispatches:    input.MaxDispatches,
		ApprovalPreviews: make(map[string]string),
		ApprovedCalls:    make(map[string]bool),
	}
	service.missions[mission.ID] = mission
	service.recordEventLocked(mission, TimelineProposed, input.Requester, "Mission proposed", "", nil)
	return cloneMission(mission), nil
}

func normalizeGrants(input []CallGrant) ([]MissionGrant, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("a Mission needs at least one scoped call")
	}

	byCallID := make(map[string]MissionGrant, len(input))
	for _, inputGrant := range input {
		callID, err := inputGrant.Call.ID()
		if err != nil {
			return nil, err
		}
		grant := MissionGrant{
			CallID:           callID,
			Risk:             inputGrant.Risk,
			RequiresApproval: inputGrant.RequiresApproval,
		}
		if existing, exists := byCallID[callID]; exists && existing != grant {
			return nil, fmt.Errorf("duplicate call grants must have the same approval policy")
		}
		byCallID[callID] = grant
	}

	grants := make([]MissionGrant, 0, len(byCallID))
	for _, grant := range byCallID {
		grants = append(grants, grant)
	}
	sort.Slice(grants, func(i, j int) bool {
		return grants[i].CallID < grants[j].CallID
	})
	return grants, nil
}

func (service *MissionService) Approve(
	ctx context.Context,
	missionID, actor string,
	now time.Time,
) (string, error) {
	service.mu.Lock()
	defer service.mu.Unlock()

	mission, err := service.getLocked(missionID)
	if err != nil {
		return "", err
	}
	if actor != mission.Requester {
		return "", fmt.Errorf("only the Mission requester may approve it")
	}
	if mission.State != MissionDraft {
		return "", fmt.Errorf("only a draft Mission may be approved")
	}
	if !mission.ExpiresAt.After(now) {
		return "", fmt.Errorf("cannot approve an expired Mission")
	}
	if err := service.validateCurrentAuthority(ctx, mission); err != nil {
		return "", err
	}

	mission.State = MissionActive
	service.recordEventLocked(mission, TimelineActivated, actor, "Mission approved and token issued", "", nil)
	return service.signer.Issue(mission)
}

func (service *MissionService) RequestApproval(
	missionID, callID, preview string,
) error {
	service.mu.Lock()
	defer service.mu.Unlock()

	mission, err := service.getLocked(missionID)
	if err != nil {
		return err
	}
	if mission.State != MissionActive {
		return fmt.Errorf("only an active Mission may request approval")
	}
	grant, exists := mission.Grant(callID)
	if !exists || !grant.RequiresApproval {
		return fmt.Errorf("this call does not require approval")
	}
	if strings.TrimSpace(preview) == "" {
		return fmt.Errorf("approval preview cannot be empty")
	}

	mission.ApprovalPreviews[callID] = preview
	mission.ApprovedCalls[callID] = false
	service.recordEventLocked(mission, TimelineApprovalRequested, mission.Agent, "Approval requested for side effect", callID, nil)
	return nil
}

func (service *MissionService) ApproveCall(
	missionID, callID, actor string,
) error {
	service.mu.Lock()
	defer service.mu.Unlock()

	mission, err := service.getLocked(missionID)
	if err != nil {
		return err
	}
	if actor != mission.Requester {
		return fmt.Errorf("only the Mission requester may approve a call")
	}
	if mission.ApprovalPreviews[callID] == "" {
		return fmt.Errorf("call approval requires a preview")
	}
	mission.ApprovedCalls[callID] = true
	service.recordEventLocked(mission, TimelineApprovalGranted, actor, "Side effect approved", callID, nil)
	return nil
}

func (service *MissionService) Revoke(missionID string) error {
	service.mu.Lock()
	defer service.mu.Unlock()

	mission, err := service.getLocked(missionID)
	if err != nil {
		return err
	}
	if mission.State != MissionActive {
		return fmt.Errorf("only an active Mission may be revoked")
	}
	mission.State = MissionRevoked
	service.recordEventLocked(mission, TimelineRevoked, mission.Requester, "Mission revoked", "", nil)
	return nil
}

func (service *MissionService) Complete(missionID string) error {
	service.mu.Lock()
	defer service.mu.Unlock()

	mission, err := service.getLocked(missionID)
	if err != nil {
		return err
	}
	if mission.State != MissionActive {
		return fmt.Errorf("only an active Mission may be completed")
	}
	mission.State = MissionCompleted
	service.recordEventLocked(mission, TimelineCompleted, mission.Requester, "Mission completed", "", nil)
	return nil
}

// ReserveDispatch atomically applies the Mission-local controls immediately
// before a gateway forwards an allowed call. It counts authorization attempts;
// the upstream side effect remains outside this transaction boundary.
func (service *MissionService) ReserveDispatch(
	missionID string,
	version int,
	callID string,
	now time.Time,
) (string, error) {
	service.mu.Lock()
	defer service.mu.Unlock()

	mission, err := service.getLocked(missionID)
	if err != nil {
		return "unknown Mission", err
	}
	if mission.Version != version {
		return "Mission token is stale", nil
	}
	if mission.State != MissionActive {
		return "Mission is " + string(mission.State), nil
	}
	if !mission.ExpiresAt.After(now) {
		return "Mission expired", nil
	}
	grant, exists := mission.Grant(callID)
	if !exists {
		return "denied by mission_call_scope", nil
	}
	if grant.RequiresApproval && !mission.ApprovedCalls[callID] {
		return "call approval is required", nil
	}
	if mission.MaxDispatches > 0 && mission.DispatchCount >= mission.MaxDispatches {
		return "Mission dispatch budget exhausted", nil
	}
	mission.DispatchCount++
	return "", nil
}

func (service *MissionService) Get(missionID string) (*Mission, error) {
	service.mu.RLock()
	defer service.mu.RUnlock()

	mission, err := service.getLocked(missionID)
	if err != nil {
		return nil, err
	}
	return cloneMission(mission), nil
}

func (service *MissionService) getLocked(missionID string) (*Mission, error) {
	mission, exists := service.missions[missionID]
	if !exists {
		return nil, fmt.Errorf("unknown Mission %s", missionID)
	}
	return mission, nil
}

func (service *MissionService) validateCurrentAuthority(
	ctx context.Context,
	mission *Mission,
) error {
	for _, grant := range mission.Intent.Grants {
		callID, err := grant.Call.ID()
		if err != nil {
			return err
		}
		for _, principal := range []struct {
			name string
			id   string
		}{
			{name: "requester", id: mission.Requester},
			{name: "agent", id: mission.Agent},
		} {
			allowed, err := CanInvokeCall(ctx, service.fga, principal.id, grant.Call)
			if err != nil {
				return err
			}
			if !allowed {
				return fmt.Errorf(
					"%s %s cannot invoke %s; Mission cannot delegate it",
					principal.name,
					principal.id,
					callID,
				)
			}
		}
	}
	return nil
}

func cloneMission(mission *Mission) *Mission {
	copy := *mission
	copy.Intent = cloneIntent(mission.Intent)
	copy.Grants = append([]MissionGrant(nil), mission.Grants...)
	copy.ApprovalPreviews = make(map[string]string, len(mission.ApprovalPreviews))
	for callID, preview := range mission.ApprovalPreviews {
		copy.ApprovalPreviews[callID] = preview
	}
	copy.ApprovedCalls = make(map[string]bool, len(mission.ApprovedCalls))
	for callID, approved := range mission.ApprovedCalls {
		copy.ApprovedCalls[callID] = approved
	}
	return &copy
}

func cloneIntent(intent IntentProposal) IntentProposal {
	copy := intent
	copy.Grants = append([]CallGrant(nil), intent.Grants...)
	for index, grant := range copy.Grants {
		calls := cloneCalls([]MCPCall{grant.Call})
		copy.Grants[index].Call = calls[0]
	}
	return copy
}

type CheckResult struct {
	Name     string `json:"name"`
	Allowed  bool   `json:"allowed"`
	Relation string `json:"relation,omitempty"`
	Object   string `json:"object,omitempty"`
}

type Decision struct {
	Allowed        bool          `json:"allowed"`
	Reason         string        `json:"reason"`
	MissionID      string        `json:"mission_id,omitempty"`
	MissionVersion int           `json:"mission_version,omitempty"`
	Agent          string        `json:"agent,omitempty"`
	Call           *MCPCall      `json:"call,omitempty"`
	Checks         []CheckResult `json:"checks"`
	Timestamp      time.Time     `json:"timestamp"`
}

type Gateway struct {
	fga      FGAStore
	missions *MissionService
	signer   *MissionTokenSigner
	mu       sync.RWMutex
	auditLog []Decision
}

type AuthorizationRequest struct {
	MissionToken string
	Agent        string
	Call         MCPCall
}

func NewGateway(
	fga FGAStore,
	missions *MissionService,
	signer *MissionTokenSigner,
) *Gateway {
	return &Gateway{fga: fga, missions: missions, signer: signer}
}

func (gateway *Gateway) Authorize(
	ctx context.Context,
	request AuthorizationRequest,
	now time.Time,
) Decision {
	claims, err := gateway.signer.Verify(request.MissionToken, now)
	if err != nil {
		return gateway.record(false, err.Error(), nil, nil, request, now)
	}
	mission, err := gateway.missions.Get(claims.MissionID)
	if err != nil {
		return gateway.record(false, err.Error(), nil, nil, request, now)
	}

	if claims.Agent != request.Agent || mission.Agent != request.Agent {
		return gateway.record(
			false,
			"Mission token is not bound to this agent",
			mission,
			[]CheckResult{{Name: "agent_binding", Allowed: false}},
			request,
			now,
		)
	}
	if claims.Version != mission.Version || !sameCallSet(claims.CallIDs, mission.CallIDs()) {
		return gateway.record(
			false,
			"Mission token is stale",
			mission,
			[]CheckResult{{Name: "mission_version", Allowed: false}},
			request,
			now,
		)
	}
	if mission.State != MissionActive {
		return gateway.record(
			false,
			"Mission is "+string(mission.State),
			mission,
			[]CheckResult{{Name: "mission_active", Allowed: false}},
			request,
			now,
		)
	}
	if !mission.ExpiresAt.After(now) {
		return gateway.record(
			false,
			"Mission expired",
			mission,
			[]CheckResult{{Name: "mission_expiry", Allowed: false}},
			request,
			now,
		)
	}

	callID, err := request.Call.ID()
	if err != nil {
		return gateway.record(false, err.Error(), mission, nil, request, now)
	}
	contextualTuples := missionContextualTuples(mission, claims)
	topology, err := callTopologyTuples(request.Call)
	if err != nil {
		return gateway.record(false, err.Error(), mission, nil, request, now)
	}
	contextualTuples = append(contextualTuples, topology...)

	baseAccess, err := gateway.fga.Check(ctx, CheckRequest{
		User:             mission.Requester,
		Relation:         "can_invoke",
		Object:           callID,
		ContextualTuples: contextualTuples,
	})
	if err != nil {
		return gateway.record(false, "authorization check failed", mission, nil, request, now)
	}
	agentAccess, err := gateway.fga.Check(ctx, CheckRequest{
		User:             request.Agent,
		Relation:         "can_invoke",
		Object:           callID,
		ContextualTuples: contextualTuples,
	})
	if err != nil {
		return gateway.record(false, "authorization check failed", mission, nil, request, now)
	}
	agentBound, err := gateway.fga.Check(ctx, CheckRequest{
		User:             request.Agent,
		Relation:         "executor",
		Object:           "mission:" + mission.ID,
		ContextualTuples: contextualTuples,
	})
	if err != nil {
		return gateway.record(false, "authorization check failed", mission, nil, request, now)
	}
	missionScope, err := gateway.fga.Check(ctx, CheckRequest{
		User:             callID,
		Relation:         "allowed_call",
		Object:           "mission:" + mission.ID,
		ContextualTuples: contextualTuples,
	})
	if err != nil {
		return gateway.record(false, "authorization check failed", mission, nil, request, now)
	}

	checks := []CheckResult{
		{Name: "requester_base_access", Allowed: baseAccess},
		{Name: "agent_base_access", Allowed: agentAccess},
		{Name: "agent_bound_to_mission", Allowed: agentBound},
		{Name: "mission_call_scope", Allowed: missionScope},
	}
	for _, requirement := range request.Call.canonicalRequirements() {
		requesterResourceAccess, err := gateway.fga.Check(ctx, CheckRequest{
			User: mission.Requester, Relation: requirement.Relation, Object: requirement.Object,
		})
		if err != nil {
			return gateway.record(false, "authorization check failed", mission, nil, request, now)
		}
		agentResourceAccess, err := gateway.fga.Check(ctx, CheckRequest{
			User: request.Agent, Relation: requirement.Relation, Object: requirement.Object,
		})
		if err != nil {
			return gateway.record(false, "authorization check failed", mission, nil, request, now)
		}
		checks = append(checks,
			CheckResult{
				Name: "requester_resource_access", Allowed: requesterResourceAccess,
				Relation: requirement.Relation, Object: requirement.Object,
			},
			CheckResult{
				Name: "agent_resource_access", Allowed: agentResourceAccess,
				Relation: requirement.Relation, Object: requirement.Object,
			},
		)
	}
	for _, check := range checks {
		if !check.Allowed {
			return gateway.record(
				false,
				"denied by "+check.Name,
				mission,
				checks,
				request,
				now,
			)
		}
	}

	grant, _ := mission.Grant(callID)
	if grant.RequiresApproval {
		approval := CheckResult{
			Name: "call_approved", Allowed: mission.ApprovedCalls[callID],
		}
		checks = append(checks, approval)
		if !approval.Allowed {
			return gateway.record(
				false,
				"call approval is required",
				mission,
				checks,
				request,
				now,
			)
		}
	}

	reserveReason, err := gateway.missions.ReserveDispatch(mission.ID, claims.Version, callID, now)
	if err != nil {
		return gateway.record(false, "authorization check failed", mission, checks, request, now)
	}
	if reserveReason != "" {
		checks = append(checks, CheckResult{Name: "mission_dispatch_control", Allowed: false})
		return gateway.record(false, reserveReason, mission, checks, request, now)
	}
	if mission.MaxDispatches > 0 {
		checks = append(checks, CheckResult{Name: "mission_dispatch_budget", Allowed: true})
	}

	return gateway.record(true, "authorized", mission, checks, request, now)
}

func missionContextualTuples(
	mission *Mission,
	claims MissionTokenClaims,
) []TupleKey {
	context := make([]TupleKey, 0, len(claims.CallIDs)+2)
	missionObject := "mission:" + mission.ID
	context = append(context,
		TupleKey{User: mission.Requester, Relation: "requester", Object: missionObject},
		TupleKey{User: claims.Agent, Relation: "executor", Object: missionObject},
	)
	for _, callID := range claims.CallIDs {
		context = append(context, TupleKey{
			User: callID, Relation: "allowed_call", Object: missionObject,
		})
	}
	return context
}

func sameCallSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftSet := make(map[string]struct{}, len(left))
	for _, callID := range left {
		leftSet[callID] = struct{}{}
	}
	if len(leftSet) != len(left) {
		return false
	}
	for _, callID := range right {
		if _, exists := leftSet[callID]; !exists {
			return false
		}
	}
	return true
}

func (gateway *Gateway) AuditLog() []Decision {
	gateway.mu.RLock()
	defer gateway.mu.RUnlock()
	return append([]Decision(nil), gateway.auditLog...)
}

func (gateway *Gateway) record(
	allowed bool,
	reason string,
	mission *Mission,
	checks []CheckResult,
	request AuthorizationRequest,
	now time.Time,
) Decision {
	decision := Decision{
		Allowed:   allowed,
		Reason:    reason,
		Agent:     request.Agent,
		Checks:    append([]CheckResult(nil), checks...),
		Timestamp: now.UTC(),
	}
	if request.Call.Server != "" || request.Call.Tool != "" {
		call := cloneCalls([]MCPCall{request.Call})[0]
		decision.Call = &call
	}
	if mission != nil {
		decision.MissionID = mission.ID
		decision.MissionVersion = mission.Version
	}

	gateway.mu.Lock()
	gateway.auditLog = append(gateway.auditLog, decision)
	gateway.mu.Unlock()
	gateway.missions.recordDecision(decision)
	return decision
}

type DemoCalls struct {
	ReadIssue       MCPCall
	Inaccessible    MCPCall
	PostSummary     MCPCall
	PostOtherTarget MCPCall
}

// DemoEnvironment creates a generic multi-server MCP flow for the demo and
// contract tests.
func DemoEnvironment(
	ctx context.Context,
) (*InMemoryFGA, *MissionService, *Gateway, string, DemoCalls, error) {
	calls := DemoCalls{
		ReadIssue: MCPCall{
			Server: "work-tracker",
			Tool:   "get_issue",
			Scope:  map[string]string{"issue_id": "APOLLO-17"},
			Requirements: []ResourceRequirement{{
				Relation: "can_read",
				Object:   "tracker_ticket:APOLLO-17",
			}},
		},
		Inaccessible: MCPCall{
			Server: "work-tracker",
			Tool:   "get_issue",
			Scope:  map[string]string{"issue_id": "HERMES-1"},
			Requirements: []ResourceRequirement{{
				Relation: "can_read",
				Object:   "tracker_ticket:HERMES-1",
			}},
		},
		PostSummary: MCPCall{
			Server: "team-chat",
			Tool:   "post_message",
			Scope:  map[string]string{"channel_id": "product"},
		},
		PostOtherTarget: MCPCall{
			Server: "team-chat",
			Tool:   "post_message",
			Scope:  map[string]string{"channel_id": "company"},
		},
	}

	durableTuples, err := durableCallTuples([]MCPCall{
		calls.ReadIssue,
		calls.Inaccessible,
		calls.PostSummary,
		calls.PostOtherTarget,
	})
	if err != nil {
		return nil, nil, nil, "", DemoCalls{}, err
	}
	workTrackerID, err := calls.ReadIssue.ServerID()
	if err != nil {
		return nil, nil, nil, "", DemoCalls{}, err
	}
	teamChatID, err := calls.PostSummary.ServerID()
	if err != nil {
		return nil, nil, nil, "", DemoCalls{}, err
	}

	durableTuples = append(durableTuples,
		TupleKey{User: "user:alice", Relation: "operator", Object: workTrackerID},
		TupleKey{User: "user:alice", Relation: "operator", Object: teamChatID},
		TupleKey{User: "agent:triage", Relation: "operator", Object: workTrackerID},
		TupleKey{User: "agent:triage", Relation: "operator", Object: teamChatID},
		TupleKey{User: "tracker_project:apollo", Relation: "project", Object: "tracker_ticket:APOLLO-17"},
		TupleKey{User: "tracker_project:hermes", Relation: "project", Object: "tracker_ticket:HERMES-1"},
		TupleKey{User: "user:alice", Relation: "member", Object: "tracker_project:apollo"},
		TupleKey{User: "agent:triage", Relation: "member", Object: "tracker_project:apollo"},
	)
	fga := NewInMemoryFGA(durableTuples)

	signer, err := NewMissionTokenSigner([]byte("mission-v1-demo-secret-32-bytes!"))
	if err != nil {
		return nil, nil, nil, "", DemoCalls{}, err
	}
	missions := NewMissionService(fga, signer)
	_, err = missions.Propose(ctx,
		StaticIntentEvaluator{
			Calls:     []MCPCall{calls.ReadIssue, calls.PostSummary},
			Rationale: "Read the selected ticket and request approval before posting.",
		},
		ToolPolicyResolver{
			Rules: map[string]CallPolicy{
				"team-chat/post_message": {
					Risk:             RiskHigh,
					RequiresApproval: true,
				},
			},
			Default: CallPolicy{Risk: RiskLow},
		},
		ProposeMissionInput{
			MissionID:     "apollo-17-product-summary-v1",
			Requester:     "user:alice",
			Agent:         "agent:triage",
			Prompt:        "Read APOLLO-17 and post a summary to the product channel.",
			Candidates:    []MCPCall{calls.ReadIssue, calls.PostSummary},
			ExpiresAt:     time.Now().Add(time.Hour),
			MaxDispatches: 3,
		},
	)
	if err != nil {
		return nil, nil, nil, "", DemoCalls{}, err
	}
	token, err := missions.Approve(
		ctx,
		"apollo-17-product-summary-v1",
		"user:alice",
		time.Now(),
	)
	if err != nil {
		return nil, nil, nil, "", DemoCalls{}, err
	}
	return fga, missions, NewGateway(fga, missions, signer), token, calls, nil
}

func durableCallTuples(calls []MCPCall) ([]TupleKey, error) {
	tuples := make([]TupleKey, 0, len(calls))
	seen := make(map[TupleKey]struct{}, len(calls))
	for _, call := range calls {
		serverID, err := call.ServerID()
		if err != nil {
			return nil, err
		}
		toolID, err := call.ToolID()
		if err != nil {
			return nil, err
		}
		for _, tuple := range []TupleKey{{User: serverID, Relation: "server", Object: toolID}} {
			if _, exists := seen[tuple]; exists {
				continue
			}
			seen[tuple] = struct{}{}
			tuples = append(tuples, tuple)
		}
	}
	return tuples, nil
}
