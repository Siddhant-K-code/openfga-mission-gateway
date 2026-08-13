// Package mission implements the reference Mission control plane and gateway.
package mission

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

type Action string

const (
	ReadJiraIssue    Action = "jira.issue.read"
	PostSlackMessage Action = "slack.message.post"
)

type TupleKey struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

type FGAStore interface {
	Check(ctx context.Context, user, relation, object string) (bool, error)
	Write(ctx context.Context, tuples []TupleKey) error
	Delete(ctx context.Context, tuples []TupleKey) error
}

// InMemoryFGA evaluates the narrow model in model.fga for contract tests.
// It is not a general OpenFGA implementation.
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
	user, relation, object string,
) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	store.mu.RLock()
	defer store.mu.RUnlock()

	switch {
	case strings.HasPrefix(object, "jira_project:"):
		return store.checkJiraProject(user, relation, object), nil
	case strings.HasPrefix(object, "jira_issue:"):
		return store.checkJiraIssue(user, relation, object), nil
	case strings.HasPrefix(object, "slack_channel:"):
		return store.checkSlackChannel(user, relation, object), nil
	case strings.HasPrefix(object, "mission:"):
		switch relation {
		case "requester", "executor", "read_issue", "post_channel":
			_, allowed := store.tuples[TupleKey{
				User: user, Relation: relation, Object: object,
			}]
			return allowed, nil
		}
	}

	return false, fmt.Errorf("unsupported FGA check: %s %s %s", user, relation, object)
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

func (store *InMemoryFGA) checkJiraProject(user, relation, project string) bool {
	if relation != "owner" && relation != "viewer" {
		return false
	}
	if _, allowed := store.tuples[TupleKey{
		User: user, Relation: relation, Object: project,
	}]; allowed {
		return true
	}
	if relation == "viewer" {
		return store.checkJiraProject(user, "owner", project)
	}
	return false
}

func (store *InMemoryFGA) checkJiraIssue(user, relation, issue string) bool {
	switch relation {
	case "project":
		_, allowed := store.tuples[TupleKey{
			User: user, Relation: "project", Object: issue,
		}]
		return allowed
	case "can_read":
		for tuple := range store.tuples {
			if tuple.Relation == "project" && tuple.Object == issue &&
				store.checkJiraProject(user, "viewer", tuple.User) {
				return true
			}
		}
	}
	return false
}

func (store *InMemoryFGA) checkSlackChannel(user, relation, channel string) bool {
	switch relation {
	case "member":
		_, allowed := store.tuples[TupleKey{
			User: user, Relation: "member", Object: channel,
		}]
		return allowed
	case "poster", "can_post":
		if _, allowed := store.tuples[TupleKey{
			User: user, Relation: relation, Object: channel,
		}]; allowed {
			return true
		}
		return store.checkSlackChannel(user, "member", channel)
	}
	return false
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
	user, relation, object string,
) (bool, error) {
	body := struct {
		TupleKey             TupleKey `json:"tuple_key"`
		AuthorizationModelID string   `json:"authorization_model_id,omitempty"`
	}{
		TupleKey:             TupleKey{User: user, Relation: relation, Object: object},
		AuthorizationModelID: client.AuthorizationModelID,
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
	type tupleSet struct {
		TupleKeys []TupleKey `json:"tuple_keys"`
	}
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
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
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

type IntentGrant struct {
	Action     Action
	ResourceID string
}

type IntentProposal struct {
	UserPrompt             string
	Grants                 []IntentGrant
	RequiresEgressApproval bool
}

type Mission struct {
	ID              string
	Requester       string
	Agent           string
	Intent          IntentProposal
	ExpiresAt       time.Time
	ReadIssues      []string
	PostChannels    []string
	State           MissionState
	Version         int
	ApprovalPreview string
	EgressApproved  bool
}

type MissionTokenSigner struct {
	secret []byte
}

type missionTokenClaims struct {
	MissionID string `json:"mission_id"`
	Agent     string `json:"agent"`
	Version   int    `json:"version"`
	ExpiresAt int64  `json:"expires_at"`
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
	claims := missionTokenClaims{
		MissionID: mission.ID,
		Agent:     mission.Agent,
		Version:   mission.Version,
		ExpiresAt: mission.ExpiresAt.Unix(),
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
) (missionTokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return missionTokenClaims{}, fmt.Errorf("invalid Mission token format")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return missionTokenClaims{}, fmt.Errorf("invalid Mission token signature")
	}
	if !hmac.Equal(signer.sign(parts[0]), signature) {
		return missionTokenClaims{}, fmt.Errorf("invalid Mission token signature")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return missionTokenClaims{}, fmt.Errorf("invalid Mission token payload")
	}
	var claims missionTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return missionTokenClaims{}, fmt.Errorf("invalid Mission token payload")
	}
	if claims.ExpiresAt <= now.Unix() {
		return missionTokenClaims{}, fmt.Errorf("Mission token expired")
	}
	return claims, nil
}

func (signer *MissionTokenSigner) sign(payload string) []byte {
	mac := hmac.New(sha256.New, signer.secret)
	_, _ = mac.Write([]byte(payload))
	return mac.Sum(nil)
}

// FilterAuthorizedCandidates consumes results from an external resolver. FGA
// does not map natural-language names to resource IDs.
func FilterAuthorizedCandidates(
	ctx context.Context,
	fga FGAStore,
	requester string,
	action Action,
	candidates []string,
) ([]string, error) {
	relation, _, prefix, err := actionDetails(action)
	if err != nil {
		return nil, err
	}

	allowed := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if !strings.HasPrefix(candidate, prefix) {
			continue
		}
		canAccess, err := fga.Check(ctx, requester, relation, candidate)
		if err != nil {
			return nil, err
		}
		if canAccess {
			allowed = append(allowed, candidate)
		}
	}
	return allowed, nil
}

type MissionService struct {
	fga      FGAStore
	signer   *MissionTokenSigner
	mu       sync.RWMutex
	missions map[string]*Mission
}

type CreateMissionInput struct {
	MissionID string
	Requester string
	Agent     string
	Intent    IntentProposal
	ExpiresAt time.Time
}

func NewMissionService(fga FGAStore, signer *MissionTokenSigner) *MissionService {
	return &MissionService{
		fga:      fga,
		signer:   signer,
		missions: make(map[string]*Mission),
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
	if len(input.Intent.Grants) == 0 {
		return nil, fmt.Errorf("a Mission needs at least one scoped action")
	}
	if !input.ExpiresAt.After(time.Now()) {
		return nil, fmt.Errorf("Mission expiry must be in the future")
	}

	readIssues, postChannels, err := collectScope(input.Intent.Grants)
	if err != nil {
		return nil, err
	}

	service.mu.Lock()
	defer service.mu.Unlock()

	if _, exists := service.missions[input.MissionID]; exists {
		return nil, fmt.Errorf("Mission %s already exists", input.MissionID)
	}
	mission := &Mission{
		ID:           input.MissionID,
		Requester:    input.Requester,
		Agent:        input.Agent,
		Intent:       input.Intent,
		ExpiresAt:    input.ExpiresAt.UTC(),
		ReadIssues:   readIssues,
		PostChannels: postChannels,
		State:        MissionDraft,
		Version:      1,
	}
	service.missions[mission.ID] = mission
	return cloneMission(mission), nil
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
	if err := service.validateBaseAccess(ctx, mission); err != nil {
		return "", err
	}
	if err := service.fga.Write(ctx, missionTuples(mission)); err != nil {
		return "", fmt.Errorf("write Mission tuples: %w", err)
	}

	mission.State = MissionActive
	return service.signer.Issue(mission)
}

func (service *MissionService) RequestEgressApproval(
	missionID, preview string,
) error {
	service.mu.Lock()
	defer service.mu.Unlock()

	mission, err := service.getLocked(missionID)
	if err != nil {
		return err
	}
	if mission.State != MissionActive {
		return fmt.Errorf("only an active Mission may request egress approval")
	}
	if !mission.Intent.RequiresEgressApproval {
		return fmt.Errorf("this Mission does not require egress approval")
	}
	if len(mission.PostChannels) == 0 {
		return fmt.Errorf("this Mission has no Slack post scope")
	}
	if strings.TrimSpace(preview) == "" {
		return fmt.Errorf("approval preview cannot be empty")
	}

	mission.ApprovalPreview = preview
	mission.EgressApproved = false
	return nil
}

func (service *MissionService) ApproveEgress(missionID, actor string) error {
	service.mu.Lock()
	defer service.mu.Unlock()

	mission, err := service.getLocked(missionID)
	if err != nil {
		return err
	}
	if actor != mission.Requester {
		return fmt.Errorf("only the Mission requester may approve egress")
	}
	if mission.ApprovalPreview == "" {
		return fmt.Errorf("egress approval requires a preview")
	}

	mission.EgressApproved = true
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
	return nil
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

func (service *MissionService) validateBaseAccess(
	ctx context.Context,
	mission *Mission,
) error {
	for _, issue := range mission.ReadIssues {
		allowed, err := service.fga.Check(ctx, mission.Requester, "can_read", issue)
		if err != nil {
			return err
		}
		if !allowed {
			return fmt.Errorf(
				"%s cannot read %s; Mission cannot delegate it",
				mission.Requester,
				issue,
			)
		}
	}
	for _, channel := range mission.PostChannels {
		allowed, err := service.fga.Check(ctx, mission.Requester, "can_post", channel)
		if err != nil {
			return err
		}
		if !allowed {
			return fmt.Errorf(
				"%s cannot post to %s; Mission cannot delegate it",
				mission.Requester,
				channel,
			)
		}
	}
	return nil
}

func collectScope(grants []IntentGrant) ([]string, []string, error) {
	readIssues := make(map[string]struct{})
	postChannels := make(map[string]struct{})

	for _, grant := range grants {
		switch grant.Action {
		case ReadJiraIssue:
			if !strings.HasPrefix(grant.ResourceID, "jira_issue:") {
				return nil, nil, fmt.Errorf("read target must be a Jira issue")
			}
			readIssues[grant.ResourceID] = struct{}{}
		case PostSlackMessage:
			if !strings.HasPrefix(grant.ResourceID, "slack_channel:") {
				return nil, nil, fmt.Errorf("post target must be a Slack channel")
			}
			postChannels[grant.ResourceID] = struct{}{}
		default:
			return nil, nil, fmt.Errorf("unsupported action %q", grant.Action)
		}
	}
	return sortedKeys(readIssues), sortedKeys(postChannels), nil
}

func missionTuples(mission *Mission) []TupleKey {
	object := "mission:" + mission.ID
	tuples := []TupleKey{
		{User: mission.Requester, Relation: "requester", Object: object},
		{User: mission.Agent, Relation: "executor", Object: object},
	}
	for _, issue := range mission.ReadIssues {
		tuples = append(tuples, TupleKey{
			User: issue, Relation: "read_issue", Object: object,
		})
	}
	for _, channel := range mission.PostChannels {
		tuples = append(tuples, TupleKey{
			User: channel, Relation: "post_channel", Object: object,
		})
	}
	return tuples
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return keys
}

func cloneMission(mission *Mission) *Mission {
	copy := *mission
	copy.ReadIssues = append([]string(nil), mission.ReadIssues...)
	copy.PostChannels = append([]string(nil), mission.PostChannels...)
	copy.Intent.Grants = append([]IntentGrant(nil), mission.Intent.Grants...)
	return &copy
}

type CheckResult struct {
	Name    string `json:"name"`
	Allowed bool   `json:"allowed"`
}

type Decision struct {
	Allowed        bool          `json:"allowed"`
	Reason         string        `json:"reason"`
	MissionID      string        `json:"mission_id,omitempty"`
	MissionVersion int           `json:"mission_version,omitempty"`
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
	Action       Action
	ResourceID   string
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
		return gateway.record(false, err.Error(), nil, nil, now)
	}
	mission, err := gateway.missions.Get(claims.MissionID)
	if err != nil {
		return gateway.record(false, err.Error(), nil, nil, now)
	}

	if claims.Agent != request.Agent || mission.Agent != request.Agent {
		return gateway.record(
			false,
			"Mission token is not bound to this agent",
			mission,
			[]CheckResult{{Name: "agent_binding", Allowed: false}},
			now,
		)
	}
	if claims.Version != mission.Version {
		return gateway.record(
			false,
			"Mission token version is stale",
			mission,
			[]CheckResult{{Name: "mission_version", Allowed: false}},
			now,
		)
	}
	if mission.State != MissionActive {
		return gateway.record(
			false,
			"Mission is "+string(mission.State),
			mission,
			[]CheckResult{{Name: "mission_active", Allowed: false}},
			now,
		)
	}
	if !mission.ExpiresAt.After(now) {
		return gateway.record(
			false,
			"Mission expired",
			mission,
			[]CheckResult{{Name: "mission_expiry", Allowed: false}},
			now,
		)
	}

	baseRelation, scopeRelation, prefix, err := actionDetails(request.Action)
	if err != nil {
		return gateway.record(false, err.Error(), mission, nil, now)
	}
	if !strings.HasPrefix(request.ResourceID, prefix) {
		return gateway.record(
			false,
			"invalid resource for "+string(request.Action),
			mission,
			[]CheckResult{{Name: "resource_type", Allowed: false}},
			now,
		)
	}

	baseAccess, err := gateway.fga.Check(
		ctx,
		mission.Requester,
		baseRelation,
		request.ResourceID,
	)
	if err != nil {
		return gateway.record(false, "authorization check failed", mission, nil, now)
	}
	agentBound, err := gateway.fga.Check(
		ctx,
		request.Agent,
		"executor",
		"mission:"+mission.ID,
	)
	if err != nil {
		return gateway.record(false, "authorization check failed", mission, nil, now)
	}
	missionScope, err := gateway.fga.Check(
		ctx,
		request.ResourceID,
		scopeRelation,
		"mission:"+mission.ID,
	)
	if err != nil {
		return gateway.record(false, "authorization check failed", mission, nil, now)
	}

	checks := []CheckResult{
		{Name: "requester_base_access", Allowed: baseAccess},
		{Name: "agent_bound_to_mission", Allowed: agentBound},
		{Name: "mission_action_and_resource_scope", Allowed: missionScope},
	}
	for _, check := range checks {
		if !check.Allowed {
			return gateway.record(
				false,
				"denied by "+check.Name,
				mission,
				checks,
				now,
			)
		}
	}

	if request.Action == PostSlackMessage && mission.Intent.RequiresEgressApproval {
		approval := CheckResult{
			Name: "egress_approved", Allowed: mission.EgressApproved,
		}
		checks = append(checks, approval)
		if !approval.Allowed {
			return gateway.record(
				false,
				"egress approval is required",
				mission,
				checks,
				now,
			)
		}
	}

	return gateway.record(true, "authorized", mission, checks, now)
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
	now time.Time,
) Decision {
	decision := Decision{
		Allowed:   allowed,
		Reason:    reason,
		Checks:    append([]CheckResult(nil), checks...),
		Timestamp: now.UTC(),
	}
	if mission != nil {
		decision.MissionID = mission.ID
		decision.MissionVersion = mission.Version
	}

	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	gateway.auditLog = append(gateway.auditLog, decision)
	return decision
}

func actionDetails(action Action) (relation, scopeRelation, prefix string, err error) {
	switch action {
	case ReadJiraIssue:
		return "can_read", "read_issue", "jira_issue:", nil
	case PostSlackMessage:
		return "can_post", "post_channel", "slack_channel:", nil
	default:
		return "", "", "", fmt.Errorf("unsupported action %q", action)
	}
}

// DemoEnvironment creates the Jira-to-Slack flow used by the demo and tests.
func DemoEnvironment(
	ctx context.Context,
) (*InMemoryFGA, *MissionService, *Gateway, string, error) {
	fga := NewInMemoryFGA([]TupleKey{
		{User: "user:alice", Relation: "owner", Object: "jira_project:apollo"},
		{
			User:     "jira_project:apollo",
			Relation: "project",
			Object:   "jira_issue:APOLLO-17",
		},
		{
			User:     "jira_project:apollo",
			Relation: "project",
			Object:   "jira_issue:APOLLO-23",
		},
		{User: "user:bob", Relation: "owner", Object: "jira_project:hermes"},
		{
			User:     "jira_project:hermes",
			Relation: "project",
			Object:   "jira_issue:HERMES-1",
		},
		{User: "user:alice", Relation: "member", Object: "slack_channel:product"},
		{User: "user:alice", Relation: "member", Object: "slack_channel:company"},
	})
	signer, err := NewMissionTokenSigner([]byte("mission-v1-demo-secret-32-bytes!"))
	if err != nil {
		return nil, nil, nil, "", err
	}
	missions := NewMissionService(fga, signer)
	_, err = missions.CreateDraft(CreateMissionInput{
		MissionID: "apollo-17-product-summary-v1",
		Requester: "user:alice",
		Agent:     "agent:triage",
		Intent: IntentProposal{
			UserPrompt: "Read APOLLO-17 and post a summary to #product.",
			Grants: []IntentGrant{
				{Action: ReadJiraIssue, ResourceID: "jira_issue:APOLLO-17"},
				{Action: PostSlackMessage, ResourceID: "slack_channel:product"},
			},
			RequiresEgressApproval: true,
		},
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		return nil, nil, nil, "", err
	}
	token, err := missions.Approve(
		ctx,
		"apollo-17-product-summary-v1",
		"user:alice",
		time.Now(),
	)
	if err != nil {
		return nil, nil, nil, "", err
	}
	return fga, missions, NewGateway(fga, missions, signer), token, nil
}
