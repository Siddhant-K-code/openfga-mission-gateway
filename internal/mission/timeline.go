package mission

import (
	"fmt"
	"time"
)

type TimelineKind string

const (
	TimelineProposed          TimelineKind = "mission_proposed"
	TimelineActivated         TimelineKind = "mission_activated"
	TimelineApprovalRequested TimelineKind = "approval_requested"
	TimelineApprovalGranted   TimelineKind = "approval_granted"
	TimelineDecision          TimelineKind = "call_decision"
	TimelineRevoked           TimelineKind = "mission_revoked"
	TimelineCompleted         TimelineKind = "mission_completed"
)

// TimelineEvent is an append-only, readable record of Mission lifecycle and
// gateway decisions. It is intended for audit export and a review UI.
type TimelineEvent struct {
	Sequence  int          `json:"sequence"`
	Kind      TimelineKind `json:"kind"`
	Timestamp time.Time    `json:"timestamp"`
	MissionID string       `json:"mission_id"`
	Actor     string       `json:"actor,omitempty"`
	CallID    string       `json:"call_id,omitempty"`
	Summary   string       `json:"summary"`
	Decision  *Decision    `json:"decision,omitempty"`
}

func (service *MissionService) Timeline(missionID string) ([]TimelineEvent, error) {
	service.mu.RLock()
	defer service.mu.RUnlock()
	if _, exists := service.missions[missionID]; !exists {
		return nil, fmt.Errorf("unknown Mission %s", missionID)
	}
	events := service.timelines[missionID]
	copy := make([]TimelineEvent, 0, len(events))
	for _, event := range events {
		clone := event
		if event.Decision != nil {
			decision := cloneDecision(*event.Decision)
			clone.Decision = &decision
		}
		copy = append(copy, clone)
	}
	return copy, nil
}

func (service *MissionService) recordDecision(decision Decision) {
	if decision.MissionID == "" {
		return
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	mission, exists := service.missions[decision.MissionID]
	if !exists {
		return
	}
	callID := ""
	if decision.Call != nil {
		callID, _ = decision.Call.ID()
	}
	copy := cloneDecision(decision)
	service.recordEventLocked(mission, TimelineDecision, decision.Agent, decision.Reason, callID, &copy)
}

func (service *MissionService) recordEventLocked(
	mission *Mission,
	kind TimelineKind,
	actor, summary, callID string,
	decision *Decision,
) {
	service.nextEvent++
	service.timelines[mission.ID] = append(service.timelines[mission.ID], TimelineEvent{
		Sequence:  service.nextEvent,
		Kind:      kind,
		Timestamp: time.Now().UTC(),
		MissionID: mission.ID,
		Actor:     actor,
		CallID:    callID,
		Summary:   summary,
		Decision:  decision,
	})
}

func cloneDecision(decision Decision) Decision {
	clone := decision
	clone.Checks = append([]CheckResult(nil), decision.Checks...)
	if decision.Call != nil {
		call := *decision.Call
		call.Scope = make(map[string]string, len(decision.Call.Scope))
		for key, value := range decision.Call.Scope {
			call.Scope[key] = value
		}
		call.Requirements = append([]ResourceRequirement(nil), decision.Call.Requirements...)
		clone.Call = &call
	}
	return clone
}
