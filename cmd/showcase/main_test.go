package main

import "testing"

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
