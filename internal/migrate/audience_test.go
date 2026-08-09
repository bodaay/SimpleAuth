package migrate

import (
	"strings"
	"testing"

	"simpleauth/internal/store"
)

// newCentral builds a central with a target app plus a victim app whose audience
// the bundle will try to claim.
func newCentral(t *testing.T, targetID string) store.Store {
	t.Helper()
	c := open(t)
	must(t, c.CreateApp(&store.App{AppID: targetID, Audience: targetID}))
	must(t, c.CreateApp(&store.App{AppID: "billing", Audience: "billing-api"}))
	return c
}

// bundleWithAudience returns a minimal bundle carrying the given audience.
func bundleWithAudience(aud string) *Bundle {
	return &Bundle{
		SchemaRev: SchemaRev,
		App:       AppConfig{Audience: aud},
	}
}

// TestApplyRejectsForeignAudience is the H15 regression: a migration-token holder
// must not be able to re-stamp their own app with another app's audience and mint
// tokens the victim's resource servers accept.
func TestApplyRejectsForeignAudience(t *testing.T) {
	c := newCentral(t, "migrated-shop")
	b := bundleWithAudience("billing-api")

	if _, err := Apply(b, c, "migrated-shop", "simpleauth", false); err == nil {
		t.Fatal("Apply accepted a bundle claiming another app's audience (H15)")
	} else if !strings.Contains(err.Error(), "billing") {
		t.Fatalf("error should name the conflicting app, got: %v", err)
	}

	// Nothing was written — the check runs before the first mutation.
	app, err := c.GetApp("migrated-shop")
	if err != nil {
		t.Fatalf("get target: %v", err)
	}
	if app.Audience != "migrated-shop" {
		t.Fatalf("target audience was mutated despite the refusal: %q", app.Audience)
	}
}

// TestApplyRejectsAppIDCollision covers claiming another app's app_id, which is
// its audience when no explicit audience is set (appAudience falls back to AppID).
func TestApplyRejectsAppIDCollision(t *testing.T) {
	c := open(t)
	must(t, c.CreateApp(&store.App{AppID: "target", Audience: "target"}))
	must(t, c.CreateApp(&store.App{AppID: "payroll"})) // no explicit audience

	if _, err := Apply(bundleWithAudience("payroll"), c, "target", "simpleauth", false); err == nil {
		t.Fatal("Apply accepted a bundle claiming another app's app_id as its audience (H15)")
	}
}

// TestApplyRejectsDefaultAppAudience is the no-effort version of the attack: a
// STOCK standalone packages aud = "simpleauth", which is the central's own default
// app. This must be refused even though ensureDefaultApp may never have written
// that row (pkg/server never calls it), so a ListApps-only check would miss it.
func TestApplyRejectsDefaultAppAudience(t *testing.T) {
	c := open(t)
	must(t, c.CreateApp(&store.App{AppID: "target", Audience: "target"}))
	// Deliberately NO "simpleauth" app row — resolveApp synthesizes it in prod.

	if _, err := Apply(bundleWithAudience("simpleauth"), c, "target", "simpleauth", false); err == nil {
		t.Fatal("Apply accepted the central's default-app audience with no app row present (H15)")
	}
}

// TestApplyAllowsDistinctAudience proves the fix is not over-broad: a legitimate
// migration still carries its own audience.
func TestApplyAllowsDistinctAudience(t *testing.T) {
	c := newCentral(t, "migrated-shop")
	if _, err := Apply(bundleWithAudience("shop-api"), c, "migrated-shop", "simpleauth", false); err != nil {
		t.Fatalf("legitimate audience carry was refused: %v", err)
	}
	app, err := c.GetApp("migrated-shop")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if app.Audience != "shop-api" {
		t.Fatalf("audience not carried: %q", app.Audience)
	}
}

// TestApplyAudienceIsIdempotent covers re-running a migration for the same app:
// the target must not collide with itself.
func TestApplyAudienceIsIdempotent(t *testing.T) {
	c := newCentral(t, "migrated-shop")
	b := bundleWithAudience("shop-api")
	if _, err := Apply(b, c, "migrated-shop", "simpleauth", false); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	// Second run carries the same audience, which the target now already holds.
	if _, err := Apply(b, c, "migrated-shop", "simpleauth", false); err != nil {
		t.Fatalf("re-running the same migration must be idempotent, got: %v", err)
	}
}

// TestApplyTrimsCarriedAudience — whitespace must not be a way to smuggle a
// near-collision past the check or to store a ragged audience.
func TestApplyTrimsCarriedAudience(t *testing.T) {
	c := newCentral(t, "migrated-shop")
	if _, err := Apply(bundleWithAudience("  billing-api  "), c, "migrated-shop", "simpleauth", false); err == nil {
		t.Fatal("whitespace-padded foreign audience must still be refused (H15)")
	}
	if _, err := Apply(bundleWithAudience("  shop-api  "), c, "migrated-shop", "simpleauth", false); err != nil {
		t.Fatalf("padded legitimate audience: %v", err)
	}
	app, _ := c.GetApp("migrated-shop")
	if app.Audience != "shop-api" {
		t.Fatalf("audience should be stored trimmed, got %q", app.Audience)
	}
}

// TestApplyEmptyAudienceKeepsTargets — an omitted audience must leave whatever the
// master admin configured on the target, not blank it.
func TestApplyEmptyAudienceKeepsTargets(t *testing.T) {
	c := open(t)
	must(t, c.CreateApp(&store.App{AppID: "target", Audience: "admin-chosen"}))
	if _, err := Apply(bundleWithAudience(""), c, "target", "simpleauth", false); err != nil {
		t.Fatalf("apply: %v", err)
	}
	app, _ := c.GetApp("target")
	if app.Audience != "admin-chosen" {
		t.Fatalf("empty carried audience must preserve the target's, got %q", app.Audience)
	}
}

// TestClassifyReportsAudienceConflict pins that the dry run surfaces the conflict
// (so an operator sees it before committing) and reports the audience it would
// apply on the happy path.
func TestClassifyReportsAudienceConflict(t *testing.T) {
	c := newCentral(t, "migrated-shop")

	rep, err := Classify(bundleWithAudience("billing-api"), c, "migrated-shop", "simpleauth")
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if rep.OK() {
		t.Fatal("Classify must block a colliding audience (H15)")
	}
	if len(rep.Blocked) == 0 || !strings.Contains(rep.Blocked[0].Reason, "billing") {
		t.Fatalf("blocked reason should name the conflicting app: %+v", rep.Blocked)
	}

	rep2, err := Classify(bundleWithAudience("shop-api"), c, "migrated-shop", "simpleauth")
	if err != nil {
		t.Fatalf("classify ok-case: %v", err)
	}
	if !rep2.OK() {
		t.Fatalf("legitimate audience must not block: %+v", rep2.Blocked)
	}
	if rep2.AudienceToApply != "shop-api" {
		t.Fatalf("dry run should report the audience it would apply, got %q", rep2.AudienceToApply)
	}
}

// TestApplyRejectsAudienceMatchingTargetAppID closes the bypass an adversarial
// review found in the first cut of this fix: `aud == target.AppID` used to
// short-circuit the whole collision check.
//
// Nothing enforces audience uniqueness at app creation, so a central can hold
// App{AppID:"reports", Audience:"analytics"} — several clients pointed at one
// resource server — while the operator registers the migration target as
// App{AppID:"analytics", Audience:"analytics-migrated"}. Self-allowing the
// target's app_id there hands the bundle "analytics", the live audience of a
// third-party RP. That is H15, unmitigated.
func TestApplyRejectsAudienceMatchingTargetAppID(t *testing.T) {
	c := open(t)
	must(t, c.CreateApp(&store.App{AppID: "reports", Audience: "analytics"}))
	must(t, c.CreateApp(&store.App{AppID: "analytics", Audience: "analytics-migrated"}))

	if _, err := Apply(bundleWithAudience("analytics"), c, "analytics", "simpleauth", false); err == nil {
		t.Fatal("bundle claimed a third party's live audience via the target's own app_id (H15)")
	}
	// The target keeps what the operator set.
	app, _ := c.GetApp("analytics")
	if app.Audience != "analytics-migrated" {
		t.Fatalf("target audience mutated despite refusal: %q", app.Audience)
	}
	// And the legitimate idempotent case still works: carrying the value the
	// target already holds.
	if _, err := Apply(bundleWithAudience("analytics-migrated"), c, "analytics", "simpleauth", false); err != nil {
		t.Fatalf("re-carrying the target's own audience must stay allowed: %v", err)
	}
}
