package store

import (
	"log"
	"os"
)

// Dangling identity mappings (M41). Before M41, DeleteUser removed only the user
// row, so the user's identity mappings kept pointing at a GUID with no user.
// Such a mapping keeps the username taken: bootstrap and LDAP import treat the
// user as existing, and app self-registration answers 409. It also keeps a
// deleted directory user out: an LDAP or Kerberos login resolves the mapping to
// the deleted GUID and fails, instead of provisioning a new account.
//
// Deployments may depend on that second effect without knowing it. Both stores
// therefore only REPORT dangling mappings on open by default, logging each one.
// They remove them all only when SA_REPAIR_DANGLING_MAPPINGS=1. For a removed
// app-local mapping, the repair also clears the app's role assignment for that
// username, unless a live user can still match the name. An operator can also
// remove mappings one at a time with DELETE
// /api/admin/users/{guid}/mappings/{provider}/{external_id}. Removing a
// directory mapping lets that user sign in again with a new account.
// SA_SKIP_MAPPING_REPAIR=1 overrides the opt-in, as it turns off the other
// startup mapping repair (H14).
func danglingRepairEnabled() bool {
	return os.Getenv("SA_REPAIR_DANGLING_MAPPINGS") == "1" && os.Getenv("SA_SKIP_MAPPING_REPAIR") != "1"
}

func logDanglingReportOnly(n int) {
	log.Printf("[store] dangling-mapping check: %d mapping(s) point at deleted users and were left in place. "+
		"Removing an ldap or kerberos mapping lets that user sign in again with a new account. "+
		"Remove single mappings with DELETE /api/admin/users/{guid}/mappings/{provider}/{external_id}, "+
		"or restart with SA_REPAIR_DANGLING_MAPPINGS=1 to remove them all (M41)", n)
}
