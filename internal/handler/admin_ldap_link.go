package handler

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"

	"simpleauth/internal/auth"
	"simpleauth/internal/store"
)

// POST /api/admin/ldap/link-users moves users an admin created in SimpleAuth
// (a "local" username with a SimpleAuth password) onto their Active Directory
// account of the same name, keeping the user: its GUID, roles, permissions,
// app assignments and sessions stay as they are.
//
// Why it is needed: authenticateUser tries the SimpleAuth password first and
// then AD. When AD accepts the password, the user is found by the "ldap"
// mapping. A user created in SimpleAuth has only a "local" mapping, so the
// first AD sign-in JIT-provisions a SECOND user and re-points local:<name> to
// it; the first user, with its roles, is left behind. Linking writes the
// ldap:<name> mapping on the existing user before that happens.
//
// Linking needs the AD account to exist, under the user's SimpleAuth username,
// matched on the LDAP config's username attribute (sAMAccountName by default):
// it writes ldap:<that name> plus ldap:<AD's own spelling> when the two differ,
// then takes the profile, groups and sAMAccountName from AD exactly as an AD
// sign-in would. It never re-points a mapping another user holds; that case is
// reported as a conflict and left to the admin.
//
// The SimpleAuth password stays unless remove_local_password is set: until it
// is removed, it keeps working beside the AD password (authenticateUser still
// re-checks AD and refuses it when the AD account is disabled). To remove it
// later, call again with remove_local_password: a user that is already linked
// and still has a SimpleAuth password is in scope then, and only its password
// is touched.

// maxLinkGUIDs bounds one request's list; all:true has no such bound.
const maxLinkGUIDs = 1000

// Link statuses. "linked" and "linkable" (the dry run's word for it) are the
// only ones that change, or would change, anything.
const (
	linkStatusLinked        = "linked"
	linkStatusLinkable      = "linkable"
	linkStatusNotInAD       = "not_in_directory"
	linkStatusDisabledInAD  = "disabled_in_directory"
	linkStatusConflict      = "conflict"
	linkStatusAmbiguous     = "ambiguous"
	linkStatusAlreadyLinked = "already_linked"
	linkStatusAppLocal      = "skipped_app_local"
	linkStatusMerged        = "skipped_merged"
	linkStatusNoLocalName   = "no_local_username"
	linkStatusNotFound      = "not_found"
)

type directoryLinkResult struct {
	GUID        string `json:"guid"`
	DisplayName string `json:"display_name,omitempty"`
	// LocalUsername is the SimpleAuth username the AD account was found under.
	LocalUsername string `json:"local_username,omitempty"`
	// DirectoryUsername is the account's name as AD spells it (the value of the
	// username attribute); after linking it is the token's samaccountname claim.
	DirectoryUsername string `json:"directory_username,omitempty"`
	// SpellingDiffers: AD spells the name differently (e.g. by case). An app that
	// keys its own users on samaccountname sees AD's spelling from now on.
	SpellingDiffers bool   `json:"spelling_differs,omitempty"`
	Status          string `json:"status"`
	// ConflictGUID is the other user that already holds this AD account.
	ConflictGUID string `json:"conflict_guid,omitempty"`
	// HasLocalPassword: the user has a SimpleAuth password after this call.
	HasLocalPassword     bool `json:"has_local_password,omitempty"`
	LocalPasswordRemoved bool `json:"local_password_removed,omitempty"`
}

// linkStop ends a link run: the directory or the store failed, so no further
// user is looked at. Users linked before it stay linked (each link is complete
// on its own).
type linkStop struct {
	code int
	msg  string
}

func (e *linkStop) Error() string { return e.msg }

func (h *Handler) handleLinkUsersToDirectory(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GUIDs               []string `json:"guids"`
		All                 bool     `json:"all"`
		DryRun              bool     `json:"dry_run"`
		RemoveLocalPassword bool     `json:"remove_local_password"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.All == (len(req.GUIDs) > 0) {
		jsonError(w, "give either guids (one or more users) or all: true", http.StatusBadRequest)
		return
	}
	if len(req.GUIDs) > maxLinkGUIDs {
		jsonError(w, fmt.Sprintf("at most %d guids per request; use all: true for every user", maxLinkGUIDs), http.StatusBadRequest)
		return
	}
	p, err := h.getLDAPConfigDecrypted()
	if err != nil {
		jsonError(w, "ldap not configured", http.StatusNotFound)
		return
	}
	cfg := ldapConfigFromStore(p)
	attr := cfg.UsernameAttr
	if attr == "" {
		attr = "sAMAccountName"
	}
	ip := getClientIP(r)

	h.directoryLinkMu.Lock()
	defer h.directoryLinkMu.Unlock()

	guids := req.GUIDs
	if req.All {
		users, err := h.store.ListUsers()
		if err != nil {
			jsonError(w, "failed to list users", http.StatusInternalServerError)
			return
		}
		guids = make([]string, 0, len(users))
		for _, u := range users {
			guids = append(guids, u.GUID)
		}
	}

	results := []directoryLinkResult{}
	summary := map[string]int{}
	for _, guid := range guids {
		res, err := h.linkUserToDirectory(cfg, attr, guid, req.DryRun, req.RemoveLocalPassword, ip)
		if err != nil {
			stop := &linkStop{code: http.StatusInternalServerError, msg: err.Error()}
			errors.As(err, &stop)
			log.Printf("[admin] Link users to directory stopped at guid=%s: %s", guid, stop.msg)
			jsonResp(w, map[string]interface{}{
				"error":   stop.msg + "; stopped there: later users were not looked at, users listed in results are done",
				"dry_run": req.DryRun,
				"results": results,
				"summary": summary,
			}, stop.code)
			return
		}
		// all:true lists only the users it is about: SimpleAuth usernames
		// without an AD link, and, when removing passwords, linked users that
		// still have one.
		if req.All && !inScopeOfAll(res, req.RemoveLocalPassword) {
			continue
		}
		results = append(results, res)
		summary[res.Status]++
	}

	log.Printf("[admin] Link users to directory dry_run=%v all=%v summary=%v ip=%s", req.DryRun, req.All, summary, ip)
	jsonResp(w, map[string]interface{}{
		"dry_run": req.DryRun,
		"results": results,
		"summary": summary,
	}, http.StatusOK)
}

// inScopeOfAll reports whether all:true lists this result: a user with a
// SimpleAuth username and no AD link, or, when removing passwords, a linked
// user that has (or, after this call, had) a SimpleAuth password.
func inScopeOfAll(res directoryLinkResult, removePassword bool) bool {
	switch res.Status {
	case linkStatusAlreadyLinked:
		return removePassword && (res.HasLocalPassword || res.LocalPasswordRemoved)
	case linkStatusAppLocal, linkStatusMerged, linkStatusNoLocalName, linkStatusNotFound:
		return false
	}
	return true
}

// linkUserToDirectory checks one user and, unless dryRun, links it. A non-nil
// error is a *linkStop: the run must end there.
func (h *Handler) linkUserToDirectory(cfg *auth.LDAPConfig, attr, guid string, dryRun, removePassword bool, ip string) (directoryLinkResult, error) {
	res := directoryLinkResult{GUID: guid}
	user, err := h.store.GetUser(guid)
	if err != nil {
		res.Status = linkStatusNotFound
		return res, nil
	}
	res.DisplayName = user.DisplayName
	if user.OwnerAppID != "" {
		res.Status = linkStatusAppLocal
		return res, nil
	}
	if user.MergedInto != "" {
		res.Status = linkStatusMerged
		return res, nil
	}
	res.HasLocalPassword = user.PasswordHash != ""

	mappings, err := h.store.GetMappingsForUser(guid)
	if err != nil {
		return res, &linkStop{http.StatusInternalServerError, fmt.Sprintf("reading the mappings of user %s failed: %v", guid, err)}
	}
	var localNames, ldapNames []string
	for _, m := range mappings {
		switch m.Provider {
		case "local":
			localNames = append(localNames, m.ExternalID)
		case "ldap":
			ldapNames = append(ldapNames, m.ExternalID)
		}
	}
	sort.Strings(localNames)
	sort.Strings(ldapNames)
	if len(localNames) > 0 {
		res.LocalUsername = localNames[0]
	}
	if len(ldapNames) > 0 {
		res.Status = linkStatusAlreadyLinked
		res.DirectoryUsername = ldapNames[0]
		if removePassword && res.HasLocalPassword && !dryRun {
			if err := h.removeLocalPassword(user, &res, ip); err != nil {
				return res, err
			}
		}
		return res, nil
	}
	if len(localNames) == 0 {
		res.Status = linkStatusNoLocalName
		return res, nil
	}

	// Look each SimpleAuth username up in the directory; all of them must lead
	// to the same AD account.
	var found *auth.LDAPResult
	var matched []string
	for _, name := range localNames {
		entry, err := h.ldapSearchUser(cfg, attr, name)
		if errors.Is(err, auth.ErrLDAPUserNotFound) {
			continue
		}
		if err != nil {
			return res, &linkStop{http.StatusBadGateway, fmt.Sprintf("directory lookup of %q failed: %v", name, err)}
		}
		if found != nil && !strings.EqualFold(found.DN, entry.DN) {
			res.Status = linkStatusAmbiguous
			return res, nil
		}
		found = entry
		matched = append(matched, name)
	}
	if found == nil {
		res.Status = linkStatusNotInAD
		return res, nil
	}
	res.LocalUsername = matched[0]
	dirName := found.Username
	if dirName == "" {
		dirName = matched[0]
	}
	res.DirectoryUsername = dirName
	res.SpellingDiffers = dirName != matched[0]
	if found.Disabled {
		res.Status = linkStatusDisabledInAD
		return res, nil
	}

	// The names the AD sign-in looks the user up by: what people type today and
	// AD's own spelling. None of them may belong to another user.
	keys := matched
	if !containsString(keys, dirName) {
		keys = append(append([]string{}, matched...), dirName)
	}
	for _, k := range keys {
		if other, err := h.store.ResolveMapping("ldap", k); err == nil && other != guid {
			res.Status = linkStatusConflict
			res.ConflictGUID = other
			return res, nil
		}
	}
	if other, err := h.store.ResolveMapping("local", dirName); err == nil && other != guid {
		res.Status = linkStatusConflict
		res.ConflictGUID = other
		return res, nil
	}

	if dryRun {
		res.Status = linkStatusLinkable
		return res, nil
	}

	for _, k := range keys {
		if err := h.store.SetIdentityMapping("ldap", k, guid); err != nil {
			return res, &linkStop{http.StatusInternalServerError, fmt.Sprintf("saving ldap:%s for user %s failed: %v", k, guid, err)}
		}
	}
	// Exactly what an AD sign-in does: profile, groups, sAMAccountName, and
	// local:<AD spelling> when it is free.
	h.syncUserFromLDAP(user, found)
	h.recordDirectoryCheck(guid)
	res.Status = linkStatusLinked

	if removePassword && user.PasswordHash != "" {
		if err := h.removeLocalPassword(user, &res, ip); err != nil {
			return res, err
		}
	}

	log.Printf("[admin] Linked user to directory guid=%s local=%q directory=%q password_removed=%v ip=%s",
		guid, res.LocalUsername, res.DirectoryUsername, res.LocalPasswordRemoved, ip)
	h.audit("ldap_link_user", "admin", ip, map[string]interface{}{
		"user_guid":              guid,
		"local_username":         res.LocalUsername,
		"directory_username":     res.DirectoryUsername,
		"local_password_removed": res.LocalPasswordRemoved,
	})
	return res, nil
}

// removeLocalPassword removes a linked user's SimpleAuth password (and its
// history), so AD is the only way in.
func (h *Handler) removeLocalPassword(user *store.User, res *directoryLinkResult, ip string) error {
	user.PasswordHash = ""
	user.PasswordHistory = nil
	user.ForcePasswordChange = false
	if err := h.store.UpdateUser(user); err != nil {
		return &linkStop{http.StatusInternalServerError, fmt.Sprintf("removing the SimpleAuth password of user %s failed: %v", user.GUID, err)}
	}
	res.HasLocalPassword = false
	res.LocalPasswordRemoved = true
	log.Printf("[admin] SimpleAuth password removed from directory-linked user guid=%s ip=%s", user.GUID, ip)
	h.audit("local_password_removed", "admin", ip, map[string]interface{}{"user_guid": user.GUID})
	return nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
