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
// mapping. A user created in SimpleAuth has only a "local" mapping, so its
// first AD sign-in JIT-provisions a SECOND user, and the first user, with its
// roles, is not the one signed in. Linking writes the ldap mappings on the
// existing user before that happens.
//
// The AD account is found with the sign-in's own search (custom_filter, else
// username_attr), limited to person entries, over one connection per run. It
// must be exactly one enabled entry that no other user holds. When both sides
// have an email and they differ, the same name is not taken as proof of the
// same person: the user is linked only when its guid is also in "confirmed".
// Linking writes ldap:<name> plus ldap:<AD's own spelling> when the two differ,
// then takes the profile, groups and sAMAccountName from AD exactly as an AD
// sign-in does. It never re-points a mapping another user holds.
//
// The SimpleAuth password stays unless remove_local_password is set: until it
// is removed, it keeps working beside the AD password (authenticateUser still
// re-checks AD and refuses it when the AD account is disabled, subject to the
// directory_outage_policy). To remove it later, call again with
// remove_local_password: a user that is already linked and still has a
// SimpleAuth password is in scope then, and only its password is touched.

// maxLinkGUIDs bounds one request's list; all:true has no such bound.
const maxLinkGUIDs = 1000

// Link statuses. "linked" and "linkable" (the dry run's word for it) are the
// only ones that change, or would change, the mappings.
const (
	linkStatusLinked        = "linked"
	linkStatusLinkable      = "linkable"
	linkStatusNotInAD       = "not_in_directory"
	linkStatusDisabledInAD  = "disabled_in_directory"
	linkStatusEmailDiffers  = "email_differs"
	linkStatusConflict      = "conflict"
	linkStatusAmbiguous     = "ambiguous"
	linkStatusAlreadyLinked = "already_linked"
	linkStatusAppLocal      = "skipped_app_local"
	linkStatusMerged        = "skipped_merged"
	linkStatusNoLocalName   = "no_local_username"
	linkStatusNotFound      = "not_found"
)

// directoryFinder looks directory users up over one connection
// (auth.LDAPUserFinder); tests replace it.
type directoryFinder interface {
	Find(username string) (*auth.LDAPResult, error)
	Close()
}

func newLDAPUserFinder(cfg *auth.LDAPConfig) (directoryFinder, error) {
	return auth.NewLDAPUserFinder(cfg)
}

type directoryLinkResult struct {
	GUID        string `json:"guid"`
	DisplayName string `json:"display_name,omitempty"`
	Email       string `json:"email,omitempty"`
	// LocalUsername is the SimpleAuth username the AD account was found under.
	LocalUsername string `json:"local_username,omitempty"`
	// DirectoryUsername is the account's name as AD spells it (the value of the
	// username attribute); after linking it is the token's samaccountname claim.
	DirectoryUsername    string `json:"directory_username,omitempty"`
	DirectoryDisplayName string `json:"directory_display_name,omitempty"`
	DirectoryEmail       string `json:"directory_email,omitempty"`
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

// linkRun is one request's state: the options and the directory connection,
// opened at the first lookup and closed when the run ends.
type linkRun struct {
	h              *Handler
	cfg            *auth.LDAPConfig
	finder         directoryFinder
	dryRun         bool
	removePassword bool
	confirmed      map[string]bool
	ip             string
}

func (run *linkRun) find(name string) (*auth.LDAPResult, error) {
	if run.finder == nil {
		f, err := run.h.ldapUserFinder(run.cfg)
		if err != nil {
			return nil, &linkStop{http.StatusBadGateway, fmt.Sprintf("connecting to the directory failed: %v", err)}
		}
		run.finder = f
	}
	return run.finder.Find(name)
}

func (run *linkRun) close() {
	if run.finder != nil {
		run.finder.Close()
	}
}

func (h *Handler) handleLinkUsersToDirectory(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GUIDs               []string `json:"guids"`
		All                 bool     `json:"all"`
		DryRun              bool     `json:"dry_run"`
		RemoveLocalPassword bool     `json:"remove_local_password"`
		Confirmed           []string `json:"confirmed"`
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
	run := &linkRun{
		h: h, cfg: ldapConfigFromStore(p), dryRun: req.DryRun, removePassword: req.RemoveLocalPassword,
		confirmed: map[string]bool{}, ip: getClientIP(r),
	}
	for _, g := range req.Confirmed {
		run.confirmed[g] = true
	}

	h.directoryLinkMu.Lock()
	defer h.directoryLinkMu.Unlock()
	defer run.close()

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
	stopWith := func(guid string, stop *linkStop) {
		log.Printf("[admin] Link users to directory stopped at guid=%s: %s", logSafe(guid), logSafe(stop.msg))
		jsonResp(w, map[string]interface{}{
			"error":   stop.msg + "; stopped there: later users were not looked at, users listed in results are done",
			"dry_run": req.DryRun,
			"results": results,
			"summary": summary,
		}, stop.code)
	}
	for _, guid := range guids {
		// The client is gone or the server's write deadline passed: stop
		// rather than keep writing what nobody will see.
		if err := r.Context().Err(); err != nil {
			stopWith(guid, &linkStop{http.StatusServiceUnavailable, fmt.Sprintf("request ended (%v)", err)})
			return
		}
		res, err := run.user(guid)
		if err != nil {
			stop := &linkStop{code: http.StatusInternalServerError, msg: err.Error()}
			errors.As(err, &stop)
			stopWith(guid, stop)
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

	// Labels, not the request's values, go to the log.
	mode, scope := "apply", "guids"
	if req.DryRun {
		mode = "dry run"
	}
	if req.All {
		scope = "all"
	}
	log.Printf("[admin] Link users to directory (%s, %s) summary=%v ip=%s", mode, scope, summary, run.ip)
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

// mappingOwner is the user holding provider:name, "" when nobody does; an
// error is a store failure.
func (h *Handler) mappingOwner(provider, name string) (string, error) {
	guid, err := h.store.ResolveMapping(provider, name)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", &linkStop{http.StatusInternalServerError, fmt.Sprintf("reading mapping %s:%s failed: %v", provider, name, err)}
	}
	return guid, nil
}

// user checks one user and, unless dryRun, links it. A non-nil error is a
// *linkStop: the run must end there.
func (run *linkRun) user(guid string) (directoryLinkResult, error) {
	h := run.h
	res := directoryLinkResult{GUID: guid}
	user, err := h.store.GetUser(guid)
	if errors.Is(err, store.ErrNotFound) {
		res.Status = linkStatusNotFound
		return res, nil
	}
	if err != nil {
		return res, &linkStop{http.StatusInternalServerError, fmt.Sprintf("reading user %s failed: %v", guid, err)}
	}
	res.DisplayName, res.Email = user.DisplayName, user.Email
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
		if run.removePassword && res.HasLocalPassword && !run.dryRun {
			if err := run.removeLocalPassword(guid, &res); err != nil {
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
		entry, err := run.find(name)
		if errors.Is(err, auth.ErrLDAPUserNotFound) {
			continue
		}
		if errors.Is(err, auth.ErrLDAPAmbiguous) {
			res.Status = linkStatusAmbiguous
			return res, nil
		}
		var stop *linkStop
		if errors.As(err, &stop) {
			return res, stop
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
	res.DirectoryDisplayName, res.DirectoryEmail = found.DisplayName, found.Email
	res.SpellingDiffers = dirName != matched[0]
	if found.Disabled {
		res.Status = linkStatusDisabledInAD
		return res, nil
	}
	// The names the AD sign-in looks the user up by: what people type today and
	// AD's own spelling. None of them may belong to another user.
	keys := append([]string{}, matched...)
	if !containsString(keys, dirName) {
		keys = append(keys, dirName)
	}
	for _, k := range keys {
		owner, err := h.mappingOwner("ldap", k)
		if err != nil {
			return res, err
		}
		if owner != "" && owner != guid {
			res.Status = linkStatusConflict
			res.ConflictGUID = owner
			return res, nil
		}
	}
	owner, err := h.mappingOwner("local", dirName)
	if err != nil {
		return res, err
	}
	if owner != "" && owner != guid {
		res.Status = linkStatusConflict
		res.ConflictGUID = owner
		return res, nil
	}

	// The same name is not proof of the same person: when both sides have an
	// email and they differ, link only what the admin confirmed.
	if user.Email != "" && found.Email != "" && !strings.EqualFold(user.Email, found.Email) && !run.confirmed[guid] {
		res.Status = linkStatusEmailDiffers
		return res, nil
	}

	if run.dryRun {
		res.Status = linkStatusLinkable
		return res, nil
	}

	// Write from a fresh copy: the user may have changed (disabled, locked)
	// while the directory was asked.
	user, err = h.store.GetUser(guid)
	if err != nil {
		return res, &linkStop{http.StatusInternalServerError, fmt.Sprintf("re-reading user %s failed: %v", guid, err)}
	}
	previousName, previousEmail := user.DisplayName, user.Email
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

	if run.removePassword && user.PasswordHash != "" {
		if err := run.removeLocalPassword(guid, &res); err != nil {
			return res, err
		}
	}

	// The store's GUID and a yes/no label go to the log, never request text or
	// a password field.
	pwd := "kept"
	if res.LocalPasswordRemoved {
		pwd = "removed"
	}
	log.Printf("[admin] Linked user to directory guid=%s local=%s directory=%s SimpleAuth password %s ip=%s",
		user.GUID, logSafe(res.LocalUsername), logSafe(res.DirectoryUsername), pwd, run.ip)
	h.audit("ldap_link_user", "admin", run.ip, map[string]interface{}{
		"user_guid":              guid,
		"local_username":         res.LocalUsername,
		"directory_username":     res.DirectoryUsername,
		"directory_dn":           found.DN,
		"previous_display_name":  previousName,
		"previous_email":         previousEmail,
		"email_confirmed":        run.confirmed[guid],
		"local_password_removed": res.LocalPasswordRemoved,
	})
	return res, nil
}

// removeLocalPassword removes a linked user's SimpleAuth password (and its
// history), so AD is the only way in. It re-reads the user so a change made
// meanwhile is not overwritten.
func (run *linkRun) removeLocalPassword(guid string, res *directoryLinkResult) error {
	h := run.h
	user, err := h.store.GetUser(guid)
	if err != nil {
		return &linkStop{http.StatusInternalServerError, fmt.Sprintf("re-reading user %s failed: %v", guid, err)}
	}
	user.PasswordHash = ""
	user.PasswordHistory = nil
	user.ForcePasswordChange = false
	if err := h.store.UpdateUser(user); err != nil {
		return &linkStop{http.StatusInternalServerError, fmt.Sprintf("removing the SimpleAuth password of user %s failed: %v", guid, err)}
	}
	res.HasLocalPassword = false
	res.LocalPasswordRemoved = true
	log.Printf("[admin] SimpleAuth password removed from directory-linked user guid=%s ip=%s", user.GUID, run.ip)
	h.audit("local_password_removed", "admin", run.ip, map[string]interface{}{"user_guid": guid})
	return nil
}

// logSafe keeps a value on one log line: line breaks out, so a name typed at
// sign-in or sent in a request cannot forge log entries.
func logSafe(s string) string {
	s = strings.ReplaceAll(s, "\n", "")
	return strings.ReplaceAll(s, "\r", "")
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
