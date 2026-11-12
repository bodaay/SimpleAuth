package handler

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"simpleauth/internal/auth"
	"simpleauth/internal/store"
)

// fakeDirectory stands in for Active Directory: sAMAccountName matching is
// case-insensitive, as in AD, and the result carries AD's own spelling.
type fakeDirectory struct {
	users     map[string]*auth.LDAPResult // key: lower-case sAMAccountName
	passwords map[string]string           // key: lower-case sAMAccountName
	searchErr error
	searches  int
}

func (d *fakeDirectory) install(t *testing.T, h *Handler) {
	t.Helper()
	if err := h.saveLDAPConfigEncrypted(&store.LDAPConfig{
		URL: "ldap://127.0.0.1:1", BaseDN: "dc=corp,dc=test", AllowInsecure: true,
	}); err != nil {
		t.Fatal(err)
	}
	h.ldapSearchUser = func(_ *auth.LDAPConfig, field, value string) (*auth.LDAPResult, error) {
		d.searches++
		if d.searchErr != nil {
			return nil, d.searchErr
		}
		if field != "sAMAccountName" {
			return nil, fmt.Errorf("unexpected search field %q", field)
		}
		if r, ok := d.users[strings.ToLower(value)]; ok {
			c := *r
			return &c, nil
		}
		return nil, fmt.Errorf("%w: %s=%s", auth.ErrLDAPUserNotFound, field, value)
	}
	h.ldapAuthenticate = func(_ *auth.LDAPConfig, username, password string) (*auth.LDAPResult, error) {
		k := strings.ToLower(username)
		r, ok := d.users[k]
		if !ok || r.Disabled || d.passwords[k] != password {
			return nil, errors.New("ldap: invalid credentials")
		}
		c := *r
		return &c, nil
	}
}

func adUser(sam string) *auth.LDAPResult {
	return &auth.LDAPResult{
		DN:          "CN=" + sam + ",CN=Users,DC=corp,DC=test",
		Username:    sam,
		DisplayName: "AD " + sam,
		Email:       strings.ToLower(sam) + "@corp.test",
		Groups:      []string{"Analysts"},
	}
}

// localUser creates a SimpleAuth user that signs in with a SimpleAuth password
// under the given name, as an admin would have before AD was configured.
func localUser(t *testing.T, s store.Store, name, password string, roles ...string) *store.User {
	t.Helper()
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	u := &store.User{DisplayName: "Local " + name, Email: name + "@old.test", PasswordHash: hash}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if err := s.SetIdentityMapping("local", name, u.GUID); err != nil {
		t.Fatal(err)
	}
	if len(roles) > 0 {
		if err := s.SetUserRoles(u.GUID, roles); err != nil {
			t.Fatal(err)
		}
	}
	return u
}

type linkResult struct {
	GUID                 string `json:"guid"`
	LocalUsername        string `json:"local_username"`
	DirectoryUsername    string `json:"directory_username"`
	SpellingDiffers      bool   `json:"spelling_differs"`
	Status               string `json:"status"`
	ConflictGUID         string `json:"conflict_guid"`
	HasLocalPassword     bool   `json:"has_local_password"`
	LocalPasswordRemoved bool   `json:"local_password_removed"`
}

type linkResponse struct {
	DryRun  bool           `json:"dry_run"`
	Results []linkResult   `json:"results"`
	Summary map[string]int `json:"summary"`
	Error   string         `json:"error"`
}

func linkUsers(t *testing.T, h *Handler, body map[string]interface{}, wantCode int) linkResponse {
	t.Helper()
	w := doJSON(h, "POST", "/api/admin/ldap/link-users", body, adminHeaders())
	if w.Code != wantCode {
		t.Fatalf("link-users %v: expected %d, got %d: %s", body, wantCode, w.Code, w.Body.String())
	}
	var resp linkResponse
	parseJSON(t, w, &resp)
	return resp
}

// signInSubject signs in through POST /api/auth/login and returns the access
// token's sub (the SimpleAuth user GUID), or "" with the status code on failure.
func signInSubject(t *testing.T, h *Handler, username, password string) (string, int) {
	t.Helper()
	w := doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": username, "password": password,
	}, nil)
	if w.Code != 200 {
		return "", w.Code
	}
	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	parseJSON(t, w, &tokens)
	parts := strings.Split(tokens.AccessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("access token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims.Sub, 200
}

func userCount(t *testing.T, s store.Store) int {
	t.Helper()
	users, err := s.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	return len(users)
}

func mappingSet(t *testing.T, s store.Store, guid string) []string {
	t.Helper()
	ms, err := s.GetMappingsForUser(guid)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range ms {
		out = append(out, m.Provider+":"+m.ExternalID)
	}
	sort.Strings(out)
	return out
}

// The point of the feature: after linking, the AD password signs the person in
// to the SAME SimpleAuth user (same GUID, same roles); no second user is made.
func TestLinkUsersLinksLocalUserToDirectory(t *testing.T) {
	h, s := testSetup(t)
	dir := &fakeDirectory{
		users:     map[string]*auth.LDAPResult{"jdoe": adUser("jdoe")},
		passwords: map[string]string{"jdoe": "ad-pass-1"},
	}
	dir.install(t, h)
	u := localUser(t, s, "jdoe", "local-pass-1", "analyst")
	before := userCount(t, s)

	resp := linkUsers(t, h, map[string]interface{}{"guids": []string{u.GUID}}, 200)
	if len(resp.Results) != 1 {
		t.Fatalf("expected 1 result, got %+v", resp.Results)
	}
	r := resp.Results[0]
	if r.Status != "linked" || r.GUID != u.GUID || r.LocalUsername != "jdoe" || r.DirectoryUsername != "jdoe" || r.SpellingDiffers {
		t.Fatalf("unexpected result %+v", r)
	}
	if resp.DryRun || resp.Summary["linked"] != 1 {
		t.Fatalf("unexpected response %+v", resp)
	}
	if guid, err := s.ResolveMapping("ldap", "jdoe"); err != nil || guid != u.GUID {
		t.Fatalf("ldap:jdoe -> %q, %v; want %s", guid, err, u.GUID)
	}
	got, _ := s.GetUser(u.GUID)
	if got.SAMAccountName != "jdoe" || got.Email != "jdoe@corp.test" || !reflect.DeepEqual(got.Groups, []string{"Analysts"}) {
		t.Fatalf("profile not taken from AD: %+v", got)
	}
	if got.PasswordHash == "" {
		t.Fatal("the SimpleAuth password was removed without remove_local_password")
	}
	if roles, _ := s.GetUserRoles(u.GUID); !reflect.DeepEqual(roles, []string{"analyst"}) {
		t.Fatalf("roles changed: %v", roles)
	}

	if sub, code := signInSubject(t, h, "jdoe", "ad-pass-1"); sub != u.GUID {
		t.Fatalf("AD sign-in: sub %q (code %d), want the linked user %s", sub, code, u.GUID)
	}
	if n := userCount(t, s); n != before {
		t.Fatalf("AD sign-in created a user: %d users, want %d", n, before)
	}
	if sub, code := signInSubject(t, h, "jdoe", "local-pass-1"); sub != u.GUID {
		t.Fatalf("SimpleAuth password sign-in after linking: sub %q (code %d), want %s", sub, code, u.GUID)
	}
}

func TestLinkUsersDryRunChangesNothing(t *testing.T) {
	h, s := testSetup(t)
	dir := &fakeDirectory{users: map[string]*auth.LDAPResult{"jdoe": adUser("jdoe")}}
	dir.install(t, h)
	u := localUser(t, s, "jdoe", "local-pass-1")
	mappingsBefore := mappingSet(t, s, u.GUID)

	resp := linkUsers(t, h, map[string]interface{}{"guids": []string{u.GUID}, "dry_run": true, "remove_local_password": true}, 200)
	if !resp.DryRun || len(resp.Results) != 1 || resp.Results[0].Status != "linkable" || resp.Results[0].DirectoryUsername != "jdoe" {
		t.Fatalf("unexpected dry run response %+v", resp)
	}
	if resp.Results[0].LocalPasswordRemoved || !resp.Results[0].HasLocalPassword {
		t.Fatalf("dry run password fields wrong: %+v", resp.Results[0])
	}
	if after := mappingSet(t, s, u.GUID); !reflect.DeepEqual(after, mappingsBefore) {
		t.Fatalf("dry run changed mappings: %v -> %v", mappingsBefore, after)
	}
	got, _ := s.GetUser(u.GUID)
	if got.SAMAccountName != "" || got.PasswordHash == "" || got.Email != "jdoe@old.test" {
		t.Fatalf("dry run changed the user: %+v", got)
	}
}

func TestLinkUsersRemovesLocalPasswordWhenAsked(t *testing.T) {
	h, s := testSetup(t)
	dir := &fakeDirectory{
		users:     map[string]*auth.LDAPResult{"jdoe": adUser("jdoe")},
		passwords: map[string]string{"jdoe": "ad-pass-1"},
	}
	dir.install(t, h)
	u := localUser(t, s, "jdoe", "local-pass-1")

	resp := linkUsers(t, h, map[string]interface{}{"guids": []string{u.GUID}, "remove_local_password": true}, 200)
	if r := resp.Results[0]; r.Status != "linked" || !r.LocalPasswordRemoved {
		t.Fatalf("unexpected result %+v", r)
	}
	got, _ := s.GetUser(u.GUID)
	if got.PasswordHash != "" || len(got.PasswordHistory) != 0 || got.ForcePasswordChange {
		t.Fatalf("SimpleAuth password not removed: hash set=%v history=%d force=%v", got.PasswordHash != "", len(got.PasswordHistory), got.ForcePasswordChange)
	}
	if _, code := signInSubject(t, h, "jdoe", "local-pass-1"); code != 401 {
		t.Fatalf("old SimpleAuth password still signs in: code %d", code)
	}
	if sub, code := signInSubject(t, h, "jdoe", "ad-pass-1"); sub != u.GUID {
		t.Fatalf("AD sign-in: sub %q (code %d), want %s", sub, code, u.GUID)
	}
}

// AD returns its own spelling of the name; both spellings must lead to the
// linked user, and the response says the spelling differs (an app keyed on the
// samaccountname claim sees the AD spelling from now on).
func TestLinkUsersTakesTheDirectorySpelling(t *testing.T) {
	h, s := testSetup(t)
	dir := &fakeDirectory{
		users:     map[string]*auth.LDAPResult{"jdoe": adUser("JDoe")},
		passwords: map[string]string{"jdoe": "ad-pass-1"},
	}
	dir.install(t, h)
	u := localUser(t, s, "jdoe", "local-pass-1")

	resp := linkUsers(t, h, map[string]interface{}{"guids": []string{u.GUID}}, 200)
	if r := resp.Results[0]; r.Status != "linked" || r.DirectoryUsername != "JDoe" || !r.SpellingDiffers {
		t.Fatalf("unexpected result %+v", r)
	}
	for _, name := range []string{"jdoe", "JDoe"} {
		if guid, err := s.ResolveMapping("ldap", name); err != nil || guid != u.GUID {
			t.Fatalf("ldap:%s -> %q, %v; want %s", name, guid, err, u.GUID)
		}
	}
	if got, _ := s.GetUser(u.GUID); got.SAMAccountName != "JDoe" {
		t.Fatalf("SAMAccountName %q, want JDoe", got.SAMAccountName)
	}
	for _, typed := range []string{"jdoe", "JDoe"} {
		if sub, code := signInSubject(t, h, typed, "ad-pass-1"); sub != u.GUID {
			t.Fatalf("AD sign-in as %q: sub %q (code %d), want %s", typed, sub, code, u.GUID)
		}
	}
}

// Every case that must not link is reported, and the user is left exactly as it was.
func TestLinkUsersReportsCasesItLeavesAlone(t *testing.T) {
	h, s := testSetup(t)
	gone := adUser("gone")
	gone.Disabled = true
	dir := &fakeDirectory{users: map[string]*auth.LDAPResult{
		"gone": gone, "dup": adUser("dup"), "linked": adUser("linked"), "shop": adUser("shop"), "merged": adUser("merged"),
		"amb1": adUser("amb1"), "amb2": adUser("amb2"),
	}}
	dir.install(t, h)

	ghost := localUser(t, s, "ghost", "local-pass-1")
	disabled := localUser(t, s, "gone", "local-pass-1")
	dup := localUser(t, s, "dup", "local-pass-1")
	other := &store.User{DisplayName: "AD dup (made at an earlier AD sign-in)"}
	if err := s.CreateUser(other); err != nil {
		t.Fatal(err)
	}
	s.SetIdentityMapping("ldap", "dup", other.GUID)
	already := localUser(t, s, "linked", "local-pass-1")
	s.SetIdentityMapping("ldap", "linked", already.GUID)
	appLocal := localUser(t, s, "shop", "local-pass-1")
	appLocal.OwnerAppID = "shop-app"
	s.UpdateUser(appLocal)
	merged := localUser(t, s, "merged", "local-pass-1")
	merged.MergedInto = other.GUID
	s.UpdateUser(merged)
	twoNames := localUser(t, s, "amb1", "local-pass-1")
	s.SetIdentityMapping("local", "amb2", twoNames.GUID) // two SimpleAuth names, two different AD accounts
	noLocal := &store.User{DisplayName: "no SimpleAuth username"}
	if err := s.CreateUser(noLocal); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		guid, status, conflict string
	}{
		{ghost.GUID, "not_in_directory", ""},
		{disabled.GUID, "disabled_in_directory", ""},
		{dup.GUID, "conflict", other.GUID},
		{already.GUID, "already_linked", ""},
		{appLocal.GUID, "skipped_app_local", ""},
		{merged.GUID, "skipped_merged", ""},
		{twoNames.GUID, "ambiguous", ""},
		{noLocal.GUID, "no_local_username", ""},
		{"no-such-guid", "not_found", ""},
	}
	var guids []string
	before := map[string][]string{}
	for _, c := range cases {
		guids = append(guids, c.guid)
		before[c.guid] = mappingSet(t, s, c.guid)
	}
	resp := linkUsers(t, h, map[string]interface{}{"guids": guids}, 200)
	if len(resp.Results) != len(cases) {
		t.Fatalf("expected %d results, got %+v", len(cases), resp.Results)
	}
	for i, c := range cases {
		r := resp.Results[i]
		if r.GUID != c.guid || r.Status != c.status || r.ConflictGUID != c.conflict {
			t.Errorf("case %d: got %+v, want status %q conflict %q", i, r, c.status, c.conflict)
		}
		if after := mappingSet(t, s, c.guid); !reflect.DeepEqual(after, before[c.guid]) {
			t.Errorf("case %d (%s): mappings changed %v -> %v", i, c.status, before[c.guid], after)
		}
	}
	if guid, _ := s.ResolveMapping("ldap", "dup"); guid != other.GUID {
		t.Fatalf("conflict re-pointed ldap:dup to %s", guid)
	}
	if resp.Summary["linked"] != 0 || resp.Summary["conflict"] != 1 {
		t.Fatalf("unexpected summary %v", resp.Summary)
	}
}

// all:true takes every user that signs in with a SimpleAuth username and has no
// AD link yet; users that are not candidates are not listed.
func TestLinkUsersAll(t *testing.T) {
	h, s := testSetup(t)
	dir := &fakeDirectory{users: map[string]*auth.LDAPResult{"alice": adUser("alice"), "carol": adUser("carol"), "shop": adUser("shop")}}
	dir.install(t, h)
	alice := localUser(t, s, "alice", "local-pass-1")
	bob := localUser(t, s, "bob", "local-pass-1")
	carol := localUser(t, s, "carol", "local-pass-1")
	s.SetIdentityMapping("ldap", "carol", carol.GUID)
	shop := localUser(t, s, "shop", "local-pass-1")
	shop.OwnerAppID = "shop-app"
	s.UpdateUser(shop)

	resp := linkUsers(t, h, map[string]interface{}{"all": true}, 200)
	got := map[string]string{}
	for _, r := range resp.Results {
		got[r.GUID] = r.Status
	}
	want := map[string]string{alice.GUID: "linked", bob.GUID: "not_in_directory"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("results %v, want %v", got, want)
	}
	if resp.Summary["linked"] != 1 || resp.Summary["not_in_directory"] != 1 {
		t.Fatalf("unexpected summary %v", resp.Summary)
	}
	if guid, _ := s.ResolveMapping("ldap", "alice"); guid != alice.GUID {
		t.Fatalf("alice not linked")
	}
}

// A directory error (AD down, bind refused) stops the run at once and says so;
// nothing after the failed lookup is touched, and nothing is guessed.
func TestLinkUsersStopsWhenTheDirectoryFails(t *testing.T) {
	h, s := testSetup(t)
	dir := &fakeDirectory{
		users:     map[string]*auth.LDAPResult{"alice": adUser("alice"), "bob": adUser("bob")},
		searchErr: errors.New("ldap: connection refused"),
	}
	dir.install(t, h)
	alice := localUser(t, s, "alice", "local-pass-1")
	bob := localUser(t, s, "bob", "local-pass-1")

	resp := linkUsers(t, h, map[string]interface{}{"guids": []string{alice.GUID, bob.GUID}}, 502)
	if !strings.Contains(resp.Error, "connection refused") {
		t.Fatalf("error does not say what failed: %q", resp.Error)
	}
	if dir.searches != 1 {
		t.Fatalf("kept looking up after the directory failed: %d searches", dir.searches)
	}
	for _, u := range []*store.User{alice, bob} {
		if _, err := s.ResolveMapping("ldap", strings.TrimPrefix(u.DisplayName, "Local ")); err == nil {
			t.Fatalf("%s linked although the directory failed", u.DisplayName)
		}
	}
}

func TestLinkUsersRequestChecks(t *testing.T) {
	h, _ := testSetup(t)
	// No LDAP configured yet.
	w := doJSON(h, "POST", "/api/admin/ldap/link-users", map[string]interface{}{"all": true}, adminHeaders())
	if w.Code != 404 {
		t.Fatalf("without LDAP: expected 404, got %d: %s", w.Code, w.Body.String())
	}
	(&fakeDirectory{}).install(t, h)
	for _, body := range []map[string]interface{}{
		{},
		{"guids": []string{}},
		{"all": true, "guids": []string{"x"}},
	} {
		w := doJSON(h, "POST", "/api/admin/ldap/link-users", body, adminHeaders())
		if w.Code != 400 {
			t.Errorf("body %v: expected 400, got %d: %s", body, w.Code, w.Body.String())
		}
	}
	w = doJSON(h, "POST", "/api/admin/ldap/link-users", map[string]interface{}{"all": true}, nil)
	if w.Code != 401 {
		t.Fatalf("without the admin key: expected 401, got %d", w.Code)
	}
}

// Link first, remove the SimpleAuth password later: with remove_local_password,
// a user that is already linked and still has a SimpleAuth password is in scope.
func TestLinkUsersRemovesThePasswordOfAnAlreadyLinkedUser(t *testing.T) {
	h, s := testSetup(t)
	dir := &fakeDirectory{
		users:     map[string]*auth.LDAPResult{"jdoe": adUser("jdoe")},
		passwords: map[string]string{"jdoe": "ad-pass-1"},
	}
	dir.install(t, h)
	u := localUser(t, s, "jdoe", "local-pass-1")
	linkUsers(t, h, map[string]interface{}{"guids": []string{u.GUID}}, 200)
	mappingsBefore := mappingSet(t, s, u.GUID)

	preview := linkUsers(t, h, map[string]interface{}{"guids": []string{u.GUID}, "remove_local_password": true, "dry_run": true}, 200)
	if r := preview.Results[0]; r.Status != "already_linked" || !r.HasLocalPassword || r.LocalPasswordRemoved {
		t.Fatalf("unexpected preview %+v", r)
	}
	if got, _ := s.GetUser(u.GUID); got.PasswordHash == "" {
		t.Fatal("the dry run removed the password")
	}

	resp := linkUsers(t, h, map[string]interface{}{"guids": []string{u.GUID}, "remove_local_password": true}, 200)
	if r := resp.Results[0]; r.Status != "already_linked" || !r.LocalPasswordRemoved {
		t.Fatalf("unexpected result %+v", r)
	}
	if got, _ := s.GetUser(u.GUID); got.PasswordHash != "" {
		t.Fatal("password not removed")
	}
	if after := mappingSet(t, s, u.GUID); !reflect.DeepEqual(after, mappingsBefore) {
		t.Fatalf("mappings changed: %v -> %v", mappingsBefore, after)
	}
	if _, code := signInSubject(t, h, "jdoe", "local-pass-1"); code != 401 {
		t.Fatalf("old SimpleAuth password still signs in: code %d", code)
	}
	if sub, _ := signInSubject(t, h, "jdoe", "ad-pass-1"); sub != u.GUID {
		t.Fatalf("AD sign-in lands on %q, want %s", sub, u.GUID)
	}
}

// all:true with remove_local_password also lists linked users that still have
// a SimpleAuth password; linked users without one are not listed.
func TestLinkUsersAllWithPasswordRemoval(t *testing.T) {
	h, s := testSetup(t)
	dir := &fakeDirectory{users: map[string]*auth.LDAPResult{"alice": adUser("alice"), "carol": adUser("carol"), "dave": adUser("dave")}}
	dir.install(t, h)
	alice := localUser(t, s, "alice", "local-pass-1")
	carol := localUser(t, s, "carol", "local-pass-1")
	s.SetIdentityMapping("ldap", "carol", carol.GUID)
	dave := &store.User{DisplayName: "AD only"}
	if err := s.CreateUser(dave); err != nil {
		t.Fatal(err)
	}
	s.SetIdentityMapping("ldap", "dave", dave.GUID)
	s.SetIdentityMapping("local", "dave", dave.GUID)

	resp := linkUsers(t, h, map[string]interface{}{"all": true, "remove_local_password": true}, 200)
	got := map[string]string{}
	for _, r := range resp.Results {
		got[r.GUID] = r.Status
		if !r.LocalPasswordRemoved {
			t.Errorf("%s: password not removed: %+v", r.GUID, r)
		}
	}
	want := map[string]string{alice.GUID: "linked", carol.GUID: "already_linked"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("results %v, want %v", got, want)
	}
}
