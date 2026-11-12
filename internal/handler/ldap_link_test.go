package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"net/http/httptest"
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
	ambiguous map[string]bool             // names that match more than one entry
	searchErr error                       // every link lookup fails with it
	openErr   error                       // opening the link connection fails with it
	onFind    func(name string)           // runs at each link lookup
	searches  int                         // link lookups
	opens     int                         // link connections opened
	closes    int
}

type fakeFinder struct{ d *fakeDirectory }

func (f *fakeFinder) Find(name string) (*auth.LDAPResult, error) {
	d := f.d
	d.searches++
	if d.onFind != nil {
		d.onFind(name)
	}
	if d.searchErr != nil {
		return nil, d.searchErr
	}
	if d.ambiguous[strings.ToLower(name)] {
		return nil, fmt.Errorf("%w: %s", auth.ErrLDAPAmbiguous, name)
	}
	if r, ok := d.users[strings.ToLower(name)]; ok {
		c := *r
		return &c, nil
	}
	return nil, fmt.Errorf("%w: %s", auth.ErrLDAPUserNotFound, name)
}

func (f *fakeFinder) Close() { f.d.closes++ }

func (d *fakeDirectory) install(t *testing.T, h *Handler) {
	t.Helper()
	if err := h.saveLDAPConfigEncrypted(&store.LDAPConfig{
		URL: "ldap://127.0.0.1:1", BaseDN: "dc=corp,dc=test", AllowInsecure: true,
	}); err != nil {
		t.Fatal(err)
	}
	h.ldapSearchUser = func(_ *auth.LDAPConfig, field, value string) (*auth.LDAPResult, error) {
		if field != "sAMAccountName" {
			return nil, fmt.Errorf("unexpected search field %q", field)
		}
		if r, ok := d.users[strings.ToLower(value)]; ok {
			c := *r
			return &c, nil
		}
		return nil, fmt.Errorf("%w: %s=%s", auth.ErrLDAPUserNotFound, field, value)
	}
	h.ldapUserFinder = func(_ *auth.LDAPConfig) (directoryFinder, error) {
		d.opens++
		if d.openErr != nil {
			return nil, d.openErr
		}
		return &fakeFinder{d}, nil
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
	u := &store.User{DisplayName: "Local " + name, Email: strings.ToLower(name) + "@corp.test", PasswordHash: hash}
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
	Email                string `json:"email"`
	DirectoryDisplayName string `json:"directory_display_name"`
	DirectoryEmail       string `json:"directory_email"`
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
	if got.SAMAccountName != "" || got.PasswordHash == "" || got.DisplayName != "Local jdoe" {
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

// Review C1: AD matches names in any case, SimpleAuth's mappings do not. A
// sign-in typed in another case must still land on the linked user, and must
// never move the linked user's mappings to a new one.
func TestSignInInAnotherCaseKeepsTheLinkedUser(t *testing.T) {
	h, s := testSetup(t)
	dir := &fakeDirectory{
		users:     map[string]*auth.LDAPResult{"jdoe": adUser("jdoe")},
		passwords: map[string]string{"jdoe": "ad-pass-1"},
	}
	dir.install(t, h)
	u := localUser(t, s, "jdoe", "local-pass-1", "analyst")
	linkUsers(t, h, map[string]interface{}{"guids": []string{u.GUID}, "remove_local_password": true}, 200)
	before := userCount(t, s)
	mappingsBefore := mappingSet(t, s, u.GUID)

	for _, typed := range []string{"JDOE", "JDoe", "jdoe"} {
		if sub, code := signInSubject(t, h, typed, "ad-pass-1"); sub != u.GUID {
			t.Fatalf("AD sign-in as %q: sub %q (code %d), want the linked user %s", typed, sub, code, u.GUID)
		}
	}
	if n := userCount(t, s); n != before {
		t.Fatalf("a sign-in in another case created a user: %d users, want %d", n, before)
	}
	for _, m := range mappingsBefore {
		if !containsString(mappingSet(t, s, u.GUID), m) {
			t.Fatalf("the linked user lost %s: %v", m, mappingSet(t, s, u.GUID))
		}
	}
	if roles, _ := s.GetUserRoles(u.GUID); !reflect.DeepEqual(roles, []string{"analyst"}) {
		t.Fatalf("roles changed: %v", roles)
	}
}

// The first AD sign-in of a user that was NOT linked still provisions a new
// user, but must not take the SimpleAuth username away from the existing one
// (that left the original user, with its roles, with no way to sign in).
func TestFirstADSignInDoesNotTakeAnExistingUsersName(t *testing.T) {
	h, s := testSetup(t)
	dir := &fakeDirectory{
		users:     map[string]*auth.LDAPResult{"bob": adUser("bob")},
		passwords: map[string]string{"bob": "ad-pass-1"},
	}
	dir.install(t, h)
	old := localUser(t, s, "bob", "local-pass-1", "analyst")

	sub, code := signInSubject(t, h, "bob", "ad-pass-1")
	if code != 200 || sub == old.GUID {
		t.Fatalf("AD sign-in of an unlinked user: sub %q code %d (a new user is expected)", sub, code)
	}
	if guid, _ := s.ResolveMapping("local", "bob"); guid != old.GUID {
		t.Fatalf("local:bob moved to %s, want it kept on %s", guid, old.GUID)
	}
	if got, code := signInSubject(t, h, "bob", "local-pass-1"); got != old.GUID {
		t.Fatalf("the existing user's SimpleAuth password no longer signs in: sub %q code %d", got, code)
	}
}

// Review I2/I4: one directory connection per run (one bind, then a search per
// user), closed at the end.
func TestLinkUsersUsesOneDirectoryConnectionPerRun(t *testing.T) {
	h, s := testSetup(t)
	dir := &fakeDirectory{users: map[string]*auth.LDAPResult{"a1": adUser("a1"), "a2": adUser("a2"), "a3": adUser("a3")}}
	dir.install(t, h)
	for _, n := range []string{"a1", "a2", "a3"} {
		localUser(t, s, n, "local-pass-1")
	}
	resp := linkUsers(t, h, map[string]interface{}{"all": true}, 200)
	if resp.Summary["linked"] != 3 {
		t.Fatalf("unexpected summary %v", resp.Summary)
	}
	if dir.opens != 1 || dir.closes != 1 || dir.searches != 3 {
		t.Fatalf("opens=%d closes=%d searches=%d, want 1, 1, 3", dir.opens, dir.closes, dir.searches)
	}
	// A run with nothing to look up opens no connection.
	dir.opens = 0
	linkUsers(t, h, map[string]interface{}{"all": true}, 200)
	if dir.opens != 0 {
		t.Fatalf("a run without lookups opened %d connection(s)", dir.opens)
	}
}

func TestLinkUsersStopsWhenTheDirectoryCannotBeReached(t *testing.T) {
	h, s := testSetup(t)
	dir := &fakeDirectory{users: map[string]*auth.LDAPResult{"alice": adUser("alice")}, openErr: errors.New("ldap: bind refused")}
	dir.install(t, h)
	alice := localUser(t, s, "alice", "local-pass-1")
	resp := linkUsers(t, h, map[string]interface{}{"guids": []string{alice.GUID}}, 502)
	if !strings.Contains(resp.Error, "bind refused") || dir.searches != 0 {
		t.Fatalf("error %q searches %d", resp.Error, dir.searches)
	}
}

// A name that matches more than one directory entry is never linked.
func TestLinkUsersDoesNotLinkAnAmbiguousDirectoryName(t *testing.T) {
	h, s := testSetup(t)
	dir := &fakeDirectory{users: map[string]*auth.LDAPResult{}, ambiguous: map[string]bool{"sam": true}}
	dir.install(t, h)
	u := localUser(t, s, "sam", "local-pass-1")
	resp := linkUsers(t, h, map[string]interface{}{"guids": []string{u.GUID}}, 200)
	if r := resp.Results[0]; r.Status != "ambiguous" {
		t.Fatalf("unexpected result %+v", r)
	}
	if _, err := s.ResolveMapping("ldap", "sam"); err == nil {
		t.Fatal("an ambiguous name was linked")
	}
}

// Review I3: the same name is not proof of the same person. When both sides
// have an email and they differ, the user is linked only once the admin
// confirms it; the results show both identities.
func TestLinkUsersNeedsConfirmationWhenTheEmailsDiffer(t *testing.T) {
	h, s := testSetup(t)
	other := adUser("ahmed")
	other.DisplayName, other.Email = "Ahmed Hassan", "ahmed.hassan@corp.test"
	dir := &fakeDirectory{users: map[string]*auth.LDAPResult{"ahmed": other}}
	dir.install(t, h)
	u := localUser(t, s, "ahmed", "local-pass-1", "analyst")
	u.DisplayName, u.Email = "Ahmed Ali", "ahmed.ali@corp.test"
	s.UpdateUser(u)

	for _, dry := range []bool{true, false} {
		for _, body := range []map[string]interface{}{{"guids": []string{u.GUID}}, {"all": true}} {
			body["dry_run"] = dry
			resp := linkUsers(t, h, body, 200)
			r := resp.Results[0]
			if r.Status != "email_differs" || r.Email != "ahmed.ali@corp.test" || r.DirectoryEmail != "ahmed.hassan@corp.test" || r.DirectoryDisplayName != "Ahmed Hassan" {
				t.Fatalf("%v: unexpected result %+v", body, r)
			}
		}
	}
	if _, err := s.ResolveMapping("ldap", "ahmed"); err == nil {
		t.Fatal("linked without confirmation")
	}

	resp := linkUsers(t, h, map[string]interface{}{"guids": []string{u.GUID}, "confirmed": []string{u.GUID}}, 200)
	if r := resp.Results[0]; r.Status != "linked" {
		t.Fatalf("confirmed link: %+v", r)
	}
	entries, err := s.QueryAuditLog(store.AuditQuery{Event: "ldap_link_user", Limit: 10})
	if err != nil || len(entries) != 1 {
		t.Fatalf("audit entries %d, %v", len(entries), err)
	}
	if entries[0].Data["previous_email"] != "ahmed.ali@corp.test" || entries[0].Data["previous_display_name"] != "Ahmed Ali" {
		t.Fatalf("the audit record lacks the previous profile: %v", entries[0].Data)
	}
}

// Review I5: a store failure is an error, never "not found" or "free".
type failingStore struct {
	store.Store
	getUserErr, resolveErr error
}

func (f *failingStore) GetUser(guid string) (*store.User, error) {
	if f.getUserErr != nil {
		return nil, f.getUserErr
	}
	return f.Store.GetUser(guid)
}

func (f *failingStore) ResolveMapping(provider, externalID string) (string, error) {
	if f.resolveErr != nil && provider == "ldap" {
		return "", f.resolveErr
	}
	return f.Store.ResolveMapping(provider, externalID)
}

func TestLinkUsersStopsOnAStoreFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		fs   failingStore
	}{
		{"GetUser", failingStore{getUserErr: errors.New("disk I/O error")}},
		{"ResolveMapping", failingStore{resolveErr: errors.New("connection reset")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, s := testSetup(t)
			dir := &fakeDirectory{users: map[string]*auth.LDAPResult{"jdoe": adUser("jdoe")}}
			dir.install(t, h)
			u := localUser(t, s, "jdoe", "local-pass-1")
			fs := tc.fs
			fs.Store = s
			h.store = &fs
			resp := linkUsers(t, h, map[string]interface{}{"guids": []string{u.GUID}}, 500)
			if resp.Error == "" || len(resp.Results) != 0 {
				t.Fatalf("unexpected response %+v", resp)
			}
			h.store = s
			if _, err := s.ResolveMapping("ldap", "jdoe"); err == nil {
				t.Fatal("linked although the store failed")
			}
		})
	}
}

// Review M6: a change an admin makes while the directory is asked (disable)
// is not overwritten by the link's write.
func TestLinkUsersKeepsAChangeMadeDuringTheLookup(t *testing.T) {
	h, s := testSetup(t)
	dir := &fakeDirectory{users: map[string]*auth.LDAPResult{"jdoe": adUser("jdoe")}}
	dir.install(t, h)
	u := localUser(t, s, "jdoe", "local-pass-1")
	dir.onFind = func(string) {
		cur, _ := s.GetUser(u.GUID)
		cur.Disabled = true
		s.UpdateUser(cur)
	}
	resp := linkUsers(t, h, map[string]interface{}{"guids": []string{u.GUID}, "remove_local_password": true}, 200)
	if r := resp.Results[0]; r.Status != "linked" || !r.LocalPasswordRemoved {
		t.Fatalf("unexpected result %+v", r)
	}
	if got, _ := s.GetUser(u.GUID); !got.Disabled || got.PasswordHash != "" {
		t.Fatalf("disabled=%v password set=%v, want true and false", got.Disabled, got.PasswordHash != "")
	}
}

// A run whose request is gone (client closed, server timeout) stops at once.
func TestLinkUsersStopsWhenTheRequestIsCanceled(t *testing.T) {
	h, s := testSetup(t)
	dir := &fakeDirectory{users: map[string]*auth.LDAPResult{"a1": adUser("a1"), "a2": adUser("a2")}}
	dir.install(t, h)
	u1 := localUser(t, s, "a1", "local-pass-1")
	u2 := localUser(t, s, "a2", "local-pass-1")
	ctx, cancel := context.WithCancel(context.Background())
	dir.onFind = func(string) { cancel() }
	body, _ := json.Marshal(map[string]interface{}{"guids": []string{u1.GUID, u2.GUID}})
	req := httptest.NewRequest("POST", "/api/admin/ldap/link-users", bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-admin-key")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if dir.searches != 1 {
		t.Fatalf("kept looking up after the request was canceled: %d searches", dir.searches)
	}
	if _, err := s.ResolveMapping("ldap", "a2"); err == nil {
		t.Fatal("linked a user after the request was canceled")
	}
}

// AD's spelling of the name is already another user's SimpleAuth username:
// linking would make the two share a sign-in name, so it is a conflict.
func TestLinkUsersReportsAConflictOnTheDirectorySpelling(t *testing.T) {
	h, s := testSetup(t)
	dir := &fakeDirectory{users: map[string]*auth.LDAPResult{"jdoe": adUser("JDoe")}}
	dir.install(t, h)
	u := localUser(t, s, "jdoe", "local-pass-1")
	other := localUser(t, s, "JDoe", "local-pass-2")
	resp := linkUsers(t, h, map[string]interface{}{"guids": []string{u.GUID}}, 200)
	if r := resp.Results[0]; r.Status != "conflict" || r.ConflictGUID != other.GUID {
		t.Fatalf("unexpected result %+v", r)
	}
	if _, err := s.ResolveMapping("ldap", "jdoe"); err == nil {
		t.Fatal("linked despite the conflict")
	}
}
