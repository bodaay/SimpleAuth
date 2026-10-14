package handler

import (
	"net/http"
	"testing"
)

// TestDeletedUserCanBeBootstrappedAgain is the M41 regression end to end: after
// an admin deletes a user, bootstrap must create the user again (it used to
// resolve the leftover local:<username> mapping and "update" a user that no
// longer existed), and the new user must be able to sign in.
func TestDeletedUserCanBeBootstrappedAgain(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()
	body := map[string]interface{}{
		"users": []map[string]interface{}{{
			"username": "carol", "password": "pass1234", "display_name": "Carol", "email": "carol",
		}},
	}

	bootstrap := func() map[string]interface{} {
		t.Helper()
		w := doJSON(h, "POST", "/api/admin/bootstrap", body, adm)
		if w.Code != 200 {
			t.Fatalf("bootstrap: expected 200, got %d: %s", w.Code, w.Body.String())
		}
		var resp struct {
			Users []map[string]interface{} `json:"users"`
		}
		parseJSON(t, w, &resp)
		if len(resp.Users) != 1 {
			t.Fatalf("bootstrap: expected 1 user in the answer, got %v", resp.Users)
		}
		return resp.Users[0]
	}

	first := bootstrap()
	if first["created"] != true {
		t.Fatalf("first bootstrap: expected created=true, got %v", first)
	}
	guid := first["guid"].(string)

	if w := doJSON(h, "DELETE", "/api/admin/users/"+guid, nil, adm); w.Code != 200 {
		t.Fatalf("delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	second := bootstrap()
	if second["created"] != true {
		t.Fatalf("bootstrap after delete: expected created=true, got %v", second)
	}
	if second["guid"] == guid {
		t.Fatalf("bootstrap after delete reused the deleted GUID %s", guid)
	}

	w := doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": "carol", "password": "pass1234",
	}, nil)
	if w.Code != 200 {
		t.Fatalf("login after re-bootstrap: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestAdminDeleteOfLocalUserClearsRoleAssignment: the app keeps an app-local
// user's roles under its username. Deleting the user through the admin API must
// clear them, as DELETE /api/app/users/{guid} does (M14), or a user created
// again under that name inherits the old roles.
func TestAdminDeleteOfLocalUserClearsRoleAssignment(t *testing.T) {
	h, s := testSetup(t)
	adm := adminHeaders()

	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
		"app_id": "desk", "audience": "desk", "allow_local_users": true,
	}, adm)
	var app map[string]interface{}
	parseJSON(t, w, &app)
	cred := basicAuth("desk", app["app_secret"].(string))

	w = doJSON(h, "POST", "/api/app/users", map[string]interface{}{
		"username": "agent2", "password": "deskpass1", "roles": []string{"Supervisor"},
	}, cred)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var u map[string]interface{}
	parseJSON(t, w, &u)

	if w := doJSON(h, "DELETE", "/api/admin/users/"+u["guid"].(string), nil, adm); w.Code != http.StatusOK {
		t.Fatalf("admin delete: %d %s", w.Code, w.Body.String())
	}
	if w := doJSON(h, "POST", "/api/app/users", map[string]interface{}{
		"username": "agent2", "password": "deskpass2",
	}, cred); w.Code != http.StatusCreated {
		t.Fatalf("create again: %d %s", w.Code, w.Body.String())
	}
	authz, err := s.GetAppAuthz("desk")
	if err != nil {
		t.Fatalf("authz: %v", err)
	}
	if roles, ok := authz.UserAssignments["agent2"]; ok {
		t.Fatalf("the new agent2 inherited the deleted user's roles %v", roles)
	}
}

// TestAppDeleteOfLocalUserRevokesTokens: DELETE /api/app/users/{guid} revokes the
// user's tokens like the admin delete does, so a token issued before the delete
// stops working.
func TestAppDeleteOfLocalUserRevokesTokens(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()

	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
		"app_id": "desk", "audience": "desk", "allow_local_users": true,
	}, adm)
	var app map[string]interface{}
	parseJSON(t, w, &app)
	cred := basicAuth("desk", app["app_secret"].(string))

	w = doJSON(h, "POST", "/api/app/users", map[string]interface{}{"username": "agent3", "password": "deskpass1"}, cred)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var u map[string]interface{}
	parseJSON(t, w, &u)

	w = doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": "agent3", "password": "deskpass1", "app_id": "desk",
	}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	var tok map[string]interface{}
	parseJSON(t, w, &tok)
	bearer := map[string]string{"Authorization": "Bearer " + tok["access_token"].(string)}
	if w := doJSON(h, "GET", "/api/auth/userinfo", nil, bearer); w.Code != http.StatusOK {
		t.Fatalf("userinfo before delete: %d %s", w.Code, w.Body.String())
	}

	if w := doJSON(h, "DELETE", "/api/app/users/"+u["guid"].(string), nil, cred); w.Code != http.StatusOK {
		t.Fatalf("app delete: %d %s", w.Code, w.Body.String())
	}
	if w := doJSON(h, "GET", "/api/auth/userinfo", nil, bearer); w.Code != http.StatusUnauthorized {
		t.Fatalf("access token after delete: want 401, got %d %s", w.Code, w.Body.String())
	}
	if w := doJSON(h, "POST", "/api/auth/refresh", map[string]interface{}{"refresh_token": tok["refresh_token"]}, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("refresh after delete: want 401, got %d %s", w.Code, w.Body.String())
	}
}
