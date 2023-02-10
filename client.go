package gopherscloak

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	urlSeparator string = "/"
)

var authAdminRealms = makeURL("auth", "admin", "realms")

func makeURL(path ...string) string {
	return strings.Join(path, urlSeparator)
}

type gopherCloak struct {
	basePath       string
	publicBasePath string
	certsCache     map[string]*CertResponse
	Config         struct {
		CertsInvalidateTime time.Duration
	}
	httpClient *http.Client
	certsLock  sync.Mutex
}

func (g *gopherCloak) HealthCheck(realm string) error {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/auth/realms/%s", g.basePath, realm), bytes.NewBufferString(""))
	if err != nil {
		return err
	}
	response, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return g.checkForErrorsInResponse(response)
}

func (g *gopherCloak) GetGroups(accessToken string, realm string) ([]*Group, error) {
	req, err := http.NewRequest(http.MethodGet, g.getAdminRealmURL(realm, "groups"), bytes.NewBufferString(""))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if err := g.checkForErrorsInResponse(response); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	userGroups := make([]*Group, 0)
	err = json.Unmarshal(body, &userGroups)
	return userGroups, err
}

func (g *gopherCloak) GetGroup(accessToken string, realm, groupID string) (*Group, error) {
	req, err := http.NewRequest(http.MethodGet, g.getAdminRealmURL(realm, "groups", groupID), bytes.NewBufferString(""))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if err := g.checkForErrorsInResponse(response); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	userGroup := new(Group)
	err = json.Unmarshal(body, userGroup)
	return userGroup, err
}

func (g *gopherCloak) GetGroupMembers(accessToken string, realm, groupID string) ([]*User, error) {
	req, err := http.NewRequest(http.MethodGet, g.getAdminRealmURL(realm, "groups", groupID, "members"), bytes.NewBufferString(""))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if err := g.checkForErrorsInResponse(response); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	users := make([]*User, 0)
	err = json.Unmarshal(body, &users)
	return users, err
}

func (g *gopherCloak) GetUserInfo(accessToken string, realm string) (*UserInfo, error) {
	panic("implement me")
}

func (g *gopherCloak) getAdminRealmURL(realm string, path ...string) string {
	path = append([]string{g.basePath, authAdminRealms, realm}, path...)
	return makeURL(path...)
}

func (g *gopherCloak) checkForErrorsInResponse(response *http.Response) error {
	if response == nil {
		return errors.New("no response")
	}
	if response.StatusCode >= 400 || response.StatusCode >= 500 {
		body, _ := io.ReadAll(response.Body)
		return fmt.Errorf("%s - %s", response.Status, string(body))
	}
	return nil
}

func getID(response *http.Response) string {
	header := response.Header.Get("Location")
	splittedPath := strings.Split(header, urlSeparator)
	return splittedPath[len(splittedPath)-1]
}

func (g *gopherCloak) LoginAdmin(username string, password string) (*Token, error) {
	req, _ := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/auth/realms/master/protocol/openid-connect/token", g.basePath),
		bytes.NewBufferString(fmt.Sprintf("username=%s&password=%s&client_id=admin-cli&grant_type=password", url.QueryEscape(username), url.QueryEscape(password))))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	response, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if err := g.checkForErrorsInResponse(response); err != nil {
		return nil, err
	}
	token := new(Token)
	err = json.Unmarshal(body, token)
	return token, err
}

func (g *gopherCloak) Login(username string, password string, realm string, clientId string, secret string) (*Token, error) {
	req, _ := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/auth/realms/%s/protocol/openid-connect/token", g.publicBasePath, realm),
		bytes.NewBufferString(fmt.Sprintf("username=%s&password=%s&client_id=%s&grant_type=password&client_secret=%s", url.QueryEscape(username), url.QueryEscape(password), url.QueryEscape(clientId), url.QueryEscape(secret))))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	response, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if err := g.checkForErrorsInResponse(response); err != nil {
		return nil, err
	}
	token := new(Token)
	err = json.Unmarshal(body, token)
	return token, err
}

func (g *gopherCloak) CreateUser(accessToken string, realm string, user User) (string, error) {
	userJson, err := json.Marshal(user)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, g.getAdminRealmURL(realm, "users"), bytes.NewBuffer(userJson))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if err := g.checkForErrorsInResponse(response); err != nil {
		return "", err
	}
	return getID(response), nil
}

func (g *gopherCloak) DeleteUser(accessToken string, realm, userID string) error {
	req, err := http.NewRequest(http.MethodDelete, g.getAdminRealmURL(realm, "users", userID), bytes.NewBufferString(""))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if err := g.checkForErrorsInResponse(response); err != nil {
		return err
	}
	return nil
}

func (g *gopherCloak) GetUserByID(accessToken string, realm string, userID string) (*User, error) {
	req, err := http.NewRequest(http.MethodGet, g.getAdminRealmURL(realm, "users", userID), bytes.NewBufferString(""))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if err := g.checkForErrorsInResponse(response); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	userModel := new(User)
	err = json.Unmarshal(body, userModel)
	if err != nil {
		return nil, err
	}

	return userModel, nil
}

func (g *gopherCloak) GetUserCount(accessToken string, realm string) (int, error) {
	panic("implement me")
}

func (g *gopherCloak) GetUsers(accessToken string, realm string, query string) ([]*User, error) {
	if len(query) > 0 && string(query[0]) != "?" {
		query = "?" + query
	}
	req, err := http.NewRequest("GET", g.getAdminRealmURL(realm, "users")+query, bytes.NewBufferString(""))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if err := g.checkForErrorsInResponse(response); err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	users := make([]*User, 0)

	err = json.Unmarshal(body, &users)
	if err != nil {
		return nil, err
	}
	return users, nil
}

func (g *gopherCloak) GetUserByUsername(accessToken string, realm string, username string) (*User, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s?username=%s", g.getAdminRealmURL(realm, "users"), username), bytes.NewBufferString(""))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if err := g.checkForErrorsInResponse(response); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	users := make([]*User, 0)
	err = json.Unmarshal(body, &users)
	if err != nil {
		return nil, err
	}
	if len(users) <= 0 {
		return nil, errors.New("not found")
	}
	return users[0], nil
}

func (g *gopherCloak) GetUserGroups(accessToken string, realm string, userID string) ([]*UserGroup, error) {
	req, err := http.NewRequest(http.MethodGet, g.getAdminRealmURL(realm, "users", userID, "groups"), bytes.NewBufferString(""))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if err := g.checkForErrorsInResponse(response); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	userGroups := make([]*UserGroup, 0)
	err = json.Unmarshal(body, &userGroups)
	if err != nil {
		return nil, err
	}

	return userGroups, nil
}

func (g *gopherCloak) GetUserEffectiveRealmRoles(accessToken string, realm string, userID string) ([]*UserRealmRoles, error) {
	req, err := http.NewRequest(http.MethodGet, g.getAdminRealmURL(realm, "users", userID, "role-mappings/realm/composite"), bytes.NewBufferString(""))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if err := g.checkForErrorsInResponse(response); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	userRealmRoles := make([]*UserRealmRoles, 0)
	err = json.Unmarshal(body, &userRealmRoles)
	if err != nil {
		return nil, err
	}

	return userRealmRoles, nil
}

func (g *gopherCloak) GetUserAvailableRealmRoles(accessToken string, realm string, userID string) ([]*UserRealmRoles, error) {
	req, err := http.NewRequest(http.MethodGet, g.getAdminRealmURL(realm, "users", userID, "role-mappings/realm/available"), bytes.NewBufferString(""))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if err := g.checkForErrorsInResponse(response); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	userRealmRoles := make([]*UserRealmRoles, 0)
	err = json.Unmarshal(body, &userRealmRoles)
	if err != nil {
		return nil, err
	}

	return userRealmRoles, nil
}

func (g *gopherCloak) AddUserEffectiveRealmRoles(accessToken string, realm string, userID string, roles []*UserRealmRoles) error {
	rolesJson, err := json.Marshal(roles)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, g.getAdminRealmURL(realm, "users", userID, "role-mappings/realm"), bytes.NewBuffer(rolesJson))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return g.checkForErrorsInResponse(response)
}

func (g *gopherCloak) DeleteUserEffectiveRealmRoles(accessToken string, realm string, userID string, roles []*UserRealmRoles) error {
	rolesJson, err := json.Marshal(roles)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodDelete, g.getAdminRealmURL(realm, "users", userID, "role-mappings/realm"), bytes.NewBuffer(rolesJson))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return g.checkForErrorsInResponse(response)
}

func (g *gopherCloak) GetUsersByRoleName(accessToken string, realm string, roleName string) ([]*User, error) {
	panic("implement me")
}

func (g *gopherCloak) GetUsersByClientRoleName(accessToken string, realm string, clientID string, roleName string, params GetUsersByRoleParams) ([]*User, error) {
	panic("implement me")
}

func (g *gopherCloak) SetPassword(accessToken string, userID string, realm string, password string, temporary bool) error {
	panic("implement me")
}

func (g *gopherCloak) UpdateUser(accessToken string, realm string, user User) error {
	userJson, err := json.Marshal(user)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPut, g.getAdminRealmURL(realm, "users", user.ID), bytes.NewBuffer(userJson))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if err := g.checkForErrorsInResponse(response); err != nil {
		return err
	}
	return nil
}

func (g *gopherCloak) AddUserToGroup(accessToken string, realm string, userID string, groupID string) error {
	req, err := http.NewRequest(http.MethodPut, g.getAdminRealmURL(realm, "users", userID, "groups", groupID), bytes.NewBufferString(""))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return g.checkForErrorsInResponse(response)
}

func (g *gopherCloak) DeleteUserFromGroup(accessToken string, realm string, userID string, groupID string) error {
	req, err := http.NewRequest(http.MethodDelete, g.getAdminRealmURL(realm, "users", userID, "groups", groupID), bytes.NewBufferString(""))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return g.checkForErrorsInResponse(response)
}

func (g *gopherCloak) GetUserSessions(token, realm, userID string) ([]*UserSessionRepresentation, error) {
	panic("implement me")
}

func (g *gopherCloak) GetUserOfflineSessionsForClient(token, realm, userID, clientID string) ([]*UserSessionRepresentation, error) {
	panic("implement me")
}

func (g *gopherCloak) LogoutAllUserSessions(accessToken string, realm string, userID string) error {
	req, err := http.NewRequest(http.MethodPost, g.getAdminRealmURL(realm, "users", userID, "logout"), bytes.NewBufferString(""))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if err := g.checkForErrorsInResponse(response); err != nil {
		return err
	}
	return nil
}

func (g *gopherCloak) GetEvents(accessToken string, realm, query string) ([]*Event, error) {
	if len(query) > 0 && string(query[0]) != "?" {
		query = "?" + query
	}
	req, err := http.NewRequest(http.MethodGet, g.getAdminRealmURL(realm, "events")+query, bytes.NewBufferString(""))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	events := make([]*Event, 0)
	err = json.Unmarshal(body, &events)
	if err != nil {
		return nil, err
	}

	return events, g.checkForErrorsInResponse(response)
}

// ===============
// Keycloak client
// ===============

// NewClient creates a new Client
func NewClient(basePath string, publicBasePath string, httpClient *http.Client) GophersCloak {
	c := gopherCloak{
		basePath:       strings.TrimRight(basePath, urlSeparator),
		publicBasePath: strings.TrimRight(publicBasePath, urlSeparator),
		certsCache:     make(map[string]*CertResponse),
	}
	c.httpClient = httpClient
	if httpClient == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.MaxIdleConns = 100
		t.MaxConnsPerHost = 100
		t.MaxIdleConnsPerHost = 100

		httpClient = &http.Client{
			Timeout:   10 * time.Second,
			Transport: t,
		}
		c.httpClient = httpClient
	}
	c.Config.CertsInvalidateTime = 60 * time.Minute

	return &c
}
