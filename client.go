package gopherscloak

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	urlSeparator string = "/"
)

var authAdminRealms = makeURL("admin", "realms")

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
		c.httpClient = setupHttpClient()
	}
	c.Config.CertsInvalidateTime = 60 * time.Minute

	return &c
}

func setupHttpClient() *http.Client {
	t := SafeTransport(10 * time.Second)
	t.MaxIdleConns = 100
	t.MaxConnsPerHost = 100
	t.MaxIdleConnsPerHost = 100

	return &http.Client{
		Timeout:   60 * time.Second,
		Transport: t,
	}
}

func IsDisallowedIP(hostIP string) bool {
	ip := net.ParseIP(hostIP)
	return ip.IsMulticast() || ip.IsUnspecified() || ip.IsLoopback()
}

func SafeTransport(timeout time.Duration) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := net.DialTimeout(network, addr, timeout)
			if err != nil {
				return nil, err
			}
			ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			if IsDisallowedIP(ip) {
				return nil, errors.New("ip address is not allowed")
			}
			return c, err
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: timeout}
			c, err := tls.DialWithDialer(dialer, network, addr, &tls.Config{})
			if err != nil {
				return nil, err
			}

			ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			if IsDisallowedIP(ip) {
				return nil, errors.New("ip address is not allowed")
			}

			err = c.Handshake()
			if err != nil {
				return c, err
			}

			return c, c.Handshake()
		},
		TLSHandshakeTimeout: timeout,
	}
}

func (g *gopherCloak) HealthCheck(realm string) error {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/realms/%s", g.basePath, realm), bytes.NewBufferString(""))
	if err != nil {
		return err
	}
	response, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	return g.checkForErrorsInResponse(response)
}

// DeleteAttackDetection Clear any user login failures for all users This can release temporary disabled users
func (g *gopherCloak) DeleteAttackDetection(accessToken string, realm string) error {
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/realms/%s/attack-detection/brute-force/users", g.basePath, realm), bytes.NewBufferString(""))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	return g.checkForErrorsInResponse(response)
}

// DeleteUserLoginFailures Clear any user login failures for all users This can release temporary disabled users
func (g *gopherCloak) DeleteUserLoginFailures(accessToken string, realm string, userId string) error {
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/realms/%s/attack-detection/brute-force/users/%s", g.basePath, realm, userId), bytes.NewBufferString(""))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	return g.checkForErrorsInResponse(response)
}

// GetAttackDetectionStatus Get status of the attack detection for a specific user
func (g *gopherCloak) GetAttackDetectionStatus(accessToken string, realm string, userId string) (map[interface{}]interface{}, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/realms/%s/attack-detection/brute-force/users/%s", g.basePath, realm, userId), bytes.NewBufferString(""))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	status := make(map[interface{}]interface{})
	err = json.Unmarshal(body, &status)
	return status, err
}

func (g *gopherCloak) GetOrganizations(accessToken string, realm string, query string) ([]Organization, error) {
	if len(query) > 0 && string(query[0]) != "?" {
		query = "?" + query
	}
	req, err := http.NewRequest("GET", g.getAdminRealmURL(realm, "organizations")+query, bytes.NewBufferString(""))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	organizations := make([]Organization, 0)
	err = json.Unmarshal(body, &organizations)
	if err != nil {
		return nil, err
	}
	return organizations, nil
}

func (g *gopherCloak) DeleteOrganization(accessToken string, realm string, organizationID string) error {
	req, err := http.NewRequest(http.MethodDelete, g.getAdminRealmURL(realm, "organizations", organizationID), bytes.NewBufferString(""))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	return g.checkForErrorsInResponse(response)
}

func (g *gopherCloak) UpdateOrganization(accessToken string, realm string, organization Organization) error {
	organizationJson, err := json.Marshal(organization)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPut, g.getAdminRealmURL(realm, "organizations", organization.ID), bytes.NewBuffer(organizationJson))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	return g.checkForErrorsInResponse(response)
}

func (g *gopherCloak) CreateOrganization(accessToken string, realm string, organization Organization) (string, error) {
	organizationJson, err := json.Marshal(organization)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, g.getAdminRealmURL(realm, "organizations"), bytes.NewBuffer(organizationJson))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return "", err
	}
	return getID(response), nil
}

func (g *gopherCloak) GetOrganization(accessToken string, realm string, organizationID string) (Organization, error) {
	req, err := http.NewRequest(http.MethodGet, g.getAdminRealmURL(realm, "organizations", organizationID), bytes.NewBufferString(""))
	if err != nil {
		return Organization{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return Organization{}, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return Organization{}, err
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return Organization{}, err
	}
	organization := Organization{}
	err = json.Unmarshal(body, &organization)
	if err != nil {
		return Organization{}, err
	}
	return organization, nil
}

func (g *gopherCloak) GetOrganizationIdentityProviders(accessToken string, realm string, organizationID string) ([]IdentityProvider, error) {
	req, err := http.NewRequest(http.MethodGet, g.getAdminRealmURL(realm, "organizations", organizationID, "identity-provider"), bytes.NewBufferString(""))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	idps := make([]IdentityProvider, 0)
	err = json.Unmarshal(body, &idps)
	if err != nil {
		return nil, err
	}
	return idps, nil
}

func (g *gopherCloak) DeleteOrganizationIdentityProvider(accessToken string, realm string, organizationID string, idpAlias string) error {
	req, err := http.NewRequest(http.MethodDelete, g.getAdminRealmURL(realm, "organizations", organizationID, "identity-provider", idpAlias), bytes.NewBufferString(""))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	return g.checkForErrorsInResponse(response)
}

func (g *gopherCloak) GetOrganizationIdentityProvider(accessToken string, realm string, organizationID string, idpAlias string) (IdentityProvider, error) {
	req, err := http.NewRequest(http.MethodGet, g.getAdminRealmURL(realm, "organizations", organizationID, "identity-provider", idpAlias), bytes.NewBufferString(""))
	if err != nil {
		return IdentityProvider{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return IdentityProvider{}, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return IdentityProvider{}, err
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return IdentityProvider{}, err
	}
	idp := IdentityProvider{}
	err = json.Unmarshal(body, &idp)
	if err != nil {
		return IdentityProvider{}, err
	}
	return idp, nil
}

func (g *gopherCloak) AddOrganizationIdentityProvider(accessToken string, realm string, organizationID string, idpAlias string) error {
	req, err := http.NewRequest(http.MethodPost, g.getAdminRealmURL(realm, "organizations", organizationID, "identity-provider"), bytes.NewBufferString(idpAlias))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	return g.checkForErrorsInResponse(response)
}

func (g *gopherCloak) GetOrganizationMemberCount(accessToken string, realm string, organizationID string) (int64, error) {
	req, err := http.NewRequest(http.MethodGet, g.getAdminRealmURL(realm, "organizations", organizationID, "members/count"), bytes.NewBufferString(""))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return 0, err
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, err
	}
	var count int64
	err = json.Unmarshal(body, &count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (g *gopherCloak) GetOrganizationMembers(accessToken string, realm string, organizationID string, query string) ([]Member, error) {
	if len(query) > 0 && string(query[0]) != "?" {
		query = "?" + query
	}
	req, err := http.NewRequest("GET", g.getAdminRealmURL(realm, "organizations", organizationID, "members")+query, bytes.NewBufferString(""))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	members := make([]Member, 0)
	err = json.Unmarshal(body, &members)
	if err != nil {
		return nil, err
	}
	return members, nil
}

func (g *gopherCloak) DeleteOrganizationMember(accessToken string, realm string, organizationID string, memberID string) error {
	req, err := http.NewRequest(http.MethodDelete, g.getAdminRealmURL(realm, "organizations", organizationID, "members", memberID), bytes.NewBufferString(""))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	return g.checkForErrorsInResponse(response)
}

func (g *gopherCloak) GetOrganizationMember(accessToken string, realm string, organizationID string, memberID string) (Member, error) {
	req, err := http.NewRequest(http.MethodGet, g.getAdminRealmURL(realm, "organizations", organizationID, "members", memberID), bytes.NewBufferString(""))
	if err != nil {
		return Member{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return Member{}, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return Member{}, err
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return Member{}, err
	}
	member := Member{}
	err = json.Unmarshal(body, &member)
	if err != nil {
		return Member{}, err
	}
	return member, nil
}

func (g *gopherCloak) GetOrganizationMemberOrganizations(accessToken string, realm string, organizationID string, memberID string) ([]Organization, error) {
	req, err := http.NewRequest(http.MethodGet, g.getAdminRealmURL(realm, "organizations", organizationID, "members", memberID, "organizations"), bytes.NewBufferString(""))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	organizations := make([]Organization, 0)
	err = json.Unmarshal(body, &organizations)
	if err != nil {
		return nil, err
	}
	return organizations, nil
}

func (g *gopherCloak) OrganizationInviteMember(accessToken string, realm string, organizationID string, member OrganizationInvite) error {
	memberJson, err := json.Marshal(member)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, g.getAdminRealmURL(realm, "organizations", organizationID, "members"), bytes.NewBuffer(memberJson))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	return g.checkForErrorsInResponse(response)
}

func (g *gopherCloak) OrganizationAddMember(accessToken string, realm string, organizationID string, memberId string) error {
	req, err := http.NewRequest(http.MethodPost, g.getAdminRealmURL(realm, "organizations", organizationID, "members"), bytes.NewBufferString(memberId))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	return g.checkForErrorsInResponse(response)
}

func (g *gopherCloak) GetGroups(accessToken string, realm string) ([]Group, error) {
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
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	userGroups := make([]Group, 0)
	err = json.Unmarshal(body, &userGroups)
	return userGroups, err
}

func (g *gopherCloak) GetGroup(accessToken string, realm, groupID string) (Group, error) {
	req, err := http.NewRequest(http.MethodGet, g.getAdminRealmURL(realm, "groups", groupID), bytes.NewBufferString(""))
	if err != nil {
		return Group{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return Group{}, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return Group{}, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return Group{}, err
	}
	userGroup := Group{}
	err = json.Unmarshal(body, &userGroup)
	return userGroup, err
}

func (g *gopherCloak) GetGroupMembers(accessToken string, realm, groupID string) ([]User, error) {
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
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	users := make([]User, 0)
	err = json.Unmarshal(body, &users)
	return users, err
}

func (g *gopherCloak) GetUserInfo(accessToken string, realm string) (UserInfo, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo", g.publicBasePath, realm), bytes.NewBufferString(""))
	if err != nil {
		return UserInfo{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return UserInfo{}, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return UserInfo{}, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return UserInfo{}, err
	}
	userInfo := UserInfo{}
	err = json.Unmarshal(body, &userInfo)
	return userInfo, err
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

func (g *gopherCloak) LoginAdmin(username string, password string) (Token, error) {
	req, _ := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/realms/master/protocol/openid-connect/token", g.basePath),
		bytes.NewBufferString(fmt.Sprintf("username=%s&password=%s&client_id=admin-cli&grant_type=password", url.QueryEscape(username), url.QueryEscape(password))))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	response, err := g.httpClient.Do(req)
	if err != nil {
		return Token{}, err
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return Token{}, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return Token{}, err
	}
	token := Token{}
	err = json.Unmarshal(body, &token)
	return token, err
}

func (g *gopherCloak) Login(username string, password string, realm string, clientId string, secret string, grantType string) (Token, error) {
	if grantType == "" {
		grantType = "password"
	}
	req, _ := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", g.publicBasePath, realm),
		bytes.NewBufferString(fmt.Sprintf("username=%s&password=%s&client_id=%s&grant_type=%s&client_secret=%s", url.QueryEscape(username), url.QueryEscape(password), url.QueryEscape(clientId), url.QueryEscape(grantType), url.QueryEscape(secret))))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	response, err := g.httpClient.Do(req)
	if err != nil {
		return Token{}, err
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return Token{}, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return Token{}, err
	}
	token := Token{}
	err = json.Unmarshal(body, &token)
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
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
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
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return err
	}
	return nil
}

func (g *gopherCloak) GetUserByID(accessToken string, realm string, userID string) (User, error) {
	req, err := http.NewRequest(http.MethodGet, g.getAdminRealmURL(realm, "users", userID), bytes.NewBufferString(""))
	if err != nil {
		return User{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return User{}, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return User{}, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return User{}, err
	}
	userModel := User{}
	err = json.Unmarshal(body, &userModel)
	if err != nil {
		return User{}, err
	}

	return userModel, nil
}

func (g *gopherCloak) GetUserCount(accessToken string, realm string) (int, error) {
	panic("implement me")
}

func (g *gopherCloak) GetUsers(accessToken string, realm string, query string) ([]User, error) {
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
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	users := make([]User, 0)

	err = json.Unmarshal(body, &users)
	if err != nil {
		return nil, err
	}
	return users, nil
}

func (g *gopherCloak) GetUserByUsername(accessToken string, realm string, username string) (User, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s?username=%s", g.getAdminRealmURL(realm, "users"), username), bytes.NewBufferString(""))
	if err != nil {
		return User{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return User{}, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return User{}, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return User{}, err
	}
	users := make([]User, 0)
	err = json.Unmarshal(body, &users)
	if err != nil {
		return User{}, err
	}
	if len(users) <= 0 {
		return User{}, errors.New("not found")
	}
	return users[0], nil
}

func (g *gopherCloak) GetUserGroups(accessToken string, realm string, userID string) ([]UserGroup, error) {
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
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	userGroups := make([]UserGroup, 0)
	err = json.Unmarshal(body, &userGroups)
	if err != nil {
		return nil, err
	}

	return userGroups, nil
}

func (g *gopherCloak) GetUserEffectiveRealmRoles(accessToken string, realm string, userID string) ([]UserRealmRoles, error) {
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
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	userRealmRoles := make([]UserRealmRoles, 0)
	err = json.Unmarshal(body, &userRealmRoles)
	if err != nil {
		return nil, err
	}

	return userRealmRoles, nil
}

func (g *gopherCloak) GetUserAvailableRealmRoles(accessToken string, realm string, userID string) ([]UserRealmRoles, error) {
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
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	userRealmRoles := make([]UserRealmRoles, 0)
	err = json.Unmarshal(body, &userRealmRoles)
	if err != nil {
		return nil, err
	}

	return userRealmRoles, nil
}

func (g *gopherCloak) AddUserEffectiveRealmRoles(accessToken string, realm string, userID string, roles []UserRealmRoles) error {
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
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	return g.checkForErrorsInResponse(response)
}

func (g *gopherCloak) DeleteUserEffectiveRealmRoles(accessToken string, realm string, userID string, roles []UserRealmRoles) error {
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
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	return g.checkForErrorsInResponse(response)
}

func (g *gopherCloak) SetPassword(accessToken string, userID string, realm string, password string, temporary bool) error {
	credential := Credential{
		Temporary: temporary,
		Type:      "password",
		Value:     password,
	}
	credentialJson, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPut, g.getAdminRealmURL(realm, "users", userID, "reset-password"), bytes.NewBuffer(credentialJson))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return err
	}
	return nil
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
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
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
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	return g.checkForErrorsInResponse(response)
}

func (g *gopherCloak) CountUsers(accessToken string, realm string, query string) (int64, error) {
	if len(query) > 0 && string(query[0]) != "?" {
		query = "?" + query
	}
	req, err := http.NewRequest("GET", g.getAdminRealmURL(realm, "users/count")+query, bytes.NewBufferString(""))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return 0, err
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, err
	}
	var count int64
	err = json.Unmarshal(body, &count)
	if err != nil {
		return 0, err
	}
	return count, nil
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
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	return g.checkForErrorsInResponse(response)
}

func (g *gopherCloak) GetUserSessions(token, realm, userID string) ([]UserSession, error) {
	panic("implement me")
}

func (g *gopherCloak) GetUserOfflineSessionsForClient(token, realm, userID, clientID string) ([]UserSession, error) {
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
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	if err := g.checkForErrorsInResponse(response); err != nil {
		return err
	}
	return nil
}

func (g *gopherCloak) TriggerEmailAction(accessToken string, realm string, userId string, actions []string) error {
	actionsJson, _ := json.Marshal(actions)

	req, err := http.NewRequest(http.MethodPut, g.getAdminRealmURL(realm, "users", userId, "execute-actions-email"), bytes.NewBuffer(actionsJson))
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Content-Type", "application/json")

	response, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)

	if err := g.checkForErrorsInResponse(response); err != nil {
		return err
	}
	return nil
}

func (g *gopherCloak) SendVerificationEmail(accessToken string, realm string, userId string, query string) error {
	if len(query) > 0 && string(query[0]) != "?" {
		query = "?" + query
	}
	req, err := http.NewRequest(http.MethodPut, g.getAdminRealmURL(realm, "users", userId, "send-verify-email")+query, bytes.NewBufferString(""))
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Content-Type", "application/json")

	response, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)

	if err := g.checkForErrorsInResponse(response); err != nil {
		return err
	}
	return nil
}

func (g *gopherCloak) GetEvents(accessToken string, realm, query string) ([]Event, error) {
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
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	body, _ := io.ReadAll(response.Body)
	events := make([]Event, 0)
	err = json.Unmarshal(body, &events)
	if err != nil {
		return nil, err
	}

	return events, g.checkForErrorsInResponse(response)
}

func (g *gopherCloak) GetIdpToken(accessToken string, realm string, idpAlias string) (Token, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/realms/%s/broker/%s/token", g.basePath, realm, idpAlias), bytes.NewBufferString(""))
	if err != nil {
		return Token{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return Token{}, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)
	body, _ := io.ReadAll(response.Body)
	token := Token{}
	err = json.Unmarshal(body, &token)
	if err != nil {
		return Token{}, err
	}

	return token, g.checkForErrorsInResponse(response)
}

func (g *gopherCloak) GetRealmRoles(accessToken string, realm string, query string) ([]Role, error) {
	if len(query) > 0 && string(query[0]) != "?" {
		query = "?" + query
	}
	req, err := http.NewRequest("GET", g.getAdminRealmURL(realm, "roles")+query, bytes.NewBufferString(""))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	roles := make([]Role, 0)
	err = json.Unmarshal(body, &roles)
	if err != nil {
		return nil, err
	}

	return roles, g.checkForErrorsInResponse(response)
}

func (g *gopherCloak) GetClientRoles(accessToken string, realm string, clientID string, query string) ([]Role, error) {
	if len(query) > 0 && string(query[0]) != "?" {
		query = "?" + query
	}
	req, err := http.NewRequest("GET", g.getAdminRealmURL(realm, "clients", clientID, "roles")+query, bytes.NewBufferString(""))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	roles := make([]Role, 0)
	err = json.Unmarshal(body, &roles)
	if err != nil {
		return nil, err
	}

	return roles, g.checkForErrorsInResponse(response)
}

func (g *gopherCloak) CreateRealmRole(accessToken string, realm string, role Role) (string, error) {
	roleJson, err := json.Marshal(role)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, g.getAdminRealmURL(realm, "roles"), bytes.NewBuffer(roleJson))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	response, err := g.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)

	if err := g.checkForErrorsInResponse(response); err != nil {
		return "", err
	}
	return getID(response), nil
}

func (g *gopherCloak) CreateClientRole(accessToken string, realm string, clientID string, role Role) (string, error) {
	roleJson, err := json.Marshal(role)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, g.getAdminRealmURL(realm, "clients", clientID, "roles"), bytes.NewBuffer(roleJson))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	response, err := g.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)

	if err := g.checkForErrorsInResponse(response); err != nil {
		return "", err
	}
	return getID(response), nil
}

func (g *gopherCloak) GetClientRolesCompositesRoles(accessToken string, realm string, clientID string, roleName string, query string) ([]Role, error) {
	if len(query) > 0 && string(query[0]) != "?" {
		query = "?" + query
	}
	req, err := http.NewRequest("GET", g.getAdminRealmURL(realm, "clients", clientID, "roles", roleName, "composites", "clients", clientID)+query, bytes.NewBufferString(""))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	roles := make([]Role, 0)
	err = json.Unmarshal(body, &roles)
	if err != nil {
		return nil, err
	}

	return roles, g.checkForErrorsInResponse(response)
}

func (g *gopherCloak) DeleteRoleFromRealmComposite(accessToken string, realm string, roleName string, roles []Role) error {
	rolesJson, err := json.Marshal(roles)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodDelete, g.getAdminRealmURL(realm, "roles", roleName, "composites"), bytes.NewBuffer(rolesJson))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	response, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)

	return g.checkForErrorsInResponse(response)
}

func (g *gopherCloak) DeleteRoleFromClientComposite(accessToken string, realm string, clientID string, roleName string, roles []Role) error {
	rolesJson, err := json.Marshal(roles)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodDelete, g.getAdminRealmURL(realm, "clients", clientID, "roles", roleName, "composites"), bytes.NewBuffer(rolesJson))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	response, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)

	return g.checkForErrorsInResponse(response)
}

func (g *gopherCloak) GetRolesComposites(accessToken string, realm string, roleName string) ([]Role, error) {
	req, err := http.NewRequest(http.MethodGet, g.getAdminRealmURL(realm, "roles", roleName, "composites"), bytes.NewBufferString(""))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	response, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	roles := make([]Role, 0)
	err = json.Unmarshal(body, &roles)
	if err != nil {
		return nil, err
	}

	return roles, g.checkForErrorsInResponse(response)
}

func (g *gopherCloak) AddCompositesToRole(accessToken string, realm string, roleName string, role Role) error {
	roleJson, err := json.Marshal(role)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, g.getAdminRealmURL(realm, "roles", roleName, "composites"), bytes.NewBuffer(roleJson))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	response, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(response.Body)

	return g.checkForErrorsInResponse(response)
}
