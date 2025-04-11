package gopherscloak

// User represents the Keycloak User Structure
type User struct {
	ID                         string              `json:"id,omitempty"`
	CreatedTimestamp           int64               `json:"createdTimestamp,omitempty"`
	Username                   string              `json:"username,omitempty"`
	Enabled                    bool                `json:"enabled"`
	Totp                       bool                `json:"totp"`
	EmailVerified              bool                `json:"emailVerified"`
	FirstName                  string              `json:"firstName,omitempty"`
	LastName                   string              `json:"lastName,omitempty"`
	Email                      string              `json:"email,omitempty"`
	FederationLink             string              `json:"federationLink,omitempty"`
	Attributes                 map[string][]string `json:"attributes,omitempty"`
	DisableableCredentialTypes []interface{}       `json:"disableableCredentialTypes,omitempty"`
	RequiredActions            []string            `json:"requiredActions,omitempty"`
	NotBefore                  int64               `json:"notBefore,omitempty"`
	Access                     map[string]bool     `json:"access"`
	ClientRoles                map[string][]string `json:"clientRoles,omitempty"`
	RealmRoles                 []string            `json:"realmRoles,omitempty"`
	ServiceAccountClientID     string              `json:"serviceAccountClientId,omitempty"`
	Credentials                []Credential        `json:"credentials,omitempty"`
}

// Credential represents credentials
type Credential struct {
	Algorithm         string              `json:"algorithm,omitempty"`
	Config            *MultiValuedHashMap `json:"config,omitempty"`
	Counter           int32               `json:"counter,omitempty"`
	CreatedDate       int64               `json:"createdDate,omitempty"`
	Device            string              `json:"device,omitempty"`
	Digits            int32               `json:"digits,omitempty"`
	HashIterations    int32               `json:"hashIterations,omitempty"`
	HashedSaltedValue string              `json:"hashedSaltedValue,omitempty"`
	Period            int32               `json:"period,omitempty"`
	Salt              string              `json:"salt,omitempty"`
	Temporary         bool                `json:"temporary"`
	Type              string              `json:"type,omitempty"`
	Value             string              `json:"value,omitempty"`
}

// MultiValuedHashMap represents something
type MultiValuedHashMap struct {
	Empty      bool    `json:"empty"`
	LoadFactor float32 `json:"loadFactor,omitempty"`
	Threshold  int32   `json:"threshold,omitempty"`
}

// GetUsersParams represents the optional parameters for getting users
type GetUsersParams struct {
	Brief     bool   `json:"brief,string"`
	Email     string `json:"email,omitempty"`
	First     int    `json:"first,string,omitempty"`
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
	Max       int    `json:"max,string,omitempty"`
	Search    string `json:"search,omitempty"`
	Username  string `json:"username,omitempty"`
}

// UserGroup is a UserGroup
type UserGroup struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Path string `json:"path,omitempty"`
}

// UserRealmRoles represents the Effective Realm Roles
type UserRealmRoles struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// GetUsersByRoleParams represents the optional parameters for getting users by role
type GetUsersByRoleParams struct {
	First int `json:"first,string,omitempty"`
	Max   int `json:"max,string,omitempty"`
}

// UserSession represents a list of user's sessions
type UserSession struct {
	Clients    map[string]string `json:"clients,omitempty"`
	ID         string            `json:"id,omitempty"`
	IPAddress  string            `json:"ipAddress,omitempty"`
	LastAccess int64             `json:"lastAccess,omitempty"`
	Start      int64             `json:"start,omitempty"`
	UserID     string            `json:"userId,omitempty"`
	Username   string            `json:"username,omitempty"`
}

// CertResponseKey is returned by the certs endpoint
type CertResponseKey struct {
	Kid *string `json:"kid,omitempty"`
	Kty *string `json:"kty,omitempty"`
	Alg *string `json:"alg,omitempty"`
	Use *string `json:"use,omitempty"`
	N   *string `json:"n,omitempty"`
	E   *string `json:"e,omitempty"`
}

// CertResponse is returned by the certs endpoint
type CertResponse struct {
	Keys []CertResponseKey `json:"keys,omitempty"`
}

// Token
type Token struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
	TokenType        string `json:"token_type"`
}

// UserInfo is returned by the userinfo endpoint
type UserInfo struct {
	Sub               string      `json:"sub,omitempty"`
	EmailVerified     bool        `json:"email_verified"`
	Address           interface{} `json:"address,omitempty"`
	PreferredUsername string      `json:"preferred_username,omitempty"`
	Email             string      `json:"email,omitempty"`
}

// Group is a Group
type Group struct {
	ID            string              `json:"id,omitempty"`
	Name          string              `json:"name,omitempty"`
	Path          string              `json:"path,omitempty"`
	SubGroups     []Group             `json:"subGroups,omitempty"`
	SubGroupCount int                 `json:"subGroupCount,omitempty"`
	Attributes    map[string][]string `json:"attributes,omitempty"`
	Access        map[string]bool     `json:"access,omitempty"`
	ClientRoles   map[string][]string `json:"clientRoles,omitempty"`
	RealmRoles    []string            `json:"realmRoles,omitempty"`
}

type Event struct {
	Time      int64        `json:"time"`
	Type      string       `json:"type"`
	RealmId   string       `json:"realmId"`
	ClientId  string       `json:"clientId"`
	UserId    string       `json:"userId"`
	SessionId string       `json:"sessionId"`
	IpAddress string       `json:"ipAddress"`
	Details   EventDetails `json:"details"`
}

type EventDetails struct {
	Action   string `json:"action"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

type Organization struct {
	ID                string               `json:"id,omitempty"`
	Name              string               `json:"name,omitempty"`
	Alias             string               `json:"alias,omitempty"`
	Enabled           bool                 `json:"enabled"`
	Description       string               `json:"description,omitempty"`
	RedirectUrl       string               `json:"redirectUrl,omitempty"`
	Attributes        map[string][]string  `json:"attributes,omitempty"`
	Domains           []OrganizationDomain `json:"domains"`
	Members           []Member             `json:"members"`
	IdentityProviders []IdentityProvider   `json:"identityProviders"`
}

type OrganizationInvite struct {
	Email     string `json:"email,omitempty"`
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
}

type OrganizationDomain struct {
	Name     string `json:"name,omitempty"`
	Verified bool   `json:"verified"`
}

type Member struct {
	ID                         string                 `json:"id,omitempty"`
	Username                   string                 `json:"username,omitempty"`
	FirstName                  string                 `json:"firstName,omitempty"`
	LastName                   string                 `json:"lastName,omitempty"`
	Email                      string                 `json:"email,omitempty"`
	EmailVerified              bool                   `json:"emailVerified"`
	Attributes                 map[string][]string    `json:"attributes,omitempty"`
	Self                       string                 `json:"self,omitempty"`
	Origin                     string                 `json:"origin,omitempty"`
	CreatedTimestamp           int64                  `json:"createdTimestamp,omitempty"`
	Enabled                    bool                   `json:"enabled"`
	Totp                       bool                   `json:"totp"`
	FederationLink             string                 `json:"federationLink,omitempty"`
	ServiceAccountClientID     string                 `json:"serviceAccountClientId,omitempty"`
	Credentials                []Credential           `json:"credentials,omitempty"`
	DisableableCredentialTypes []string               `json:"disableableCredentialTypes,omitempty"`
	RequiredActions            []string               `json:"requiredActions,omitempty"`
	FederatedIdentities        []FederatedIdentity    `json:"federatedIdentities,omitempty"`
	RealmRoles                 []string               `json:"realmRoles,omitempty"`
	ClientRoles                map[string][]string    `json:"clientRoles,omitempty"`
	ClientConsents             map[string]UserConsent `json:"clientConsents,omitempty"`
	NotBefore                  int64                  `json:"notBefore,omitempty"`
	ApplicationRoles           map[string][]string    `json:"applicationRoles,omitempty"`
	SocialLinks                []SocialLink           `json:"socialLinks,omitempty"`
	Groups                     []string               `json:"groups,omitempty"`
	Access                     map[string]bool        `json:"access,omitempty"`
}

type IdentityProvider struct {
	Alias                       string            `json:"alias,omitempty"`
	DisplayName                 string            `json:"displayName,omitempty"`
	InternalId                  string            `json:"internalId,omitempty"`
	ProviderId                  string            `json:"providerId,omitempty"`
	Enabled                     bool              `json:"enabled"`
	UpdateProfileFirstLoginMode string            `json:"updateProfileFirstLoginMode,omitempty"`
	TrustEmail                  bool              `json:"trustEmail"`
	StoreToken                  bool              `json:"storeToken"`
	AddReadTokenRoleOnCreate    bool              `json:"addReadTokenRoleOnCreate"`
	AuthenticateByDefault       bool              `json:"authenticateByDefault"`
	LinkOnly                    bool              `json:"linkOnly"`
	HideOnLoginPage             bool              `json:"hideOnLoginPage"`
	FirstBrokerLoginFlowAlias   string            `json:"firstBrokerLoginFlowAlias,omitempty"`
	PostBrokerLoginFlowAlias    string            `json:"postBrokerLoginFlowAlias,omitempty"`
	OrganisationId              string            `json:"organisationId,omitempty"`
	Config                      map[string]string `json:"config,omitempty"`
	UpdateProfileFirstLogin     bool              `json:"updateProfileFirstLogin"`
}

type FederatedIdentity struct {
	IdentityProvider string `json:"identityProvider,omitempty"`
	UserId           string `json:"userId,omitempty"`
	UserName         string `json:"userName,omitempty"`
}

type UserConsent struct {
	ClientId            string   `json:"clientId,omitempty"`
	GrantedClientScopes []string `json:"grantedClientScopes,omitempty"`
	CreatedDate         int64    `json:"createdDate,omitempty"`
	LastUpdatedDate     int64    `json:"lastUpdatedDate,omitempty"`
	GrantedRealmRoles   []string `json:"grantedRealmRoles,omitempty"`
}

type SocialLink struct {
	SocialProvider string `json:"socialProvider,omitempty"`
	SocialUserId   string `json:"socialUserId,omitempty"`
	SocialUsername string `json:"socialUsername,omitempty"`
}

type Role struct {
	ID                 string            `json:"id,omitempty"`
	Name               string            `json:"name,omitempty"`
	Description        string            `json:"description,omitempty"`
	ScopeParamRequired bool              `json:"scopeParamRequired"`
	Composite          bool              `json:"composite"`
	ClientRole         bool              `json:"clientRole"`
	ContainerID        string            `json:"containerId,omitempty"`
	Attributes         map[string]string `json:"attributes,omitempty"`
}

type Roles struct {
	RealmRoles       []Role            `json:"realm,omitempty"`
	ClientRoles      map[string][]Role `json:"client,omitempty"`
	ApplicationRoles map[string][]Role `json:"application,omitempty"`
}
