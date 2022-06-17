package gopherscloak

// User represents the Keycloak User Structure
type User struct {
	ID                         string                      `json:"id,omitempty"`
	CreatedTimestamp           int64                       `json:"createdTimestamp,omitempty"`
	Username                   string                      `json:"username,omitempty"`
	Enabled                    bool                        `json:"enabled"`
	Totp                       bool                        `json:"totp"`
	EmailVerified              bool                        `json:"emailVerified"`
	FirstName                  string                      `json:"firstName,omitempty"`
	LastName                   string                      `json:"lastName,omitempty"`
	Email                      string                      `json:"email,omitempty"`
	FederationLink             string                      `json:"federationLink,omitempty"`
	Attributes                 map[string][]string         `json:"attributes,omitempty"`
	DisableableCredentialTypes []interface{}               `json:"disableableCredentialTypes,omitempty"`
	RequiredActions            []string                    `json:"requiredActions,omitempty"`
	NotBefore                  int64                       `json:"notBefore,omitempty"`
	Access                     map[string]bool             `json:"access"`
	ClientRoles                map[string][]string         `json:"clientRoles,omitempty"`
	RealmRoles                 []string                    `json:"realmRoles,omitempty"`
	ServiceAccountClientID     string                      `json:"serviceAccountClientId,omitempty"`
	Credentials                []*CredentialRepresentation `json:"credentials,omitempty"`
}

// CredentialRepresentation represents credentials
type CredentialRepresentation struct {
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
	BriefRepresentation bool   `json:"briefRepresentation,string"`
	Email               string `json:"email,omitempty"`
	First               int    `json:"first,string,omitempty"`
	FirstName           string `json:"firstName,omitempty"`
	LastName            string `json:"lastName,omitempty"`
	Max                 int    `json:"max,string,omitempty"`
	Search              string `json:"search,omitempty"`
	Username            string `json:"username,omitempty"`
}

// UserGroup is a UserGroup
type UserGroup struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Path string `json:"path,omitempty"`
}

// GetUsersByRoleParams represents the optional parameters for getting users by role
type GetUsersByRoleParams struct {
	First int `json:"first,string,omitempty"`
	Max   int `json:"max,string,omitempty"`
}

// UserSessionRepresentation represents a list of user's sessions
type UserSessionRepresentation struct {
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
	Keys []*CertResponseKey `json:"keys,omitempty"`
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
	ID          string              `json:"id,omitempty"`
	Name        string              `json:"name,omitempty"`
	Path        string              `json:"path,omitempty"`
	SubGroups   []*Group            `json:"subGroups,omitempty"`
	Attributes  map[string][]string `json:"attributes,omitempty"`
	Access      map[string]bool     `json:"access,omitempty"`
	ClientRoles map[string][]string `json:"clientRoles,omitempty"`
	RealmRoles  []string            `json:"realmRoles,omitempty"`
}

type Event struct {
	Time      int64  `json:"time"`
	Type      string `json:"type"`
	RealmId   string `json:"realmId"`
	ClientId  string `json:"clientId"`
	UserId    string `json:"userId"`
	SessionId string `json:"sessionId"`
	IpAddress string `json:"ipAddress"`
	Details   string `json:"details"`
}
