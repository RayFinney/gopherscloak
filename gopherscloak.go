package gopherscloak

type GophersCloak interface {
	// HealthCheck checks if the server is up and running
	HealthCheck(realm string) error

	// DeleteAttackDetection Clear any user login failures for all users This can release temporary disabled users
	DeleteAttackDetection(realm string) error
	// DeleteUserLoginFailures Clear any user login failures for all users This can release temporary disabled users
	DeleteUserLoginFailures(realm string, userId string) error
	// GetAttackDetectionStatus Get status of the attack detection for a specific user
	GetAttackDetectionStatus(realm string, userId string) (map[interface{}]interface{}, error)

	// GetOrganizations gets all organizations
	GetOrganizations(accessToken string, realm string, query string) ([]Organization, error)
	// DeleteOrganization deletes the given organization
	DeleteOrganization(accessToken string, realm string, organizationID string) error
	// GetOrganization gets the organization with the given id
	GetOrganization(accessToken string, realm string, organizationID string) (Organization, error)
	// UpdateOrganization updates the given organization
	UpdateOrganization(accessToken string, realm string, organization Organization) error
	// CreateOrganization creates a new organization
	CreateOrganization(accessToken string, realm string, organization Organization) (string, error)
	// GetOrganizationIdentityProviders gets all identity providers of the given organization
	GetOrganizationIdentityProviders(accessToken string, realm string, organizationID string) ([]IdentityProvider, error)
	// DeleteOrganizationIdentityProvider deletes the given identity provider of the given organization
	DeleteOrganizationIdentityProvider(accessToken string, realm string, organizationID string, idpAlias string) error
	// GetOrganizationIdentityProvider gets the identity provider with the given id of the given organization
	GetOrganizationIdentityProvider(accessToken string, realm string, organizationID string, idpAlias string) (IdentityProvider, error)
	// AddOrganizationIdentityProvider Adds the identity provider with the specified id to the organization
	AddOrganizationIdentityProvider(accessToken string, realm string, organizationID string, idpAlias string) error
	// GetOrganizationMemberCount gets the number of members of the given organization
	GetOrganizationMemberCount(accessToken string, realm string, organizationID string) (int64, error)
	// GetOrganizationMembers gets all members of the given organization
	GetOrganizationMembers(accessToken string, realm string, organizationID string, query string) ([]Member, error)
	// DeleteOrganizationMember deletes the given member of the given organization
	DeleteOrganizationMember(accessToken string, realm string, organizationID string, memberID string) error
	// GetOrganizationMember gets the member with the given id of the given organization
	GetOrganizationMember(accessToken string, realm string, organizationID string, memberID string) (Member, error)
	// GetOrganizationMemberOrganizations gets all organizations of the given member of the given organization
	GetOrganizationMemberOrganizations(accessToken string, realm string, organizationID string, memberID string) ([]Organization, error)
	// OrganizationInviteMember Invites an existing user or sends a registration link to a new user, based on the provided e-mail address.
	OrganizationInviteMember(accessToken string, realm string, organizationID string, member OrganizationInvite) error
	// OrganizationAddMember adds a new member to the given organization
	OrganizationAddMember(accessToken string, realm string, organizationID string, memberId string) error

	// LoginAdmin logs in the admin user against basePath not publicBasePath
	LoginAdmin(username string, password string) (Token, error)
	// Login logs in the user against publicBasePath
	Login(username string, password string, realm string, clientId string, secret string, grantType string) (Token, error)

	// CreateUser creates a new user
	CreateUser(accessToken string, realm string, user User) (string, error)
	// DeleteUser deletes the given user
	DeleteUser(accessToken string, realm, userID string) error
	// GetUserByID gets the user with the given id
	GetUserByID(accessToken string, realm string, userID string) (User, error)
	// GetUserByUsername gets the user with the given username
	GetUserByUsername(accessToken string, realm string, username string) (User, error)
	// GetUsers gets all users of the given realm
	GetUsers(accessToken string, realm string, query string) ([]User, error)
	// GetUserGroups gets the groups of the given user
	GetUserGroups(accessToken string, realm string, userID string) ([]UserGroup, error)
	// GetUserEffectiveRealmRoles gets effective realm-level role mappings. This will recurse all composite roles to get the result.
	GetUserEffectiveRealmRoles(accessToken string, realm string, userID string) ([]UserRealmRoles, error)
	// GetUserAvailableRealmRoles gets available realm-level role mappings. This will recurse all composite roles to get the result.
	GetUserAvailableRealmRoles(accessToken string, realm string, userID string) ([]UserRealmRoles, error)
	// AddUserEffectiveRealmRoles adds effective realm-level role mappings to the user
	AddUserEffectiveRealmRoles(accessToken string, realm string, userID string, roles []UserRealmRoles) error
	//DeleteUserEffectiveRealmRoles adds effective realm-level role mappings to the user
	DeleteUserEffectiveRealmRoles(accessToken string, realm string, userID string, roles []UserRealmRoles) error
	// SetPassword sets a new password for the user with the given id. Needs elevated privileges
	SetPassword(accessToken string, userID string, realm string, password string, temporary bool) error
	// UpdateUser updates the given user
	UpdateUser(accessToken string, realm string, user User) error
	// AddUserToGroup puts given user to given group
	AddUserToGroup(accessToken string, realm string, userID string, groupID string) error
	// CountUsers Returns the number of users that match the given criteria.
	CountUsers(accessToken string, realm string, query string) (int64, error)
	// DeleteUserFromGroup deletes given user from given group
	DeleteUserFromGroup(accessToken string, realm string, userID string, groupID string) error
	// GetUserSessions returns user sessions associated with the user
	GetUserSessions(token, realm, userID string) ([]UserSession, error)
	// GetUserOfflineSessionsForClient returns offline sessions associated with the user and client
	GetUserOfflineSessionsForClient(token, realm, userID, clientID string) ([]UserSession, error)
	// GetUserInfo gets the user info for the given realm
	GetUserInfo(accessToken string, realm string) (UserInfo, error)
	// LogoutAllUserSessions log out all current user sessions
	LogoutAllUserSessions(accessToken string, realm string, userID string) error
	// TriggerEmailAction triggers an email action for the user
	TriggerEmailAction(accessToken string, realm string, userId string, actions []string) error
	// SendVerificationEmail triggers an email action for the user
	SendVerificationEmail(accessToken string, realm string, userId string) error

	// Groups
	// GetGroups gets all groups of the given realm
	GetGroups(accessToken string, realm string) ([]Group, error)
	// GetGroup gets the given group
	GetGroup(accessToken string, realm, groupID string) (Group, error)
	// GetGroupMembers get a list of users of group with id in realm
	GetGroupMembers(accessToken string, realm, groupID string) ([]User, error)
	// GetEvents Returns all events, or filters them based on URL query parameters listed here
	GetEvents(accessToken string, realm, query string) ([]Event, error)
}
