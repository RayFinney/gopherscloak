package gopherscloak

type GophersCloak interface {
	// Utility
	HealthCheck(realm string) error

	// Admin
	LoginAdmin(username string, password string) (*Token, error)
	// User Login
	Login(username string, password string, realm string, clientId string, secret string) (*Token, error)

	// User
	// CreateUser creates a new user
	CreateUser(accessToken string, realm string, user User) (string, error)
	// DeleteUser deletes the given user
	DeleteUser(accessToken string, realm, userID string) error
	// GetUserByID gets the user with the given id
	GetUserByID(accessToken string, realm string, userID string) (*User, error)
	// GetUserByUsername gets the user with the given username
	GetUserByUsername(accessToken string, realm string, username string) (*User, error)
	// GetUser count returns the userCount of the given realm
	GetUserCount(accessToken string, realm string) (int, error)
	// GetUsers gets all users of the given realm
	GetUsers(accessToken string, realm string, query string) ([]*User, error)
	// GetUserGroups gets the groups of the given user
	GetUserGroups(accessToken string, realm string, userID string) ([]*UserGroup, error)
	// GetUsersByRoleName returns all users have a given role
	GetUsersByRoleName(accessToken string, realm string, roleName string) ([]*User, error)
	// GetUsersByClientRoleName returns all users have a given client role
	GetUsersByClientRoleName(accessToken string, realm string, clientID string, roleName string, params GetUsersByRoleParams) ([]*User, error)
	// SetPassword sets a new password for the user with the given id. Needs elevated privileges
	SetPassword(accessToken string, userID string, realm string, password string, temporary bool) error
	// UpdateUser updates the given user
	UpdateUser(accessToken string, realm string, user User) error
	// AddUserToGroup puts given user to given group
	AddUserToGroup(accessToken string, realm string, userID string, groupID string) error
	// DeleteUserFromGroup deletes given user from given group
	DeleteUserFromGroup(accessToken string, realm string, userID string, groupID string) error
	// GetUserSessions returns user sessions associated with the user
	GetUserSessions(token, realm, userID string) ([]*UserSessionRepresentation, error)
	// GetUserOfflineSessionsForClient returns offline sessions associated with the user and client
	GetUserOfflineSessionsForClient(token, realm, userID, clientID string) ([]*UserSessionRepresentation, error)
	// GetUserInfo gets the user info for the given realm
	GetUserInfo(accessToken string, realm string) (*UserInfo, error)
	// LogoutAllUserSessions log out all current user sessions
	LogoutAllUserSessions(accessToken string, realm string, userID string) error

	// Groups
	// GetGroups gets all groups of the given realm
	GetGroups(accessToken string, realm string) ([]*Group, error)
	// GetGroup gets the given group
	GetGroup(accessToken string, realm, groupID string) (*Group, error)
	// GetGroupMembers get a list of users of group with id in realm
	GetGroupMembers(accessToken string, realm, groupID string) ([]*User, error)
	// GetEvents Returns all events, or filters them based on URL query parameters listed here
	GetEvents(accessToken string, realm, query string) ([]*Event, error)
}
