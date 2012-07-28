package rhodecode

import (
	"encoding/json"
	"errors"
	"fmt"
)

type User struct {
	Id          int
	Username    string
	Password    string
	Email       string
	FirstName   string
	LastName    string
	Active      bool
	Admin       bool
	LdapDN      string
	LastLogin   string
	Permissions *Permissions
}

type Permissions struct {
	Global             []string          `json:"global"`
	Repositories       map[string]string `json:"repositories"`
	RepositoriesGroups map[string]string `json:"repositories_groups"`
}

type userDec struct {
	Id          *int         `json:"id"`
	Username    *string      `json:"username"`
	Email       *string      `json:"email"`
	FirstName   *string      `json:"firstname"`
	LastName    *string      `json:"lastname"`
	Active      *bool        `json:"active"`
	Admin       *bool        `json:"admin"`
	LdapDN      *string      `json:"ldap_dn"`
	LastLogin   *string      `json:"last_login"`
	Permissions *Permissions `json:"permissions"`
}

func (u *userDec) decode() *User {
	return &User{
		Id:          ptrToInt(u.Id),
		Username:    ptrToString(u.Username),
		Email:       ptrToString(u.Email),
		FirstName:   ptrToString(u.FirstName),
		LastName:    ptrToString(u.LastName),
		Active:      ptrToBool(u.Active),
		Admin:       ptrToBool(u.Admin),
		LdapDN:      ptrToString(u.LdapDN),
		LastLogin:   ptrToString(u.LastLogin),
		Permissions: u.Permissions,
	}
}

func unmarshalUser(data []byte) (*User, error) {
	type response struct {
		Id     string      `json:"id"`
		Result *userDec    `json:"result"`
		Error  interface{} `json:"error"`
	}

	res := &response{}
	err := json.Unmarshal(data, &res)
	if err != nil {
		return nil, err
	}

	if res.Error != nil {
		return nil, castError(res.Error)
	}

	if res.Result == nil {
		return nil, errors.New("User not found")
	}

	return res.Result.decode(), nil
}

func unmarshalUsers(data []byte) ([]*User, error) {
	type response struct {
		Id     string      `json:"id"`
		Result []*userDec  `json:"result"`
		Error  interface{} `json:"error"`
	}

	res := &response{}
	err := json.Unmarshal(data, &res)
	if err != nil {
		return nil, err
	}

	if res.Error != nil {
		return nil, castError(res.Error)
	}

	users := make([]*User, len(res.Result))
	for i := range res.Result {
		users[i] = res.Result[i].decode()
	}

	return users, nil
}

// Get’s an user by user_id.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) GetUser(id string, userId int) (*User, error) {
	req := r.newRequest(id, "get_user")
	req.Args["userid"] = fmt.Sprint(userId)

	data, err := req.send()
	if err != nil {
		return nil, err
	}

	return unmarshalUser(data)
}

// Lists all existing users.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) GetUsers(id string) ([]*User, error) {
	req := r.newRequest(id, "get_users")

	data, err := req.send()
	if err != nil {
		return nil, err
	}

	return unmarshalUsers(data)
}

// Creates new user.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) CreateUser(id string, user *User) (int, error) {
	req := r.newRequest(id, "create_user")
	req.Args["username"] = user.Username
	req.Args["password"] = user.Password
	req.Args["email"] = user.Email
	if user.FirstName != "" {
		req.Args["firstname"] = user.FirstName
	}
	if user.LastName != "" {
		req.Args["lastname"] = user.LastName
	}
	req.Args["active"] = boolToIntString(user.Active)
	req.Args["admin"] = boolToIntString(user.Admin)
	if user.LdapDN != "" {
		req.Args["ldap_dn"] = user.LdapDN
	}

	data, err := req.send()
	if err != nil {
		return 0, err
	}

	return unmarshalResult(data)
}

// Updates current one if such user exists.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) UpdateUser(id string, user *User) (int, error) {
	req := r.newRequest(id, "update_user")
	req.Args["userid"] = fmt.Sprint(user.Id)
	if user.Username != "" {
		req.Args["username"] = user.Username
	}
	req.Args["password"] = user.Password
	req.Args["email"] = user.Email
	req.Args["firstname"] = user.FirstName
	req.Args["lastname"] = user.LastName
	req.Args["active"] = boolToIntString(user.Active)
	req.Args["admin"] = boolToIntString(user.Admin)
	req.Args["ldap_dn"] = user.LdapDN

	data, err := req.send()
	if err != nil {
		return 0, err
	}

	return unmarshalResult(data)
}
