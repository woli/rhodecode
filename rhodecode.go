package rhodecode

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
)

type RhodeCode struct {
	url    string
	apiKey string
}

type request struct {
	url    string
	Id     string            `json:"id"`
	ApiKey string            `json:"api_key"`
	Method string            `json:"method"`
	Args   map[string]string `json:"args"`
}

type User struct {
	Id          float64
	Username    string
	Password    string
	Email       string
	FirstName   string
	LastName    string
	Active      bool
	Admin       bool
	LdapDN      string
	LastLogin   string
	Permissions struct {
		Global             []string
		Repositories       map[string]string
		RepositoriesGroups map[string]string
	}
}

type UsersGroup struct {
	Id      float64
	Name    string
	Active  bool
	Members []*User
}

type Repo struct {
	Id                    float64
	Name                  string
	Description           string
	Type                  string
	Users                 []*User
	UserPermissions       map[float64]string
	UsersGroups           []*UsersGroup
	UsersGroupPermissions map[float64]string
	OwnerName             string
	Private               bool
	CloneUri              string
}

type RepoNode struct {
	Name string
	Type string
}

// Sets the certificate authority to be used in all API requests.
func SetCertAuth(pem []byte) {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	http.DefaultTransport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: pool,
		},
	}
}

func resError(err interface{}) error {
	str, ok := err.(string)
	if !ok {
		return fmt.Errorf("%+v", err)
	}

	return errors.New(str)
}

func nonNil(s *string) string {
	if s != nil {
		return *s
	}

	return ""
}

func boolToIntStr(b bool) string {
	if b {
		return "1"
	}

	return "0"
}

func (r *request) send() ([]byte, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", r.url, bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Add("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// Returns a new RhodeCode. 
func New(url, apiKey string) *RhodeCode {
	return &RhodeCode{url: url, apiKey: apiKey}
}

func (r *RhodeCode) newRequest(id, method string) *request {
	return &request{
		url:    r.url,
		Id:     id,
		ApiKey: r.apiKey,
		Method: method,
		Args:   make(map[string]string),
	}
}

// Pulls given repo from remote location.
// Can be used to automatically keep remote repos up to date.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) Pull(id, repoName string) error {
	req := r.newRequest(id, "pull")
	req.Args["repo_name"] = repoName

	data, err := req.send()
	if err != nil {
		return err
	}

	type response struct {
		Id     string      `json:"id"`
		Result *string     `json:"result"`
		Error  interface{} `json:"error"`
	}

	res := &response{}
	err = json.Unmarshal(data, &res)
	if err != nil {
		return err
	}

	if res.Error != nil {
		return resError(res.Error)
	}

	return nil
}

// Get’s an user by username or user_id.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) GetUser(id, userId string) (*User, error) {
	req := r.newRequest(id, "get_user")
	req.Args["userid"] = userId

	data, err := req.send()
	if err != nil {
		return nil, err
	}

	type response struct {
		Id     string `json:"id"`
		Result *struct {
			Id          float64 `json:"id"`
			Username    *string `json:"username"`
			Email       *string `json:"email"`
			FirstName   *string `json:"firstname"`
			LastName    *string `json:"lastname"`
			Active      bool    `json:"active"`
			Admin       bool    `json:"admin"`
			LdapDN      *string `json:"ldap_dn"`
			LastLogin   *string `json:"last_login"`
			Permissions *struct {
				Global             []string          `json:"global"`
				Repositories       map[string]string `json:"repositories"`
				RepositoriesGroups map[string]string `json:"repositories_groups"`
			}
		} `json:"result"`
		Error interface{} `json:"error"`
	}

	res := &response{}
	err = json.Unmarshal(data, &res)
	if err != nil {
		return nil, err
	}

	if res.Error != nil {
		return nil, resError(res.Error)
	}

	u := res.Result
	user := &User{
		Id:        u.Id,
		Username:  nonNil(u.Username),
		Email:     nonNil(u.Email),
		FirstName: nonNil(u.FirstName),
		LastName:  nonNil(u.LastName),
		Active:    u.Active,
		Admin:     u.Admin,
		LdapDN:    nonNil(u.LdapDN),
		LastLogin: nonNil(u.LastLogin),
	}

	if u.Permissions != nil {
		user.Permissions.Global = u.Permissions.Global
		user.Permissions.Repositories = u.Permissions.Repositories
		user.Permissions.RepositoriesGroups = u.Permissions.RepositoriesGroups
	}

	return user, nil
}

// Lists all existing users.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) GetUsers(id string) ([]*User, error) {
	req := r.newRequest(id, "get_users")

	data, err := req.send()
	if err != nil {
		return nil, err
	}

	type response struct {
		Id     string `json:"id"`
		Result []struct {
			Id        float64 `json:"id"`
			Username  *string `json:"username"`
			Email     *string `json:"email"`
			FirstName *string `json:"firstname"`
			LastName  *string `json:"lastname"`
			Active    bool    `json:"active"`
			Admin     bool    `json:"admin"`
			LdapDN    *string `json:"ldap_dn"`
			LastLogin *string `json:"last_login"`
		} `json:"result"`
		Error interface{} `json:"error"`
	}

	res := &response{}
	err = json.Unmarshal(data, &res)
	if err != nil {
		return nil, err
	}

	if res.Error != nil {
		return nil, resError(res.Error)
	}

	users := make([]*User, 0)
	for i := range res.Result {
		u := res.Result[i]
		user := &User{
			Id:        u.Id,
			Username:  nonNil(u.Username),
			Email:     nonNil(u.Email),
			FirstName: nonNil(u.FirstName),
			LastName:  nonNil(u.LastName),
			Active:    u.Active,
			Admin:     u.Admin,
			LdapDN:    nonNil(u.LdapDN),
			LastLogin: nonNil(u.LastLogin),
		}

		users = append(users, user)
	}

	return users, nil
}

// Creates new user.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) CreateUser(id string, user *User) (float64, error) {
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
	req.Args["active"] = boolToIntStr(user.Active)
	req.Args["admin"] = boolToIntStr(user.Admin)
	if user.LdapDN != "" {
		req.Args["ldap_dn"] = user.LdapDN
	}

	data, err := req.send()
	if err != nil {
		return 0, err
	}

	type response struct {
		Id     string `json:"id"`
		Result *struct {
			Id  float64 `json:"id"`
			Msg string  `json:"msg"`
		} `json:"result"`
		Error interface{} `json:"error"`
	}

	res := &response{}
	err = json.Unmarshal(data, &res)
	if err != nil {
		return 0, err
	}

	if res.Error != nil {
		return 0, resError(res.Error)
	}

	return res.Result.Id, nil
}

// Updates current one if such user exists.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) UpdateUser(id string, user *User) (float64, error) {
	req := r.newRequest(id, "update_user")
	req.Args["userid"] = fmt.Sprintf("%v", user.Id)
	if user.Username != "" {
		req.Args["username"] = user.Username
	}
	req.Args["password"] = user.Password
	req.Args["email"] = user.Email
	req.Args["firstname"] = user.FirstName
	req.Args["lastname"] = user.LastName
	req.Args["active"] = boolToIntStr(user.Active)
	req.Args["admin"] = boolToIntStr(user.Admin)
	req.Args["ldap_dn"] = user.LdapDN

	data, err := req.send()
	if err != nil {
		return 0, err
	}

	type response struct {
		Id     string `json:"id"`
		Result *struct {
			Id  float64 `json:"id"`
			Msg string  `json:"msg"`
		} `json:"result"`
		Error interface{} `json:"error"`
	}

	res := &response{}
	err = json.Unmarshal(data, &res)
	if err != nil {
		return 0, err
	}

	if res.Error != nil {
		return 0, resError(res.Error)
	}

	return res.Result.Id, nil
}

// Gets an existing users group.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) GetUsersGroup(id, groupName string) (*UsersGroup, error) {
	req := r.newRequest(id, "get_users_group")
	req.Args["group_name"] = groupName

	data, err := req.send()
	if err != nil {
		return nil, err
	}

	type response struct {
		Id     string `json:"id"`
		Result *struct {
			Id        float64 `json:"id"`
			GroupName *string `json:"group_name"`
			Active    bool    `json:"active"`
			Members   []struct {
				Id        float64 `json:"id"`
				Username  *string `json:"username"`
				FirstName *string `json:"firstname"`
				LastName  *string `json:"lastname"`
				Email     *string `json:"email"`
				Active    bool    `json:"active"`
				Admin     bool    `json:"admin"`
				LdapDN    *string `json:"ldap_dn"`
			} `json:"members"`
		} `json:"result"`
		Error interface{} `json:"error"`
	}

	res := &response{}
	err = json.Unmarshal(data, &res)
	if err != nil {
		return nil, err
	}

	if res.Error != nil {
		return nil, resError(res.Error)
	}

	g := res.Result
	group := &UsersGroup{
		Id:      g.Id,
		Name:    nonNil(g.GroupName),
		Active:  g.Active,
		Members: make([]*User, 0),
	}

	for j := range g.Members {
		u := g.Members[j]
		user := &User{
			Id:        u.Id,
			Username:  nonNil(u.Username),
			FirstName: nonNil(u.FirstName),
			LastName:  nonNil(u.LastName),
			Email:     nonNil(u.Email),
			Active:    u.Active,
			Admin:     u.Admin,
			LdapDN:    nonNil(u.LdapDN),
		}

		group.Members = append(group.Members, user)
	}

	return group, nil
}

// Lists all existing users groups.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) GetUsersGroups(id string) ([]*UsersGroup, error) {
	req := r.newRequest(id, "get_users_groups")

	data, err := req.send()
	if err != nil {
		return nil, err
	}

	type response struct {
		Id     string `json:"id"`
		Result []struct {
			Id        float64 `json:"id"`
			GroupName *string `json:"group_name"`
			Active    bool    `json:"active"`
			Members   []struct {
				Id        float64 `json:"id"`
				Username  *string `json:"username"`
				FirstName *string `json:"firstname"`
				LastName  *string `json:"lastname"`
				Email     *string `json:"email"`
				Active    bool    `json:"active"`
				Admin     bool    `json:"admin"`
				LdapDN    *string `json:"ldap_dn"`
			} `json:"members"`
		} `json:"result"`
		Error interface{} `json:"error"`
	}

	res := &response{}
	err = json.Unmarshal(data, &res)
	if err != nil {
		return nil, err
	}

	if res.Error != nil {
		return nil, resError(res.Error)
	}

	groups := make([]*UsersGroup, 0)
	for i := range res.Result {
		g := res.Result[i]
		group := &UsersGroup{
			Id:      g.Id,
			Name:    nonNil(g.GroupName),
			Active:  g.Active,
			Members: make([]*User, 0),
		}

		for j := range g.Members {
			u := g.Members[j]
			user := &User{
				Id:        u.Id,
				Username:  nonNil(u.Username),
				FirstName: nonNil(u.FirstName),
				LastName:  nonNil(u.LastName),
				Email:     nonNil(u.Email),
				Active:    u.Active,
				Admin:     u.Admin,
				LdapDN:    nonNil(u.LdapDN),
			}

			group.Members = append(group.Members, user)
		}

		groups = append(groups, group)
	}

	return groups, nil
}

// Creates new users group.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) CreateUsersGroup(id string, group *UsersGroup) (float64, error) {
	req := r.newRequest(id, "create_users_group")
	req.Args["group_name"] = group.Name
	req.Args["active"] = boolToIntStr(group.Active)

	data, err := req.send()
	if err != nil {
		return 0, err
	}

	type response struct {
		Id     string `json:"id"`
		Result *struct {
			Id  float64 `json:"id"`
			Msg string  `json:"msg"`
		} `json:"result"`
		Error interface{} `json:"error"`
	}

	res := &response{}
	err = json.Unmarshal(data, &res)
	if err != nil {
		return 0, err
	}

	if res.Error != nil {
		return 0, resError(res.Error)
	}

	return res.Result.Id, nil
}

// Adds a user to a users group.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) AddUserToUsersGroup(id, groupName, username string) (float64, error) {
	req := r.newRequest(id, "add_user_to_users_group")
	req.Args["group_name"] = groupName
	req.Args["username"] = username

	data, err := req.send()
	if err != nil {
		return 0, err
	}

	type response struct {
		Id     string `json:"id"`
		Result *struct {
			Id      *float64 `json:"id"`
			Success bool     `json:"success"`
			Msg     string   `json:"msg"`
		} `json:"result"`
		Error interface{} `json:"error"`
	}

	res := &response{}
	err = json.Unmarshal(data, &res)
	if err != nil {
		return 0, err
	}

	if res.Error != nil {
		return 0, resError(res.Error)
	}

	if !res.Result.Success {
		return 0, errors.New(res.Result.Msg)
	}

	return *res.Result.Id, nil
}

// Removes a user from a users group.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) RemoveUserFromUsersGroup(id, groupName, username string) error {
	req := r.newRequest(id, "remove_user_from_users_group")
	req.Args["group_name"] = groupName
	req.Args["username"] = username

	data, err := req.send()
	if err != nil {
		return err
	}

	type response struct {
		Id     string `json:"id"`
		Result *struct {
			Success bool   `json:"success"`
			Msg     string `json:"msg"`
		} `json:"result"`
		Error interface{} `json:"error"`
	}

	res := &response{}
	err = json.Unmarshal(data, &res)
	if err != nil {
		return err
	}

	if res.Error != nil {
		return resError(res.Error)
	}

	if !res.Result.Success {
		return errors.New(res.Result.Msg)
	}

	return nil
}

// Gets an existing repository by it’s name or repository_id.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) GetRepo(id string, repoId float64) (*Repo, error) {
	req := r.newRequest(id, "get_repo")
	req.Args["repoid"] = fmt.Sprintf("%v", repoId)

	data, err := req.send()
	if err != nil {
		return nil, err
	}

	type response struct {
		Id     string `json:"id"`
		Result *struct {
			Id          float64                  `json:"id"`
			RepoName    *string                  `json:"repo_name"`
			Type        *string                  `json:"type"`
			Description *string                  `json:"description"`
			Members     []map[string]interface{} `json:"members"`
		} `json:"result"`
		Error interface{} `json:"error"`
	}

	res := &response{}
	err = json.Unmarshal(data, &res)
	if err != nil {
		return nil, err
	}

	if res.Error != nil {
		return nil, resError(res.Error)
	}

	repo := &Repo{
		Id:                    res.Result.Id,
		Name:                  nonNil(res.Result.RepoName),
		Type:                  nonNil(res.Result.Type),
		Description:           nonNil(res.Result.Description),
		Users:                 make([]*User, 0),
		UserPermissions:       make(map[float64]string),
		UsersGroups:           make([]*UsersGroup, 0),
		UsersGroupPermissions: make(map[float64]string),
	}

	for i := range res.Result.Members {
		member := res.Result.Members[i]
		val, ok := member["type"]
		if !ok {
			continue
		}

		if t, ok := val.(string); ok {
			if t == "user" {
				user := &User{}
				user.Id, _ = member["id"].(float64)
				user.Username, _ = member["username"].(string)
				user.FirstName, _ = member["firstname"].(string)
				user.LastName, _ = member["lastname"].(string)
				user.Email, _ = member["email"].(string)
				user.Active, _ = member["active"].(bool)
				user.Admin, _ = member["admin"].(bool)
				user.LdapDN, _ = member["ldap_dn"].(string)
				repo.UserPermissions[user.Id], _ = member["permission"].(string)
				repo.Users = append(repo.Users, user)
			} else if t == "users_group" {
				usersGroup := &UsersGroup{}
				usersGroup.Id, _ = member["id"].(float64)
				usersGroup.Name, _ = member["name"].(string)
				usersGroup.Active, _ = member["active"].(bool)
				repo.UsersGroupPermissions[usersGroup.Id], _ = member["permission"].(string)
				repo.UsersGroups = append(repo.UsersGroups, usersGroup)
			}
		}
	}

	return repo, nil
}

// Lists all existing repositories.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) GetRepos(id string) ([]*Repo, error) {
	req := r.newRequest(id, "get_repos")

	data, err := req.send()
	if err != nil {
		return nil, err
	}

	type response struct {
		Id     string `json:"id"`
		Result []struct {
			Id          float64 `json:"id"`
			Name        *string `json:"repo_name"`
			Type        *string `json:"type"`
			Description *string `json:"description"`
		} `json:"result"`
		Error interface{} `json:"error"`
	}

	res := &response{}
	err = json.Unmarshal(data, &res)
	if err != nil {
		return nil, err
	}

	if res.Error != nil {
		return nil, resError(res.Error)
	}

	repos := make([]*Repo, 0)
	for i := range res.Result {
		rp := res.Result[i]
		repo := &Repo{
			Id:          rp.Id,
			Name:        nonNil(rp.Name),
			Type:        nonNil(rp.Type),
			Description: nonNil(rp.Description),
		}

		repos = append(repos, repo)
	}

	return repos, nil
}

// Returns a list of nodes and it’s children in a flat list for a given path at given revision.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) GetRepoNodes(id, repoName, revision, rootPath string, files, dirs bool) ([]*RepoNode, error) {
	if !files && !dirs {
		return make([]*RepoNode, 0), nil
	}

	req := r.newRequest(id, "get_repo_nodes")
	req.Args["repo_name"] = repoName
	req.Args["revision"] = revision
	req.Args["root_path"] = rootPath
	if files && dirs {
		req.Args["ret_type"] = "all"
	} else if files {
		req.Args["ret_type"] = "files"
	} else {
		req.Args["ret_type"] = "dirs"
	}

	data, err := req.send()
	if err != nil {
		return nil, err
	}

	type response struct {
		Id     string `json:"id"`
		Result []struct {
			Name *string `json:"name"`
			Type *string `json:"type"`
		} `json:"result"`
		Error interface{} `json:"error"`
	}

	res := &response{}
	err = json.Unmarshal(data, &res)
	if err != nil {
		return nil, err
	}

	if res.Error != nil {
		return nil, resError(res.Error)
	}

	nodes := make([]*RepoNode, 0)
	for i := range res.Result {
		n := res.Result[i]
		node := &RepoNode{
			Name: nonNil(n.Name),
			Type: nonNil(n.Type),
		}

		nodes = append(nodes, node)
	}

	return nodes, nil
}

// Creates a repository.
// If repository name contains “/”, all needed repository groups will be created.
// For example “foo/bar/baz” will create groups “foo”, “bar” (with “foo” as parent),
// and create “baz” repository with “bar” as group.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) CreateRepo(id string, repo *Repo) (float64, error) {
	req := r.newRequest(id, "create_repo")
	req.Args["repo_name"] = repo.Name
	req.Args["owner_name"] = repo.OwnerName
	if repo.Description != "" {
		req.Args["description"] = repo.Description
	}
	if repo.Type != "" {
		req.Args["repo_type"] = repo.Type
	}
	req.Args["private"] = boolToIntStr(repo.Private)
	if repo.CloneUri != "" {
		req.Args["clone_uri"] = repo.CloneUri
	}

	data, err := req.send()
	if err != nil {
		return 0, err
	}

	type response struct {
		Id     string `json:"id"`
		Result *struct {
			Id  float64 `json:"id"`
			Msg string  `json:"msg"`
		} `json:"result"`
		Error interface{} `json:"error"`
	}

	res := &response{}
	err = json.Unmarshal(data, &res)
	if err != nil {
		return 0, err
	}

	if res.Error != nil {
		return 0, resError(res.Error)
	}

	return res.Result.Id, nil
}

// Deletes a repository.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) DeleteRepo(id, repoName string) error {
	req := r.newRequest(id, "delete_repo")
	req.Args["repo_name"] = repoName

	data, err := req.send()
	if err != nil {
		return err
	}

	type response struct {
		Id     string `json:"id"`
		Result *struct {
			Msg string `json:"msg"`
		} `json:"result"`
		Error interface{} `json:"error"`
	}

	res := &response{}
	err = json.Unmarshal(data, &res)
	if err != nil {
		return err
	}

	if res.Error != nil {
		return resError(res.Error)
	}

	return nil
}

// Grant permission for user on given repository, or update existing one if found.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) GrantUserPermission(id, repoName, username string, read, write, admin bool) error {
	req := r.newRequest(id, "grant_user_permission")
	req.Args["repo_name"] = repoName
	req.Args["username"] = username
	if admin {
		req.Args["perm"] = "repository.admin"
	} else if write {
		req.Args["perm"] = "repository.write"
	} else if read {
		req.Args["perm"] = "repository.read"
	} else {
		req.Args["perm"] = "repository.none"
	}

	data, err := req.send()
	if err != nil {
		return err
	}

	type response struct {
		Id     string `json:"id"`
		Result *struct {
			Msg string `json:"msg"`
		} `json:"result"`
		Error interface{} `json:"error"`
	}

	res := &response{}
	err = json.Unmarshal(data, &res)
	if err != nil {
		return err
	}

	if res.Error != nil {
		return resError(res.Error)
	}

	return nil
}

// Revoke permission for user on given repository.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) RevokeUserPermission(id, repoName, username string) error {
	req := r.newRequest(id, "revoke_user_permission")
	req.Args["repo_name"] = repoName
	req.Args["username"] = username

	data, err := req.send()
	if err != nil {
		return err
	}

	type response struct {
		Id     string `json:"id"`
		Result *struct {
			Msg string `json:"msg"`
		} `json:"result"`
		Error interface{} `json:"error"`
	}

	res := &response{}
	err = json.Unmarshal(data, &res)
	if err != nil {
		return err
	}

	if res.Error != nil {
		return resError(res.Error)
	}

	return nil
}

// Grant permission for users group on given repository, or update existing one if found.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) GrantUsersGroupPermission(id, repoName, groupName string, read, write, admin bool) error {
	req := r.newRequest(id, "grant_users_group_permission")
	req.Args["repo_name"] = repoName
	req.Args["group_name"] = groupName
	if admin {
		req.Args["perm"] = "repository.admin"
	} else if write {
		req.Args["perm"] = "repository.write"
	} else if read {
		req.Args["perm"] = "repository.read"
	} else {
		req.Args["perm"] = "repository.none"
	}

	data, err := req.send()
	if err != nil {
		return err
	}

	type response struct {
		Id     string `json:"id"`
		Result *struct {
			Msg string `json:"msg"`
		} `json:"result"`
		Error interface{} `json:"error"`
	}

	res := &response{}
	err = json.Unmarshal(data, &res)
	if err != nil {
		return err
	}

	if res.Error != nil {
		return resError(res.Error)
	}

	return nil
}

// Revoke permission for users group on given repository.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) RevokeUsersGroupPermission(id, repoName, groupName string) error {
	req := r.newRequest(id, "revoke_users_group_permission")
	req.Args["repo_name"] = repoName
	req.Args["group_name"] = groupName

	data, err := req.send()
	if err != nil {
		return err
	}

	type response struct {
		Id     string `json:"id"`
		Result *struct {
			Msg string `json:"msg"`
		} `json:"result"`
		Error interface{} `json:"error"`
	}

	res := &response{}
	err = json.Unmarshal(data, &res)
	if err != nil {
		return err
	}

	if res.Error != nil {
		return resError(res.Error)
	}

	return nil
}
