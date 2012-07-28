package rhodecode

import (
	"encoding/json"
	"errors"
	"fmt"
)

type Repo struct {
	Id                    int
	Name                  string
	Description           string
	Type                  string
	Users                 []*User
	UserPermissions       map[int]string
	UsersGroups           []*UsersGroup
	UsersGroupPermissions map[int]string
	OwnerName             string
	Private               bool
	CloneUri              string
}

type repoDec struct {
	Id          *int                     `json:"id"`
	RepoName    *string                  `json:"repo_name"`
	Type        *string                  `json:"type"`
	Description *string                  `json:"description"`
	Members     []map[string]interface{} `json:"members"`
}

func (r *repoDec) decode() *Repo {
	dec := &Repo{
		Id:                    ptrToInt(r.Id),
		Name:                  ptrToString(r.RepoName),
		Type:                  ptrToString(r.Type),
		Description:           ptrToString(r.Description),
		Users:                 make([]*User, 0),
		UserPermissions:       make(map[int]string),
		UsersGroups:           make([]*UsersGroup, 0),
		UsersGroupPermissions: make(map[int]string),
	}

	for i := range r.Members {
		member := r.Members[i]
		val, ok := member["type"]
		if !ok {
			continue
		}

		if t, ok := val.(string); ok {
			if t == "user" {
				user := &User{}
				user.Id, _ = member["id"].(int)
				user.Username, _ = member["username"].(string)
				user.FirstName, _ = member["firstname"].(string)
				user.LastName, _ = member["lastname"].(string)
				user.Email, _ = member["email"].(string)
				user.Active, _ = member["active"].(bool)
				user.Admin, _ = member["admin"].(bool)
				user.LdapDN, _ = member["ldap_dn"].(string)
				dec.UserPermissions[user.Id], _ = member["permission"].(string)
				dec.Users = append(dec.Users, user)
			} else if t == "users_group" {
				usersGroup := &UsersGroup{}
				usersGroup.Id, _ = member["id"].(int)
				usersGroup.Name, _ = member["name"].(string)
				usersGroup.Active, _ = member["active"].(bool)
				dec.UsersGroupPermissions[usersGroup.Id], _ = member["permission"].(string)
				dec.UsersGroups = append(dec.UsersGroups, usersGroup)
			}
		}
	}

	return dec
}

func unmarshalRepo(data []byte) (*Repo, error) {
	type response struct {
		Id     string      `json:"id"`
		Result *repoDec    `json:"result"`
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
		return nil, errors.New("Repo not found")
	}

	return res.Result.decode(), nil
}

func unmarshalRepos(data []byte) ([]*Repo, error) {
	type response struct {
		Id     string      `json:"id"`
		Result []*repoDec  `json:"result"`
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

	repos := make([]*Repo, len(res.Result))
	for i := range res.Result {
		repos[i] = res.Result[i].decode()
	}

	return repos, nil
}

// Gets an existing repository by it’s name or repository_id.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) GetRepo(id string, repoId int) (*Repo, error) {
	req := r.newRequest(id, "get_repo")
	req.Args["repoid"] = fmt.Sprintf("%v", repoId)

	data, err := req.send()
	if err != nil {
		return nil, err
	}

	return unmarshalRepo(data)
}

// Lists all existing repositories.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) GetRepos(id string) ([]*Repo, error) {
	req := r.newRequest(id, "get_repos")

	data, err := req.send()
	if err != nil {
		return nil, err
	}

	return unmarshalRepos(data)
}

// Creates a repository.
// If repository name contains “/”, all needed repository groups will be created.
// For example “foo/bar/baz” will create groups “foo”, “bar” (with “foo” as parent),
// and create “baz” repository with “bar” as group.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) CreateRepo(id string, repo *Repo) (int, error) {
	req := r.newRequest(id, "create_repo")
	req.Args["repo_name"] = repo.Name
	req.Args["owner_name"] = repo.OwnerName
	if repo.Description != "" {
		req.Args["description"] = repo.Description
	}
	if repo.Type != "" {
		req.Args["repo_type"] = repo.Type
	}
	req.Args["private"] = boolToIntString(repo.Private)
	if repo.CloneUri != "" {
		req.Args["clone_uri"] = repo.CloneUri
	}

	data, err := req.send()
	if err != nil {
		return 0, err
	}

	return unmarshalResult(data)
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

	_, err = unmarshalResult(data)
	return err
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
		return castError(res.Error)
	}

	return nil
}
