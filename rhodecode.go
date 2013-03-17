// Package rhodecode provides access to the RhodeCode API.
//
// See http://pythonhosted.org/RhodeCode/api/api.html
//
// RhodeCode Version: 1.5.3
package rhodecode

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
)

type Service struct {
	apiUrl      string
	apiKey      string
	client      *http.Client
	Users       *UsersService
	UsersGroups *UsersGroupsService
	Repos       *ReposService
	Permissions *PermissionsService
}

type service struct {
	s *Service
}

type UsersService service
type UsersGroupsService service
type ReposService service
type PermissionsService service

func New(apiUrl, apiKey string, client *http.Client) (*Service, error) {
	if client == nil {
		return nil, errors.New("client is nil")
	}
	s := &Service{
		apiUrl: apiUrl,
		apiKey: apiKey,
		client: client,
	}
	s.Users = &UsersService{s}
	s.UsersGroups = &UsersGroupsService{s}
	s.Repos = &ReposService{s}
	s.Permissions = &PermissionsService{s}
	return s, nil
}

//-------------------------------------------------------------------------
// common
//-------------------------------------------------------------------------

type OperationResult struct {
	Success bool   `json:"success"`
	Msg     string `json:"msg"`
}

func (s *Service) doRequest(id int, method string, args map[string]string) ([]byte, error) {
	if args == nil {
		args = make(map[string]string)
	}
	v := struct {
		Id     int               `json:"id,omitempty"`
		ApiKey string            `json:"api_key,omitempty"`
		Method string            `json:"method,omitempty"`
		Args   map[string]string `json:"args"`
	}{
		id,
		s.apiKey,
		method,
		args,
	}
	body := new(bytes.Buffer)
	err := json.NewEncoder(body).Encode(&v)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequest("POST", s.apiUrl, body)
	req.ContentLength = int64(body.Len())
	req.Header.Add("Content-Type", "application/json")
	res, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	err = checkResponse(data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func checkResponse(data []byte) error {
	r := struct {
		Error *string `json:"error"`
	}{}
	err := json.Unmarshal(data, &r)
	if err != nil {
		return err
	}
	if r.Error == nil {
		return nil
	}
	return errors.New(*r.Error)
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

type Nstring string

func (n *Nstring) UnmarshalJSON(b []byte) (err error) {
	if string(b) == "null" {
		return nil
	}
	return json.Unmarshal(b, (*string)(n))
}

//-------------------------------------------------------------------------
// users
//-------------------------------------------------------------------------

type User struct {
	UserId      int          `json:"user_id"`
	ApiKey      string       `json:"api_key"`
	Username    string       `json:"username"`
	Password    string       `json:"password"`
	Firstname   string       `json:"firstname"`
	Lastname    string       `json:"lastname"`
	Email       string       `json:"email"`
	Emails      []string     `json:"emails"`
	IPAddresses []string     `json:"ip_addresses"`
	Active      bool         `json:"active"`
	Admin       bool         `json:"admin"`
	LdapDN      Nstring      `json:"ldap_dn"`
	LastLogin   Nstring      `json:"last_login"`
	Permissions *Permissions `json:"permissions"`
}

type Permissions struct {
	Global             []string          `json:"global"`
	Repositories       map[string]string `json:"repositories"`
	RepositoriesGroups map[string]string `json:"repositories_groups"`
}

type UserResult struct {
	Msg  string `json:"msg"`
	User *User  `json:"user"`
}

//-------------------------------------------------------------------------
// list users
//-------------------------------------------------------------------------

type UsersListCall struct {
	s *Service
}

type UsersListResult struct {
	Id    int     `json:"id"`
	Users []*User `json:"result"`
}

func (r *UsersService) List() *UsersListCall {
	return &UsersListCall{r.s}
}

func (c *UsersListCall) Do(resId int) (*UsersListResult, error) {
	data, err := c.s.doRequest(resId, "get_users", nil)
	if err != nil {
		return nil, err
	}
	ret := new(UsersListResult)
	err = json.Unmarshal(data, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

//-------------------------------------------------------------------------
// get user
//-------------------------------------------------------------------------

type UsersGetCall struct {
	s    *Service
	user string
}

type UsersGetResult struct {
	Id   int   `json:"id"`
	User *User `json:"result"`
}

func (r *UsersService) Get(user string) *UsersGetCall {
	return &UsersGetCall{r.s, user}
}

func (c *UsersGetCall) Do(resId int) (*UsersGetResult, error) {
	args := make(map[string]string)
	args["userid"] = c.user
	data, err := c.s.doRequest(resId, "get_user", args)
	if err != nil {
		return nil, err
	}
	ret := new(UsersGetResult)
	err = json.Unmarshal(data, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

//-------------------------------------------------------------------------
// insert user
//-------------------------------------------------------------------------

type UsersInsertCall struct {
	s    *Service
	user *User
}

type UsersInsertResult struct {
	Id     int         `json:"id"`
	Result *UserResult `json:"result"`
}

func (r *UsersService) Insert(user *User) *UsersInsertCall {
	return &UsersInsertCall{r.s, user}
}

func (c *UsersInsertCall) Do(resId int) (*UsersInsertResult, error) {
	args := make(map[string]string)
	args["username"] = c.user.Username
	args["email"] = c.user.Email
	args["password"] = c.user.Password
	if c.user.Firstname != "" {
		args["firstname"] = c.user.Firstname
	}
	if c.user.Lastname != "" {
		args["lastname"] = c.user.Lastname
	}
	args["active"] = strconv.Itoa(btoi(c.user.Active))
	args["admin"] = strconv.Itoa(btoi(c.user.Admin))
	if c.user.LdapDN != "" {
		args["ldap_dn"] = string(c.user.LdapDN)
	}
	data, err := c.s.doRequest(resId, "create_user", args)
	if err != nil {
		return nil, err
	}
	ret := new(UsersInsertResult)
	err = json.Unmarshal(data, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

//-------------------------------------------------------------------------
// update user
//-------------------------------------------------------------------------

type UsersUpdateCall struct {
	s    *Service
	user *User
}

type UsersUpdateResult struct {
	Id     int         `json:"id"`
	Result *UserResult `json:"result"`
}

func (r *UsersService) Update(user *User) *UsersUpdateCall {
	return &UsersUpdateCall{r.s, user}
}

func (c *UsersUpdateCall) Do(resId int) (*UsersUpdateResult, error) {
	args := make(map[string]string)
	args["userid"] = strconv.Itoa(c.user.UserId)
	if c.user.Username != "" {
		args["username"] = c.user.Username
	}
	if c.user.Email != "" {
		args["email"] = c.user.Email
	}
	if c.user.Password != "" {
		args["password"] = c.user.Password
	}
	if c.user.Firstname != "" {
		args["firstname"] = c.user.Firstname
	}
	if c.user.Lastname != "" {
		args["lastname"] = c.user.Lastname
	}
	args["active"] = strconv.Itoa(btoi(c.user.Active))
	args["admin"] = strconv.Itoa(btoi(c.user.Admin))
	if c.user.LdapDN != "" {
		args["ldap_dn"] = string(c.user.LdapDN)
	}
	data, err := c.s.doRequest(resId, "update_user", args)
	if err != nil {
		return nil, err
	}
	ret := new(UsersUpdateResult)
	err = json.Unmarshal(data, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

//-------------------------------------------------------------------------
// delete user
//-------------------------------------------------------------------------

type UsersDeleteCall struct {
	s    *Service
	user string
}

type UsersDeleteResult struct {
	Id     int         `json:"id"`
	Result *UserResult `json:"result"`
}

func (r *UsersService) Delete(user string) *UsersDeleteCall {
	return &UsersDeleteCall{r.s, user}
}

func (c *UsersDeleteCall) Do(resId int) (*UsersDeleteResult, error) {
	args := make(map[string]string)
	args["userid"] = c.user
	data, err := c.s.doRequest(resId, "delete_user", args)
	if err != nil {
		return nil, err
	}
	fmt.Println(string(data))
	ret := new(UsersDeleteResult)
	err = json.Unmarshal(data, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

//-------------------------------------------------------------------------
// users groups
//-------------------------------------------------------------------------

type UsersGroup struct {
	UsersGroupId int     `json:"users_group_id"`
	GroupName    string  `json:"group_name"`
	Active       bool    `json:"active"`
	Members      []*User `json:"members"`
}

type UsersGroupResult struct {
	Msg        string      `json:"msg"`
	UsersGroup *UsersGroup `json:"users_group"`
}

//-------------------------------------------------------------------------
// list users groups
//-------------------------------------------------------------------------

type UsersGroupsListCall struct {
	s *Service
}

type UsersGroupsListResult struct {
	Id          int           `json:"id"`
	UsersGroups []*UsersGroup `json:"result"`
}

func (r *UsersGroupsService) List() *UsersGroupsListCall {
	return &UsersGroupsListCall{r.s}
}

func (c *UsersGroupsListCall) Do(resId int) (*UsersGroupsListResult, error) {
	data, err := c.s.doRequest(resId, "get_users_groups", nil)
	if err != nil {
		return nil, err
	}
	ret := new(UsersGroupsListResult)
	err = json.Unmarshal(data, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

//-------------------------------------------------------------------------
// get users group
//-------------------------------------------------------------------------

type UsersGroupsGetCall struct {
	s          *Service
	usersGroup string
}

type UsersGroupsGetResult struct {
	Id         int         `json:"id"`
	UsersGroup *UsersGroup `json:"result"`
}

func (r *UsersGroupsService) Get(usersGroup string) *UsersGroupsGetCall {
	return &UsersGroupsGetCall{r.s, usersGroup}
}

func (c *UsersGroupsGetCall) Do(resId int) (*UsersGroupsGetResult, error) {
	args := make(map[string]string)
	args["usersgroupid"] = c.usersGroup
	data, err := c.s.doRequest(resId, "get_users_group", args)
	if err != nil {
		return nil, err
	}
	ret := new(UsersGroupsGetResult)
	err = json.Unmarshal(data, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

//-------------------------------------------------------------------------
// insert users group
//-------------------------------------------------------------------------

type UsersGroupsInsertCall struct {
	s          *Service
	usersGroup *UsersGroup
}

type UsersGroupsInsertResult struct {
	Id     int               `json:"id"`
	Result *UsersGroupResult `json:"result"`
}

func (r *UsersGroupsService) Insert(usersGroup *UsersGroup) *UsersGroupsInsertCall {
	return &UsersGroupsInsertCall{r.s, usersGroup}
}

func (c *UsersGroupsInsertCall) Do(resId int) (*UsersGroupsInsertResult, error) {
	args := make(map[string]string)
	args["group_name"] = c.usersGroup.GroupName
	args["active"] = strconv.Itoa(btoi(c.usersGroup.Active))
	data, err := c.s.doRequest(resId, "create_users_group", args)
	if err != nil {
		return nil, err
	}
	ret := new(UsersGroupsInsertResult)
	err = json.Unmarshal(data, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

//-------------------------------------------------------------------------
// add user to users group
//-------------------------------------------------------------------------

type UsersGroupsAddUserCall struct {
	s          *Service
	usersGroup string
	user       string
}

type UsersGroupsAddUserResult struct {
	Id     int              `json:"id"`
	Result *OperationResult `json:"result"`
}

func (r *UsersGroupsService) AddUser(usersGroup, user string) *UsersGroupsAddUserCall {
	return &UsersGroupsAddUserCall{r.s, usersGroup, user}
}

func (c *UsersGroupsAddUserCall) Do(resId int) (*UsersGroupsAddUserResult, error) {
	args := make(map[string]string)
	args["usersgroupid"] = c.usersGroup
	args["userid"] = c.user
	data, err := c.s.doRequest(resId, "add_user_to_users_group", args)
	if err != nil {
		return nil, err
	}
	ret := new(UsersGroupsAddUserResult)
	err = json.Unmarshal(data, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

//-------------------------------------------------------------------------
// remove user from users group
//-------------------------------------------------------------------------

type UsersGroupsRemoveUserCall struct {
	s          *Service
	usersGroup string
	user       string
}

type UsersGroupsRemoveUserResult struct {
	Id     int              `json:"id"`
	Result *OperationResult `json:"result"`
}

func (r *UsersGroupsService) RemoveUser(usersGroup, user string) *UsersGroupsRemoveUserCall {
	return &UsersGroupsRemoveUserCall{r.s, usersGroup, user}
}

func (c *UsersGroupsRemoveUserCall) Do(resId int) (*UsersGroupsRemoveUserResult, error) {
	args := make(map[string]string)
	args["usersgroupid"] = c.usersGroup
	args["userid"] = c.user
	data, err := c.s.doRequest(resId, "remove_user_from_users_group", args)
	if err != nil {
		return nil, err
	}
	ret := new(UsersGroupsRemoveUserResult)
	err = json.Unmarshal(data, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

//-------------------------------------------------------------------------
// repos
//-------------------------------------------------------------------------

type Repo struct {
	RepoId           int               `json:"repo_id"`
	RepoName         string            `json:"repo_name"`
	RepoType         string            `json:"repo_type"`
	CloneUri         Nstring           `json:"clone_uri"`
	Private          bool              `json:"private"`
	CreatedOn        string            `json:"created_on"`
	Description      string            `json:"description"`
	LandingRev       string            `json:"landing_rev"`
	Owner            string            `json:"owner"`
	ForkOf           Nstring           `json:"fork_of"`
	EnableDownloads  bool              `json:"enable_downloads"`
	EnableLocking    bool              `json:"enable_locking"`
	EnableStatistics bool              `json:"enable_statistics"`
	LastChangeset    *Changeset        `json:"last_changeset"`
	Users            []*RepoUser       `json:"-"`
	UsersGroups      []*RepoUsersGroup `json:"-"`
}

type Changeset struct {
	Author   string `json:"author"`
	Date     string `json:"date"`
	Message  string `json:"message"`
	RawId    string `json:"raw_id"`
	Revision int    `json:"revision"`
	ShortId  string `json:"short_id"`
}

type RepoUser struct {
	User
	Permission Permission
}

type RepoUsersGroup struct {
	UsersGroup
	Permission Permission
}

type RepoResult struct {
	Msg  string `json:"msg"`
	Repo *Repo  `json:"repo"`
}

//-------------------------------------------------------------------------
// list repos
//-------------------------------------------------------------------------

type ReposListCall struct {
	s *Service
}

type ReposListResult struct {
	Id    int     `json:"id"`
	Repos []*Repo `json:"result"`
}

func (r *ReposService) List() *ReposListCall {
	return &ReposListCall{r.s}
}

func (c *ReposListCall) Do(resId int) (*ReposListResult, error) {
	data, err := c.s.doRequest(resId, "get_repos", nil)
	if err != nil {
		return nil, err
	}
	ret := new(ReposListResult)
	err = json.Unmarshal(data, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

//-------------------------------------------------------------------------
// get repo
//-------------------------------------------------------------------------

type ReposGetCall struct {
	s    *Service
	repo string
}

type ReposGetResult struct {
	Id   int   `json:"id"`
	Repo *Repo `json:"result"`
}

func (r *ReposService) Get(repo string) *ReposGetCall {
	return &ReposGetCall{r.s, repo}
}

func (c *ReposGetCall) Do(resId int) (*ReposGetResult, error) {
	args := make(map[string]string)
	args["repoid"] = c.repo
	data, err := c.s.doRequest(resId, "get_repo", args)
	if err != nil {
		return nil, err
	}
	ret := new(ReposGetResult)
	err = json.Unmarshal(data, ret)
	if err != nil {
		return nil, err
	}

	type members struct {
		Result struct {
			Members []map[string]interface{} `json:"members"`
		} `json:"result"`
	}
	m := new(members)
	err = json.Unmarshal(data, m)
	if err != nil {
		return nil, err
	}
	for _, member := range m.Result.Members {
		if val, ok := member["type"]; ok {
			if t, ok := val.(string); ok {
				if t == "user" {
					ret.Repo.Users = append(ret.Repo.Users, repoUser(member))
				} else if t == "users_group" {
					ret.Repo.UsersGroups = append(ret.Repo.UsersGroups, repoUsersGroup(member))
				}
			}
		}
	}

	return ret, nil
}

func repoUser(member map[string]interface{}) *RepoUser {
	r := new(RepoUser)
	userId, _ := member["user_id"].(float64)
	r.UserId = int(userId)
	r.Username, _ = member["username"].(string)
	r.Firstname, _ = member["firstname"].(string)
	r.Lastname, _ = member["lastname"].(string)
	r.Email, _ = member["email"].(string)
	r.Emails, _ = member["emails"].([]string)
	r.ApiKey, _ = member["api_key"].(string)
	r.IPAddresses, _ = member["ip_addresses"].([]string)
	r.Active, _ = member["active"].(bool)
	r.Admin, _ = member["admin"].(bool)
	if member["ldap_dn"] != nil {
		ldapDN, _ := member["ldap_dn"].(string)
		r.LdapDN = Nstring(ldapDN)
	}
	if member["last_login"] != nil {
		lastLogin, _ := member["last_login"].(string)
		r.LastLogin = Nstring(lastLogin)
	}
	permission, _ := member["permission"].(string)
	r.Permission = strToPermission(permission)
	return r
}

func repoUsersGroup(member map[string]interface{}) *RepoUsersGroup {
	r := new(RepoUsersGroup)
	usersGroupId, _ := member["users_group_id"].(float64)
	r.UsersGroupId = int(usersGroupId)
	r.GroupName, _ = member["group_name"].(string)
	r.Active, _ = member["active"].(bool)
	permission, _ := member["permission"].(string)
	r.Permission = strToPermission(permission)
	return r
}

//-------------------------------------------------------------------------
// insert repo
//-------------------------------------------------------------------------

type ReposInsertCall struct {
	s    *Service
	repo *Repo
}

type ReposInsertResult struct {
	Id     int         `json:"id"`
	Result *RepoResult `json:"result"`
}

func (r *ReposService) Insert(repo *Repo) *ReposInsertCall {
	return &ReposInsertCall{r.s, repo}
}

func (c *ReposInsertCall) Do(resId int) (*ReposInsertResult, error) {
	args := make(map[string]string)
	args["repo_name"] = c.repo.RepoName
	if c.repo.Owner != "" {
		args["owner"] = c.repo.Owner
	}
	if c.repo.RepoType != "" {
		args["repo_type"] = c.repo.RepoType
	}
	if c.repo.Description != "" {
		args["description"] = c.repo.Description
	}
	args["private"] = strconv.Itoa(btoi(c.repo.Private))
	if c.repo.CloneUri != "" {
		args["clone_uri"] = string(c.repo.CloneUri)
	}
	if c.repo.LandingRev != "" {
		args["landing_rev"] = c.repo.LandingRev
	}
	args["enable_downloads"] = strconv.Itoa(btoi(c.repo.EnableDownloads))
	args["enable_locking"] = strconv.Itoa(btoi(c.repo.EnableLocking))
	args["enable_statistics"] = strconv.Itoa(btoi(c.repo.EnableStatistics))
	data, err := c.s.doRequest(resId, "create_repo", args)
	if err != nil {
		return nil, err
	}
	ret := new(ReposInsertResult)
	err = json.Unmarshal(data, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

//-------------------------------------------------------------------------
// delete repo
//-------------------------------------------------------------------------

type ReposDeleteCall struct {
	s    *Service
	repo string
}

type ReposDeleteResult struct {
	Id     int              `json:"id"`
	Result *OperationResult `json:"result"`
}

func (r *ReposService) Delete(repo string) *ReposDeleteCall {
	return &ReposDeleteCall{r.s, repo}
}

func (c *ReposDeleteCall) Do(resId int) (*ReposDeleteResult, error) {
	args := make(map[string]string)
	args["repoid"] = c.repo
	data, err := c.s.doRequest(resId, "delete_repo", args)
	if err != nil {
		return nil, err
	}
	ret := new(ReposDeleteResult)
	err = json.Unmarshal(data, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

//-------------------------------------------------------------------------
// pull
//-------------------------------------------------------------------------

type ReposPullCall struct {
	s    *Service
	repo string
}

type ReposPullResult struct {
	Id     int    `json:"id"`
	Result string `json:"result"`
}

func (r *ReposService) Pull(repo string) *ReposPullCall {
	return &ReposPullCall{r.s, repo}
}

func (c *ReposPullCall) Do(resId int) (*ReposPullResult, error) {
	args := make(map[string]string)
	args["repoid"] = c.repo
	data, err := c.s.doRequest(resId, "pull", args)
	if err != nil {
		return nil, err
	}
	ret := new(ReposPullResult)
	err = json.Unmarshal(data, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

//-------------------------------------------------------------------------
// lock
//-------------------------------------------------------------------------

type ReposLockCall struct {
	s      *Service
	repo   string
	user   string
	locked bool
}

type ReposLockResult struct {
	Id     int    `json:"id"`
	Result string `json:"result"`
}

func (r *ReposService) Lock(repo, user string) *ReposLockCall {
	return &ReposLockCall{r.s, repo, user, true}
}

func (r *ReposService) Unlock(repo, user string) *ReposLockCall {
	return &ReposLockCall{r.s, repo, user, false}
}

func (c *ReposLockCall) Do(resId int) (*ReposLockResult, error) {
	args := make(map[string]string)
	args["repoid"] = c.repo
	if c.user != "" {
		args["userid"] = c.user
	}
	args["locked"] = strconv.Itoa(btoi(c.locked))
	data, err := c.s.doRequest(resId, "lock", args)
	if err != nil {
		return nil, err
	}
	ret := new(ReposLockResult)
	err = json.Unmarshal(data, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

//-------------------------------------------------------------------------
// fork
//-------------------------------------------------------------------------

type RepoFork struct {
	ForkName        string `json:"fork_name"`
	Owner           string `json:"owner"`
	Description     string `json:"description"`
	CopyPermissions bool   `json:"copy_permissions"`
	Private         bool   `json:"private"`
	LandingRev      string `json:"landing_rev"`
}

type ReposForkCall struct {
	s    *Service
	repo string
	fork *RepoFork
}

type ReposForkResult struct {
	Id     int              `json:"id"`
	Result *OperationResult `json:"result"`
}

func (r *ReposService) Fork(repo string, fork *RepoFork) *ReposForkCall {
	return &ReposForkCall{r.s, repo, fork}
}

func (c *ReposForkCall) Do(resId int) (*ReposForkResult, error) {
	args := make(map[string]string)
	args["repoid"] = c.repo
	args["fork_name"] = c.fork.ForkName
	if c.fork.Owner != "" {
		args["owner"] = c.fork.Owner
	}
	if c.fork.Description != "" {
		args["description"] = c.fork.Description
	}
	args["copy_permissions"] = strconv.Itoa(btoi(c.fork.CopyPermissions))
	args["private"] = strconv.Itoa(btoi(c.fork.Private))
	if c.fork.LandingRev != "" {
		args["landing_rev"] = c.fork.LandingRev
	}
	data, err := c.s.doRequest(resId, "fork_repo", args)
	if err != nil {
		return nil, err
	}
	ret := new(ReposForkResult)
	err = json.Unmarshal(data, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

//-------------------------------------------------------------------------
// list repo nodes
//-------------------------------------------------------------------------

type RepoNode struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type ReposNodesCall struct {
	s        *Service
	repo     string
	revision string
	rootPath string
	retType  string
}

type ReposNodesResult struct {
	Id        int         `json:"id"`
	RepoNodes []*RepoNode `json:"result"`
}

func (r *ReposService) Nodes(repo, revision, rootPath string) *ReposNodesCall {
	return &ReposNodesCall{r.s, repo, revision, rootPath, "all"}
}

func (c *ReposNodesCall) RetType(files, dirs bool) *ReposNodesCall {
	if files && !dirs {
		c.retType = "files"
	} else if !files && dirs {
		c.retType = "dirs"
	} else {
		c.retType = "all"
	}
	return c
}

func (c *ReposNodesCall) Do(resId int) (*ReposNodesResult, error) {
	args := make(map[string]string)
	args["repoid"] = c.repo
	args["revision"] = c.revision
	args["root_path"] = c.rootPath
	args["ret_type"] = c.retType
	data, err := c.s.doRequest(resId, "get_repo_nodes", args)
	if err != nil {
		return nil, err
	}
	ret := new(ReposNodesResult)
	err = json.Unmarshal(data, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

//-------------------------------------------------------------------------
// rescan repos
//-------------------------------------------------------------------------

type ReposRescanCall struct {
	s              *Service
	removeObsolete bool
}

type ReposRescanResult struct {
	Id     int           `json:"id"`
	Result *RescanResult `json:"result"`
}

type RescanResult struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
}

func (r *ReposService) Rescan(removeObsolete bool) *ReposRescanCall {
	return &ReposRescanCall{r.s, removeObsolete}
}

func (c *ReposRescanCall) Do(resId int) (*ReposRescanResult, error) {
	args := make(map[string]string)
	args["remove_obsolete"] = strconv.Itoa(btoi(c.removeObsolete))
	data, err := c.s.doRequest(resId, "rescan_repos", args)
	if err != nil {
		return nil, err
	}
	ret := new(ReposRescanResult)
	err = json.Unmarshal(data, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

//-------------------------------------------------------------------------
// permissions
//-------------------------------------------------------------------------

type Permission int

const (
	PermissionNone Permission = iota
	PermissionRead
	PermissionWrite
	PermissionAdmin
)

func (p *Permission) String() string {
	switch *p {
	case PermissionRead:
		return "repository.read"
	case PermissionWrite:
		return "repository.write"
	case PermissionAdmin:
		return "repository.admin"
	}
	return "repository.none"
}

func strToPermission(permission string) Permission {
	switch permission {
	case "repository.read":
		return PermissionRead
	case "repository.write":
		return PermissionWrite
	case "repository.admin":
		return PermissionAdmin
	}
	return PermissionNone
}

//-------------------------------------------------------------------------
// grant user permission
//-------------------------------------------------------------------------

type GrantUserPermissionCall struct {
	s    *Service
	repo string
	user string
	perm Permission
}

type GrantUserPermissionResult struct {
	Id     int              `json:"id"`
	Result *OperationResult `json:"result"`
}

func (r *PermissionsService) GrantUserPermission(repo, user string, perm Permission) *GrantUserPermissionCall {
	return &GrantUserPermissionCall{r.s, repo, user, perm}
}

func (c *GrantUserPermissionCall) Do(resId int) (*GrantUserPermissionResult, error) {
	args := make(map[string]string)
	args["repoid"] = c.repo
	args["userid"] = c.user
	args["perm"] = c.perm.String()
	data, err := c.s.doRequest(resId, "grant_user_permission", args)
	if err != nil {
		return nil, err
	}
	ret := new(GrantUserPermissionResult)
	err = json.Unmarshal(data, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

//-------------------------------------------------------------------------
// revoke user permission
//-------------------------------------------------------------------------

type RevokeUserPermissionCall struct {
	s    *Service
	repo string
	user string
}

type RevokeUserPermissionResult struct {
	Id     int              `json:"id"`
	Result *OperationResult `json:"result"`
}

func (r *PermissionsService) RevokeUserPermission(repo, user string) *RevokeUserPermissionCall {
	return &RevokeUserPermissionCall{r.s, repo, user}
}

func (c *RevokeUserPermissionCall) Do(resId int) (*RevokeUserPermissionResult, error) {
	args := make(map[string]string)
	args["repoid"] = c.repo
	args["userid"] = c.user
	data, err := c.s.doRequest(resId, "revoke_user_permission", args)
	if err != nil {
		return nil, err
	}
	ret := new(RevokeUserPermissionResult)
	err = json.Unmarshal(data, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

//-------------------------------------------------------------------------
// grant users group permission
//-------------------------------------------------------------------------

type GrantUsersGroupPermissionCall struct {
	s          *Service
	repo       string
	usersGroup string
	perm       Permission
}

type GrantUsersGroupPermissionResult struct {
	Id     int              `json:"id"`
	Result *OperationResult `json:"result"`
}

func (r *PermissionsService) GrantUsersGroupPermission(repo, usersGroup string, perm Permission) *GrantUsersGroupPermissionCall {
	return &GrantUsersGroupPermissionCall{r.s, repo, usersGroup, perm}
}

func (c *GrantUsersGroupPermissionCall) Do(resId int) (*GrantUsersGroupPermissionResult, error) {
	args := make(map[string]string)
	args["repoid"] = c.repo
	args["usersgroupid"] = c.usersGroup
	args["perm"] = c.perm.String()
	data, err := c.s.doRequest(resId, "grant_users_group_permission", args)
	if err != nil {
		return nil, err
	}
	ret := new(GrantUsersGroupPermissionResult)
	err = json.Unmarshal(data, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

//-------------------------------------------------------------------------
// revoke users group permission
//-------------------------------------------------------------------------

type RevokeUsersGroupPermissionCall struct {
	s          *Service
	repo       string
	usersGroup string
}

type RevokeUsersGroupPermissionResult struct {
	Id     int              `json:"id"`
	Result *OperationResult `json:"result"`
}

func (r *PermissionsService) RevokeUsersGroupPermission(repo, usersGroup string) *RevokeUsersGroupPermissionCall {
	return &RevokeUsersGroupPermissionCall{r.s, repo, usersGroup}
}

func (c *RevokeUsersGroupPermissionCall) Do(resId int) (*RevokeUsersGroupPermissionResult, error) {
	args := make(map[string]string)
	args["repoid"] = c.repo
	args["usersgroupid"] = c.usersGroup
	data, err := c.s.doRequest(resId, "revoke_users_group_permission", args)
	if err != nil {
		return nil, err
	}
	ret := new(RevokeUsersGroupPermissionResult)
	err = json.Unmarshal(data, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}
