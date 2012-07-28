package rhodecode

import (
	"encoding/json"
	"errors"
)

type UsersGroup struct {
	Id      int
	Name    string
	Active  bool
	Members []*User
}

type usersGroupDec struct {
	Id      *int       `json:"id"`
	Name    *string    `json:"group_name"`
	Active  *bool      `json:"active"`
	Members []*userDec `json:"members"`
}

func (u *usersGroupDec) decode() *UsersGroup {
	dec := &UsersGroup{
		Id:     ptrToInt(u.Id),
		Name:   ptrToString(u.Name),
		Active: ptrToBool(u.Active),
	}

	if u.Members != nil {
		dec.Members = make([]*User, len(u.Members))
		for i := range u.Members {
			dec.Members[i] = u.Members[i].decode()
		}
	}

	return dec
}

func unmarshalUsersGroup(data []byte) (*UsersGroup, error) {
	type response struct {
		Id     string         `json:"id"`
		Result *usersGroupDec `json:"result"`
		Error  interface{}    `json:"error"`
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
		return nil, errors.New("UsersGroup not found")
	}

	return res.Result.decode(), nil
}

func unmarshalUsersGroups(data []byte) ([]*UsersGroup, error) {
	type response struct {
		Id     string           `json:"id"`
		Result []*usersGroupDec `json:"result"`
		Error  interface{}      `json:"error"`
	}

	res := &response{}
	err := json.Unmarshal(data, &res)
	if err != nil {
		return nil, err
	}

	if res.Error != nil {
		return nil, castError(res.Error)
	}

	usersGroups := make([]*UsersGroup, len(res.Result))
	for i := range res.Result {
		usersGroups[i] = res.Result[i].decode()
	}

	return usersGroups, nil
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

	return unmarshalUsersGroup(data)
}

// Lists all existing users groups.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) GetUsersGroups(id string) ([]*UsersGroup, error) {
	req := r.newRequest(id, "get_users_groups")

	data, err := req.send()
	if err != nil {
		return nil, err
	}

	return unmarshalUsersGroups(data)
}

// Creates new users group.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) CreateUsersGroup(id string, group *UsersGroup) (int, error) {
	req := r.newRequest(id, "create_users_group")
	req.Args["group_name"] = group.Name
	req.Args["active"] = boolToIntString(group.Active)

	data, err := req.send()
	if err != nil {
		return 0, err
	}

	return unmarshalResult(data)
}

// Adds a user to a users group.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) AddUserToUsersGroup(id, groupName, username string) (int, error) {
	req := r.newRequest(id, "add_user_to_users_group")
	req.Args["group_name"] = groupName
	req.Args["username"] = username

	data, err := req.send()
	if err != nil {
		return 0, err
	}

	return unmarshalResult(data)
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

	_, err = unmarshalResult(data)
	return err
}
