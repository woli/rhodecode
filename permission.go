package rhodecode

type Permission int

const (
	PERMISSION_NONE Permission = iota
	PERMISSION_READ
	PERMISSION_WRITE
	PERMISSION_ADMIN
)

func permissionToString(p Permission) string {
	switch p {
	case PERMISSION_READ:
		return "repository.read"
	case PERMISSION_WRITE:
		return "repository.write"
	case PERMISSION_ADMIN:
		return "repository.admin"
	}

	return "repository.none"
}

// Grant permission for user on given repository, or update existing one if found.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) GrantUserPermission(id, repoName, username string, p Permission) error {
	req := r.newRequest(id, "grant_user_permission")
	req.Args["repo_name"] = repoName
	req.Args["username"] = username
	req.Args["perm"] = permissionToString(p)

	data, err := req.send()
	if err != nil {
		return err
	}

	_, err = unmarshalResult(data)
	return err
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

	_, err = unmarshalResult(data)
	return err
}

// Grant permission for users group on given repository, or update existing one if found.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) GrantUsersGroupPermission(id, repoName, groupName string, p Permission) error {
	req := r.newRequest(id, "grant_users_group_permission")
	req.Args["repo_name"] = repoName
	req.Args["group_name"] = groupName
	req.Args["perm"] = permissionToString(p)

	data, err := req.send()
	if err != nil {
		return err
	}

	_, err = unmarshalResult(data)
	return err
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

	_, err = unmarshalResult(data)
	return err
}
