package rhodecode

import (
	"encoding/json"
)

type RetType int

const (
	RET_TYPE_ALL RetType = iota
	RET_TYPE_FILES
	RET_TYPE_DIRS
)

func retTypeToString(t RetType) string {
	switch t {
	case RET_TYPE_FILES:
		return "files"
	case RET_TYPE_DIRS:
		return "dirs"
	}

	return "all"
}

type RepoNode struct {
	Name string
	Type string
}

type repoNodeDec struct {
	Name *string `json:"name"`
	Type *string `json:"type"`
}

func (r *repoNodeDec) decode() *RepoNode {
	return &RepoNode{
		Name: ptrToString(r.Name),
		Type: ptrToString(r.Type),
	}
}

func unmarshalRepoNodes(data []byte) ([]*RepoNode, error) {
	type response struct {
		Id     string         `json:"id"`
		Result []*repoNodeDec `json:"result"`
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

	repoNodes := make([]*RepoNode, len(res.Result))
	for i := range res.Result {
		repoNodes[i] = res.Result[i].decode()
	}

	return repoNodes, nil
}

// Returns a list of nodes and it’s children in a flat list for a given path at given revision.
//	This command can be executed only using api_key belonging to user with admin rights.
func (r *RhodeCode) GetRepoNodes(id, repoName, revision, rootPath string, t RetType) ([]*RepoNode, error) {
	req := r.newRequest(id, "get_repo_nodes")
	req.Args["repo_name"] = repoName
	req.Args["revision"] = revision
	req.Args["root_path"] = rootPath
	req.Args["ret_type"] = retTypeToString(t)

	data, err := req.send()
	if err != nil {
		return nil, err
	}

	return unmarshalRepoNodes(data)
}
