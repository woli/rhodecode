package rhodecode

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
)

type request struct {
	url    string
	Id     string            `json:"id"`
	ApiKey string            `json:"api_key"`
	Method string            `json:"method"`
	Args   map[string]string `json:"args"`
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
