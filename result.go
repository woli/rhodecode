package rhodecode

import (
	"encoding/json"
	"errors"
)

type result struct {
	Id      int
	Msg     string
	Success bool
}

type resultDec struct {
	Id      *int    `json:"id"`
	Msg     *string `json:"msg"`
	Success *bool   `json:"success"`
}

func (r *resultDec) decode() *result {
	return &result{
		Id:      ptrToInt(r.Id),
		Msg:     ptrToString(r.Msg),
		Success: ptrToBool(r.Success),
	}
}

func unmarshalResult(data []byte) (int, error) {
	type response struct {
		Id     string      `json:"id"`
		Result *resultDec  `json:"result"`
		Error  interface{} `json:"error"`
	}

	res := &response{}
	err := json.Unmarshal(data, &res)
	if err != nil {
		return 0, err
	}

	if res.Error != nil {
		return 0, castError(res.Error)
	}

	if res.Result == nil {
		return 0, errors.New("") // todo
	}

	result := res.Result.decode()
	if res.Result.Success != nil && !result.Success {
		return 0, errors.New(result.Msg)
	}

	return result.Id, nil
}
