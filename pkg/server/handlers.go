package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	"github.com/gorilla/mux"
	moovhttp "github.com/moov-io/base/http"
)

func bindJSON(request *http.Request, params interface{}) (err error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return fmt.Errorf("could not parse json request: %s", err)
	}

	err = json.Unmarshal(body, params)
	if err != nil {
		return fmt.Errorf("could not parse json request: %s", err)
	}
	return
}

type getMachinesRequest struct {
	requestID string
}

type getMachinesResponse struct {
	Machines []*Machine `json:"machines"`
	Err      error      `json:"error"`
}

func decodeGetMachinesRequest(_ context.Context, request *http.Request) (interface{}, error) {
	return getMachinesRequest{
		requestID: moovhttp.GetRequestID(request),
	}, nil
}

func getMachinesEndpoint(s Service) endpoint.Endpoint {
	return func(_ context.Context, _ interface{}) (interface{}, error) {
		return getMachinesResponse{
			Machines: s.GetMachines(),
			Err:      nil,
		}, nil
	}
}

type findMachineRequest struct {
	requestID string
	ik        string
}

type findMachineResponse struct {
	Machine *Machine `json:"machine"`
	Err     error    `json:"error"`
}

func decodeFindMachineRequest(_ context.Context, request *http.Request) (interface{}, error) {
	req := findMachineRequest{
		requestID: moovhttp.GetRequestID(request),
	}

	ik, _ := mux.Vars(request)["ik"]
	req.ik = ik

	return req, nil
}

func findMachineEndpoint(s Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(findMachineRequest)
		if !ok {
			return generateKSNResponse{Err: ErrFoundABug}, ErrFoundABug
		}

		resp := findMachineResponse{}
		m, err := s.GetMachine(req.ik)
		if err != nil {
			resp.Err = err
			return resp, nil
		}

		resp.Machine = m
		return resp, nil
	}
}

type createMachineRequest struct {
	BaseKey   BaseKey
	requestID string
}

type createMachineResponse struct {
	IK      string   `json:"ik"`
	Machine *Machine `json:"machine"`
	Err     error    `json:"error"`
}

func decodeCreateMachineRequest(_ context.Context, request *http.Request) (interface{}, error) {
	req := createMachineRequest{
		requestID: moovhttp.GetRequestID(request),
	}

	if err := bindJSON(request, &req.BaseKey); err != nil {
		return nil, err
	}

	return req, nil
}

func createMachineEndpoint(s Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(createMachineRequest)
		if !ok {
			return createMachineResponse{Err: ErrFoundABug}, ErrFoundABug
		}

		resp := createMachineResponse{}

		m := NewMachine(req.BaseKey)
		err := s.CreateMachine(m)
		if err != nil {
			resp.Err = err
			return resp, nil
		}

		resp.Machine = m
		resp.IK = m.InitialKey

		return resp, nil
	}
}

type generateKSNRequest struct {
	requestID string
	ik        string
}

type generateKSNResponse struct {
	KSN string `json:"ksn"`
	Err error  `json:"error"`
}

func decodeGenerateKSNRequest(_ context.Context, request *http.Request) (interface{}, error) {
	req := generateKSNRequest{
		requestID: moovhttp.GetRequestID(request),
	}

	ik, _ := mux.Vars(request)["ik"]
	req.ik = ik

	return req, nil
}

func generateKSNEndpoint(s Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(generateKSNRequest)
		if !ok {
			return generateKSNResponse{Err: ErrFoundABug}, ErrFoundABug
		}

		resp := generateKSNResponse{}
		m, err := s.MakeNextKSN(req.ik)
		if err != nil {
			resp.Err = err
			return resp, nil
		}

		resp.KSN = m.CurrentKSN
		return resp, nil
	}
}

type encryptPinRequest struct {
	requestID string
	ik        string
	pin       string
	pan       string
	format    string
}

type encryptPinResponse struct {
	Encrypted string `json:"encrypted"`
	Err       error  `json:"error"`
}

func decodeEncryptPinRequest(_ context.Context, request *http.Request) (interface{}, error) {
	req := encryptPinRequest{
		requestID: moovhttp.GetRequestID(request),
	}

	ik, _ := mux.Vars(request)["ik"]
	req.ik = ik

	type requestParam struct {
		Pin    string
		Pan    string
		Format string
	}

	reqParams := requestParam{}
	if err := bindJSON(request, &reqParams); err != nil {
		return nil, err
	}

	req.pin = reqParams.Pin
	req.pan = reqParams.Pan
	req.format = reqParams.Format

	return req, nil
}

func encryptPinEndpoint(s Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(encryptPinRequest)
		if !ok {
			return encryptPinResponse{Err: ErrFoundABug}, ErrFoundABug
		}

		resp := encryptPinResponse{}
		encrypted, err := s.EncryptPin(req.ik, req.pin, req.pan, req.format)
		if err != nil {
			resp.Err = err
			return resp, nil
		}

		resp.Encrypted = encrypted
		return resp, nil
	}
}

type decryptPinRequest struct {
	requestID string
	ik        string
	encrypted string
	pan       string
	format    string
}

type decryptPinResponse struct {
	Decrypted string `json:"decrypted"`
	Err       error  `json:"error"`
}

func decodeDecryptPinRequest(_ context.Context, request *http.Request) (interface{}, error) {
	req := decryptPinRequest{
		requestID: moovhttp.GetRequestID(request),
	}

	ik, _ := mux.Vars(request)["ik"]
	req.ik = ik

	type requestParam struct {
		Encrypted string
		Pan       string
		Format    string
	}

	reqParams := requestParam{}
	if err := bindJSON(request, &reqParams); err != nil {
		return nil, err
	}

	req.encrypted = reqParams.Encrypted
	req.pan = reqParams.Pan
	req.format = reqParams.Format

	return req, nil
}

func decryptPinEndpoint(s Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(decryptPinRequest)
		if !ok {
			return decryptPinResponse{Err: ErrFoundABug}, ErrFoundABug
		}

		resp := decryptPinResponse{}
		decrypted, err := s.EncryptPin(req.ik, req.encrypted, req.pan, req.format)
		if err != nil {
			resp.Err = err
			return resp, nil
		}

		resp.Decrypted = decrypted
		return resp, nil
	}
}

type generateMacRequest struct {
	requestID string
	ik        string
	action    string
	data      string
	macType   string
}

type generateMacResponse struct {
	Generated string `json:"generated"`
	Err       error  `json:"error"`
}

func decodeGenerateMacRequest(_ context.Context, request *http.Request) (interface{}, error) {
	req := generateMacRequest{
		requestID: moovhttp.GetRequestID(request),
	}

	ik, _ := mux.Vars(request)["ik"]
	req.ik = ik

	type requestParam struct {
		Action  string
		Data    string
		MacType string
	}

	reqParams := requestParam{}
	if err := bindJSON(request, &reqParams); err != nil {
		return nil, err
	}

	req.action = reqParams.Action
	req.data = reqParams.Data
	req.macType = reqParams.MacType

	return req, nil
}

func generateMacEndpoint(s Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(generateMacRequest)
		if !ok {
			return generateMacResponse{Err: ErrFoundABug}, ErrFoundABug
		}

		resp := generateMacResponse{}
		encrypted, err := s.GenerateMac(req.ik, req.data, req.action, req.macType)
		if err != nil {
			resp.Err = err
			return resp, nil
		}

		resp.Generated = encrypted
		return resp, nil
	}
}

type encryptDataRequest struct {
	requestID string
	ik        string
	action    string
	data      string
	iv        string
}

type encryptDataResponse struct {
	Encrypted string `json:"encrypted"`
	Err       error  `json:"error"`
}

func decodeEncryptDataRequest(_ context.Context, request *http.Request) (interface{}, error) {
	req := encryptDataRequest{
		requestID: moovhttp.GetRequestID(request),
	}

	ik, _ := mux.Vars(request)["ik"]
	req.ik = ik

	type requestParam struct {
		Action string
		Data   string
		Iv     string
	}

	reqParams := requestParam{}
	if err := bindJSON(request, &reqParams); err != nil {
		return nil, err
	}

	req.action = reqParams.Action
	req.data = reqParams.Data
	req.iv = reqParams.Iv

	return req, nil
}

func encryptDataEndpoint(s Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(encryptDataRequest)
		if !ok {
			return encryptDataResponse{Err: ErrFoundABug}, ErrFoundABug
		}

		resp := encryptDataResponse{}
		encrypted, err := s.EncryptData(req.ik, req.data, req.action, req.iv)
		if err != nil {
			resp.Err = err
			return resp, nil
		}

		resp.Encrypted = encrypted
		return resp, nil
	}
}

type decryptDataRequest struct {
	requestID string
	ik        string
	action    string
	data      string
	iv        string
}

type decryptDataResponse struct {
	Data string `json:"data"`
	Err  error  `json:"error"`
}

func decodeDecryptDataRequest(_ context.Context, request *http.Request) (interface{}, error) {
	req := decryptDataRequest{
		requestID: moovhttp.GetRequestID(request),
	}

	ik, _ := mux.Vars(request)["ik"]
	req.ik = ik

	type requestParam struct {
		Action string
		Data   string
		Iv     string
	}

	reqParams := requestParam{}
	if err := bindJSON(request, &reqParams); err != nil {
		return nil, err
	}

	req.action = reqParams.Action
	req.data = reqParams.Data
	req.iv = reqParams.Iv

	return req, nil
}

func decryptDataEndpoint(s Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(decryptDataRequest)
		if !ok {
			return decryptDataResponse{Err: ErrFoundABug}, ErrFoundABug
		}

		resp := decryptDataResponse{}
		decrypted, err := s.EncryptData(req.ik, req.data, req.action, req.iv)
		if err != nil {
			resp.Err = err
			return resp, nil
		}

		resp.Data = decrypted
		return resp, nil
	}
}
