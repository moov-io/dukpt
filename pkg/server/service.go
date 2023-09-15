package server

import (
	"errors"
	"fmt"
	"github.com/moov-io/dukpt/pkg"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
)

// Service is a REST interface for interacting with machine structures
type Service interface {
	CreateMachine(m *Machine) error
	GetMachine(ik string) (*Machine, error)
	GetMachines() []*Machine
	MakeNextKSN(ik string) (*Machine, error)
	DeleteMachine(ik string) error
	EncryptPin(ik, pin, pan, format string) (string, error)
	DecryptPin(ik, ciphertext, pan, format string) (string, error)
	GenerateMac(ik, data, action, macType string) (string, error)
	EncryptData(ik, data, action, iv string) (string, error)
	DecryptData(ik, ciphertext, action, iv string) (string, error)
}

// service a concrete implementation of the service.
type service struct {
	store Repository
}

// NewService creates a new concrete service
func NewService(r Repository) Service {
	return &service{
		store: r,
	}
}

// CreateMachine add a machine to storage
func (s *service) CreateMachine(m *Machine) error {
	if m == nil {
		return ErrNotFound
	}

	params := UnifiedParams{
		Algorithm:        m.Algorithm,
		AlgorithmKeyType: m.AlgorithmKey,
		KSN:              m.KeySerialNumber,
		BKD:              m.BaseDerivativeKey,
	}

	if err := params.ValidateAlgorithm(); err != nil {
		return err
	}

	ik, err := InitialKey(params)
	if err != nil {
		return err
	}

	m.InitialKey = ik

	// getting transaction key
	params.IK = ik
	m.TransactionKey, err = TransactionKey(params)
	if err != nil {
		return err
	}

	if err = s.store.StoreMachine(m); err != nil {
		return err
	}

	return nil
}

// GetMachine returns a machine based on the supplied initial key
func (s *service) GetMachine(ik string) (*Machine, error) {
	f, err := s.store.FindMachine(ik)
	if err != nil {
		return nil, ErrNotFound
	}
	return f, nil
}

func (s *service) GetMachines() []*Machine {
	return s.store.FindAllMachines()
}

// MakeNextKSN does to generate next ksn
func (s *service) MakeNextKSN(ik string) (*Machine, error) {
	m, err := s.GetMachine(ik)
	if err != nil {
		return nil, fmt.Errorf("make next ksn: %v(%s)", err, ik)
	}

	var nextKsn []byte
	if m.Algorithm == "aes" {
		nextKsn, err = pkg.GenerateNextAesKsn(pkg.HexDecode(m.CurrentKSN))
		if err != nil {
			return nil, err
		}
	} else {
		nextKsn, err = pkg.GenerateNextDesKsn(pkg.HexDecode(m.CurrentKSN))
		if err != nil {
			return nil, err
		}
	}

	// update machine
	m.CurrentKSN = pkg.HexEncode(nextKsn)

	params := UnifiedParams{
		Algorithm:        m.Algorithm,
		AlgorithmKeyType: m.AlgorithmKey,
		KSN:              m.CurrentKSN,
		IK:               ik,
	}
	m.TransactionKey, err = TransactionKey(params)
	if err != nil {
		return nil, err
	}

	return m, err
}

func (s *service) DeleteMachine(ik string) error {
	return s.store.DeleteMachine(ik)
}

func (s *service) EncryptPin(ik, pin, pan, format string) (string, error) {
	m, err := s.GetMachine(ik)
	if err != nil {
		return "", fmt.Errorf("make next ksn: %v(%s)", err, ik)
	}

	params := UnifiedParams{
		Algorithm:        m.Algorithm,
		AlgorithmKeyType: m.AlgorithmKey,
		TK:               m.TransactionKey,
		KSN:              m.CurrentKSN,
		IK:               ik,
		Format:           format,
		PIN:              pin,
		PAN:              pan,
	}

	if params.Format == "" {
		params.Format = "ISO-0"
	}

	return EncryptPin(params)
}

func (s *service) DecryptPin(ik, ciphertext, pan, format string) (string, error) {
	m, err := s.GetMachine(ik)
	if err != nil {
		return "", fmt.Errorf("make next ksn: %v(%s)", err, ik)
	}

	params := UnifiedParams{
		Algorithm:        m.Algorithm,
		AlgorithmKeyType: m.AlgorithmKey,
		TK:               m.TransactionKey,
		KSN:              m.CurrentKSN,
		IK:               ik,
		Format:           format,
		PIN:              ciphertext,
		PAN:              pan,
	}

	if params.Format == "" {
		params.Format = "ISO-0"
	}

	return EncryptPin(params)
}

func (s *service) GenerateMac(ik, data, action, macType string) (string, error) {
	m, err := s.GetMachine(ik)
	if err != nil {
		return "", fmt.Errorf("make next ksn: %v(%s)", err, ik)
	}

	params := UnifiedParams{
		Algorithm:        m.Algorithm,
		AlgorithmKeyType: m.AlgorithmKey,
		TK:               m.TransactionKey,
		KSN:              m.CurrentKSN,
		IK:               ik,
		Plaintext:        data,
		Action:           action,
		MacType:          macType,
	}

	return GenerateMac(params)
}

func (s *service) EncryptData(ik, data, action, iv string) (string, error) {
	m, err := s.GetMachine(ik)
	if err != nil {
		return "", fmt.Errorf("make next ksn: %v(%s)", err, ik)
	}

	params := UnifiedParams{
		Algorithm:        m.Algorithm,
		AlgorithmKeyType: m.AlgorithmKey,
		TK:               m.TransactionKey,
		KSN:              m.CurrentKSN,
		IK:               ik,
		Plaintext:        data,
		Action:           action,
		IV:               iv,
	}

	return EncryptData(params)
}

func (s *service) DecryptData(ik, ciphertext, action, iv string) (string, error) {
	m, err := s.GetMachine(ik)
	if err != nil {
		return "", fmt.Errorf("make next ksn: %v(%s)", err, ik)
	}

	params := UnifiedParams{
		Algorithm:        m.Algorithm,
		AlgorithmKeyType: m.AlgorithmKey,
		TK:               m.TransactionKey,
		KSN:              m.CurrentKSN,
		IK:               ik,
		Ciphertext:       ciphertext,
		Action:           action,
		IV:               iv,
	}

	return DecryptData(params)
}
