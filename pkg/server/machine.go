package server

import (
	"time"
)

type BaseKey struct {
	Algorithm         string
	AlgorithmKey      string
	BaseDerivativeKey string
	KeySerialNumber   string
}

type Machine struct {
	BaseKey
	InitialKey     string
	CurrentKSN     string
	TransactionKey string
	CreatedAt      time.Time
}

func NewMachine(b BaseKey) *Machine {
	return &Machine{
		BaseKey:    b,
		CurrentKSN: b.KeySerialNumber,
	}
}
