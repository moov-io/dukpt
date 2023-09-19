package server

import (
	"errors"
	"sync"

	"github.com/moov-io/base/log"
)

// Repository is the Service storage mechanism abstraction
type Repository interface {
	StoreMachine(m *Machine) error
	FindMachine(ik string) (*Machine, error)
	FindAllMachines() []*Machine
	DeleteMachine(ik string) error
}

type repositoryInMemory struct {
	mtx      sync.RWMutex
	machines map[string]*Machine
	logger   log.Logger
}

// NewRepositoryInMemory is an in memory ach storage repository for machines
func NewRepositoryInMemory(logger log.Logger) Repository {
	repo := &repositoryInMemory{
		machines: make(map[string]*Machine),
		logger:   logger,
	}

	return repo
}

// StoreMachine create new machine based on the supplied initial key
func (r *repositoryInMemory) StoreMachine(m *Machine) error {
	if m == nil {
		return errors.New("nil machine provided")
	}

	r.mtx.Lock()
	defer r.mtx.Unlock()
	if _, ok := r.machines[m.InitialKey]; ok {
		return ErrAlreadyExists
	}
	r.machines[m.InitialKey] = m
	return nil
}

// FindMachine retrieves a machine based on the supplied initial key
func (r *repositoryInMemory) FindMachine(ik string) (*Machine, error) {
	r.mtx.RLock()
	defer r.mtx.RUnlock()
	if val, ok := r.machines[ik]; ok {
		return val, nil
	}
	return nil, ErrNotFound
}

// FindAllMachines returns all machines that have been saved in memory
func (r *repositoryInMemory) FindAllMachines() []*Machine {
	r.mtx.RLock()
	defer r.mtx.RUnlock()
	files := make([]*Machine, 0, len(r.machines))
	for i := range r.machines {
		files = append(files, r.machines[i])
	}
	return files
}

// DeleteMachine removes a machine that have been saved in memory by the supplied initial key
func (r *repositoryInMemory) DeleteMachine(ik string) error {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	delete(r.machines, ik)
	return nil
}
