package server

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func mockServiceInMemory() Service {
	repository := NewRepositoryInMemory(nil)
	return NewService(repository)
}

func mockBaseDesKey() BaseKey {
	return BaseKey{
		Algorithm:         "des",
		BaseDerivativeKey: "0123456789ABCDEFFEDCBA9876543210",
		KeySerialNumber:   "FFFF9876543210E00001",
	}
}

func mockBaseAesKey() BaseKey {
	return BaseKey{
		Algorithm:         "des",
		BaseDerivativeKey: "FEDCBA9876543210F1F1F1F1F1F1F1F1",
		KeySerialNumber:   "12345678901234560001",
	}
}

func TestServer__CreateMachine(t *testing.T) {
	s := mockServiceInMemory()
	mDes := NewMachine(mockBaseDesKey())
	err := s.CreateMachine(mDes)
	require.NoError(t, err)

	err = s.CreateMachine(mDes)
	require.Equal(t, "already exists", err.Error())

	mAes := NewMachine(mockBaseAesKey())
	err = s.CreateMachine(mAes)
	require.NoError(t, err)

	err = s.CreateMachine(mAes)
	require.Equal(t, "already exists", err.Error())
}

func TestServer__GetMachine(t *testing.T) {
	s := mockServiceInMemory()
	m := NewMachine(mockBaseDesKey())
	s.CreateMachine(m)
	s.CreateMachine(NewMachine(mockBaseAesKey()))

	machines := s.GetMachines()
	require.Equal(t, "042666b49184cfa368de9628d0397bc9", machines[0].TransactionKey)
	require.Equal(t, "00e527d4b288b7b87b7ab90082e6fc94", machines[1].TransactionKey)

	machine, err := s.GetMachine(m.InitialKey)
	require.NoError(t, err)
	require.Equal(t, "042666b49184cfa368de9628d0397bc9", machine.TransactionKey)
}

func TestServer__DeleteMachine(t *testing.T) {
	s := mockServiceInMemory()
	m1 := NewMachine(mockBaseDesKey())
	m2 := NewMachine(mockBaseAesKey())
	s.CreateMachine(m1)
	s.CreateMachine(m2)

	machines := s.GetMachines()
	require.Equal(t, 2, len(machines))

	s.DeleteMachine(m1.InitialKey)
	s.DeleteMachine(m2.InitialKey)

	machines = s.GetMachines()
	require.Equal(t, 0, len(machines))
}

func TestServer__MakeNextKSN(t *testing.T) {
	s := mockServiceInMemory()

	m := NewMachine(mockBaseDesKey())
	s.CreateMachine(m)
	m, err := s.MakeNextKSN(m.InitialKey)
	require.NoError(t, err)
	require.Equal(t, "ffff9876543210e00002", m.CurrentKSN)

	m = NewMachine(mockBaseAesKey())
	s.CreateMachine(m)
	m, err = s.MakeNextKSN(m.InitialKey)
	require.NoError(t, err)
	require.Equal(t, "12345678901234560002", m.CurrentKSN)
}
