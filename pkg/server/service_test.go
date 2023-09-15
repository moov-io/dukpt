package server

import (
	"strings"
	"testing"

	"github.com/moov-io/dukpt/pkg"
	"github.com/moov-io/dukpt/pkg/aes"
	"github.com/stretchr/testify/require"
)

func mockServiceInMemory() Service {
	repository := NewRepositoryInMemory(nil)
	return NewService(repository)
}

func mockBaseDesKey() BaseKey {
	return BaseKey{
		Algorithm:         pkg.AlgorithmDes,
		BaseDerivativeKey: "0123456789ABCDEFFEDCBA9876543210",
		KeySerialNumber:   "FFFF9876543210E00001",
	}
}

func mockBaseAesKey() BaseKey {
	return BaseKey{
		Algorithm:         pkg.AlgorithmAes,
		BaseDerivativeKey: "FEDCBA9876543210F1F1F1F1F1F1F1F1",
		KeySerialNumber:   "123456789012345600000001",
		AlgorithmKey:      aes.KeyAES128Type,
	}
}

func TestService__CreateMachine(t *testing.T) {
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

func TestService__GetMachine(t *testing.T) {
	s := mockServiceInMemory()

	m := NewMachine(mockBaseDesKey())
	s.CreateMachine(m)

	s.CreateMachine(NewMachine(mockBaseAesKey()))

	machines := s.GetMachines()
	require.Equal(t, "042666b49184cfa368de9628d0397bc9", machines[0].TransactionKey)
	require.Equal(t, "4f21b565bad9835e112b6465635eae44", machines[1].TransactionKey)

	machine, err := s.GetMachine(m.InitialKey)
	require.NoError(t, err)
	require.Equal(t, "042666b49184cfa368de9628d0397bc9", machine.TransactionKey)
}

func TestService__DeleteMachine(t *testing.T) {
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

func TestService__MakeNextKSN(t *testing.T) {
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
	require.Equal(t, "123456789012345600000002", m.CurrentKSN)
}

func TestService__EncryptPin(t *testing.T) {
	s := mockServiceInMemory()

	m := NewMachine(mockBaseDesKey())
	s.CreateMachine(m)

	encrypted, err := s.EncryptPin(m.InitialKey, "1234", "4012345678909", "")
	require.NoError(t, err)
	require.Equal(t, "1B9C1845EB993A7A", strings.ToUpper(encrypted))

	m = NewMachine(mockBaseAesKey())
	s.CreateMachine(m)

	_, err = s.EncryptPin(m.InitialKey, "1234", "4111111111111111", "")
	require.NoError(t, err)
}

func TestService__DecryptPin(t *testing.T) {
	s := mockServiceInMemory()

	m := NewMachine(mockBaseDesKey())
	s.CreateMachine(m)

	pin, err := s.DecryptPin(m.InitialKey, "1B9C1845EB993A7A", "4012345678909", "")
	require.NoError(t, err)
	require.Equal(t, "1234", strings.ToUpper(pin))

	m = NewMachine(mockBaseAesKey())
	s.CreateMachine(m)

	pin, err = s.DecryptPin(m.InitialKey, "1dd48e0fc64d89836fa3b71cf4aa3783", "4111111111111111", "")
	require.NoError(t, err)
	require.Equal(t, "1234", strings.ToUpper(pin))
}

func TestService__EncryptData(t *testing.T) {
	s := mockServiceInMemory()

	m := NewMachine(mockBaseDesKey())
	s.CreateMachine(m)

	encrypted, err := s.EncryptData(m.InitialKey, "4012345678909D987", pkg.ActionRequest, "")
	require.NoError(t, err)
	require.Equal(t, "FC0D53B7EA1FDA9EE68AAF2E70D9B9506229BE2AA993F04F", strings.ToUpper(encrypted))

	m = NewMachine(mockBaseAesKey())
	s.CreateMachine(m)

	encrypted, err = s.EncryptData(m.InitialKey, "4012345678909D987", pkg.ActionRequest, "")
	require.NoError(t, err)
	require.Equal(t, "E5AFA5B408A3310E3D779C8A9A2AE29448BD5B4232582090DB703AF647205A79", strings.ToUpper(encrypted))
}

func TestService__DecryptData(t *testing.T) {
	s := mockServiceInMemory()

	m := NewMachine(mockBaseDesKey())
	s.CreateMachine(m)

	data, err := s.DecryptData(m.InitialKey, "FC0D53B7EA1FDA9EE68AAF2E70D9B9506229BE2AA993F04F", pkg.ActionRequest, "")
	require.NoError(t, err)
	require.Equal(t, 0, strings.Index(strings.ToUpper(data), "4012345678909D987"))

	m = NewMachine(mockBaseAesKey())
	s.CreateMachine(m)

	data, err = s.DecryptData(m.InitialKey, "E5AFA5B408A3310E3D779C8A9A2AE29448BD5B4232582090DB703AF647205A79", pkg.ActionRequest, "")
	require.NoError(t, err)
	require.Equal(t, 0, strings.Index(strings.ToUpper(data), "4012345678909D987"))
}

func TestService__GenerateMac(t *testing.T) {
	s := mockServiceInMemory()

	m := NewMachine(mockBaseDesKey())
	s.CreateMachine(m)

	encrypted, err := s.GenerateMac(m.InitialKey, "4012345678909D987", pkg.ActionRequest, "")
	require.NoError(t, err)
	require.Equal(t, "9CCC78173FC4FB64", strings.ToUpper(encrypted))

	m = NewMachine(mockBaseAesKey())
	s.CreateMachine(m)

	encrypted, err = s.GenerateMac(m.InitialKey, "4012345678909D987", pkg.ActionRequest, pkg.MaxTypeCmac)
	require.NoError(t, err)
	require.Equal(t, "A2EB5C1C35809E58404E873C3C411E31", strings.ToUpper(encrypted))

	encrypted, err = s.GenerateMac(m.InitialKey, "4012345678909D987", pkg.ActionRequest, pkg.MaxTypeHmac)
	require.NoError(t, err)
	require.Equal(t, "B6F8B3159CD4E140159DA87A68C0FB7AF2F123D222662E98988C76386E8E8A02", strings.ToUpper(encrypted))
}
