//go:build windows

package tbs

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	modK32 = syscall.NewLazyDLL("Kernel32.dll")

	closeHandleFunc     = modK32.NewProc("CloseHandle")
	deviceIoControlFunc = modK32.NewProc("DeviceIoControl")
)

var (
	modNtd = syscall.NewLazyDLL("ntdll.dll")

	ntCreateFileFunc      = modNtd.NewProc("NtCreateFile")
	rtlInitUnicodeStrFunc = modNtd.NewProc("RtlInitUnicodeString")
	ntQueryInfoFileFunc   = modNtd.NewProc("NtQueryInformationFile")
	ntQuerySystemInfoFunc = modNtd.NewProc("NtQuerySystemInformation")
	rtGetLocationFunc     = modNtd.NewProc("RtlGetPersistedStateLocation")
)

func nStatusToErrCode(fn string, status uint32) error {
	return fmt.Errorf("%s error: 0x%x", fn, status)
}

type objectAttributes struct {
	length  uint32
	rootDir syscall.Handle
	objName *unicodeString
	attrs   uint32
	secDesc uintptr
	secQoS  uintptr
}

type unicodeString struct {
	length    uint16
	maxLength uint16
	buf       *uint16
}

type ioStatusBlock struct {
	status      uint32
	information uintptr
}

func sliceToPtr[T byte | uint16](v []T) uintptr {
	if len(v) == 0 {
		return 0
	}
	p := unsafe.Pointer(unsafe.SliceData(v))
	return uintptr(p)
}

func deviceIoControl(handle uintptr, code uint32, in, out []byte, size *uint32) error {
	ret, _, err := deviceIoControlFunc.Call(
		handle,
		uintptr(code),
		sliceToPtr(in),
		uintptr(len(in)),
		sliceToPtr(out),
		uintptr(len(out)),
		uintptr(unsafe.Pointer(size)),
		0,
	)
	if ret == 0 {
		return err
	}
	return nil
}

func closeHandle(handle uintptr) error {
	ret, _, err := closeHandleFunc.Call(handle)
	if ret == 0 {
		return err
	}
	return nil
}

func newUnicodeString(str string) (*unicodeString, error) {
	var us unicodeString
	s, err := syscall.UTF16PtrFromString(str)
	if err != nil {
		return nil, err
	}
	rtlInitUnicodeStrFunc.Call(
		uintptr(unsafe.Pointer(&us)),
		uintptr(unsafe.Pointer(s)),
	)
	return &us, nil
}

func tpmDeviceAttr() (*objectAttributes, error) {
	name, err := newUnicodeString("\\??\\TPM")
	if err != nil {
		return nil, err
	}
	attr := &objectAttributes{
		length:  48,
		rootDir: 0,
		objName: name,
		attrs:   64,
	}
	return attr, nil
}

func ntCreateFile(handle *uintptr) error {
	var block ioStatusBlock
	attr, err := tpmDeviceAttr()
	if err != nil {
		return err
	}
	status, _, _ := ntCreateFileFunc.Call(
		uintptr(unsafe.Pointer(handle)),
		uintptr(0xC0000000), // GENERIC_READ | GENERIC_WRITE
		uintptr(unsafe.Pointer(attr)),
		uintptr(unsafe.Pointer(&block)),
		0, 0, 1, 1, 0, 0, 0,
	)
	if status != 0 {
		return nStatusToErrCode(ntCreateFileFunc.Name, uint32(status))
	}
	return nil
}

func ntQueryInfoFile(handle uintptr) error {
	out := make([]byte, 8)
	status, _, _ := ntQueryInfoFileFunc.Call(
		handle,
		uintptr(unsafe.Pointer(&ioStatusBlock{})),
		sliceToPtr(out),
		8,
		16, // FileModeInformation
	)
	if status != 0 {
		return nStatusToErrCode(ntQueryInfoFileFunc.Name, uint32(status))
	}
	return nil
}

func ntQuerySystemInformation(sysInfoClass int32, info []byte, sysInfoLen uint64) error {
	status, _, _ := ntQuerySystemInfoFunc.Call(
		uintptr(sysInfoClass),
		sliceToPtr(info),
		uintptr(sysInfoLen),
		0,
	)
	if status != 0 {
		return nStatusToErrCode(ntQuerySystemInfoFunc.Name, uint32(status))
	}
	return nil
}

func ntGetPersistedStateLocation(sid, path *uint16, locationType uint32) (string, error) {
	target := make([]uint16, 260)
	size := uint64(len(target))
	status, _, _ := rtGetLocationFunc.Call(
		uintptr(unsafe.Pointer(sid)),
		0,
		uintptr(unsafe.Pointer(path)),
		uintptr(locationType),
		sliceToPtr(target),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
	)
	if status != 0 {
		return "", nStatusToErrCode(rtGetLocationFunc.Name, uint32(status))
	}
	return syscall.UTF16ToString(target[:size]), nil
}
