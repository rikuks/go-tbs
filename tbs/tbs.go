//go:build windows

package tbs

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	tpmServicePath = "System\\CurrentControlSet\\Services\\TPM"
	pcrBanksPath   = "System\\CurrentControlSet\\Control\\IntegrityServices"
)

type OwnerAuthType uint32

const (
	OwnerAuthTypeFull                 OwnerAuthType = 1
	OwnerAuthTypeEndorsement20        OwnerAuthType = 12
	OwnerAuthTypeEndorsementStorage20 OwnerAuthType = 13
)

type Locality uint32

const (
	LocalityZero  Locality = 0x00
	LocalityOne   Locality = 0x01
	LocalityTwo   Locality = 0x02
	LocalityThree Locality = 0x03
	LocalityFour  Locality = 0x04
)

type Priority uint32

const (
	PriorityLow    Priority = 0x64
	PriorityNormal Priority = 0xC8
	PrioritySystem Priority = 0x190
	PriorityHigh   Priority = 0x12C
	PriorityMax    Priority = 0x80000000
)

type TpmDeviceInfo struct {
	StructVersion uint32
	Version       uint32
	InterFaceType uint32
	ImpRevision   uint32
}

type Attribute uint32

const (
	RequestRaw Attribute = 1 << iota
	IncludeTpm12
	IncludeTpm20
)

type LogType uint32

const (
	LogTypeSRTMCurrent LogType = iota
	LogTypeDRTMCurrent
	LogTypeSRTMBoot
	LogTypeSRTMResume
	LogTypeDRTMBoot
	LogTypeDRTMResume
)

var (
	ErrInvalidContext    = errors.New("the specified context handle does not refer to a valid context")
	ErrUnavailableLog    = errors.New("the TBS event log is not available")
	ErrTpmDeviceNotFound = errors.New("a compatible Trusted Platform Module (TPM) Security Device cannot be found on this computer")
)

// SubmitCommand submits a Trusted Platform Module (TPM) command to TPM Base Services (TBS) for processing.
func SubmitCommand(ctx uintptr, command, out []byte) (uint32, error) {
	var size uint32
	if err := tpmDeviceIoControl(ctx, 0x22C00C, command, out, &size); err != nil {
		return 0, err
	}
	return size, nil
}

func SubmitCommandNonBlocking(ctx uintptr, priority Priority, command, out []byte) (uint32, error) {
	var size uint32
	err := submitCommand(ctx, LocalityZero, priority, command, out, 0x22C194, &size)
	if err != nil {
		return 0, err
	}
	return size, nil
}

func submitCommand(ctx uintptr, locality Locality, priority Priority, in, out []byte, code uint32, size *uint32) error {
	if locality != LocalityZero || priority > PriorityMax {
		return errors.New("internal error")
	}
	if code == 0 {
		code = 0x22C00C
	}
	if err := tpmDeviceIoControl(ctx, code, in, out, size); err != nil {
		return err
	}
	return nil
}

// CancelCommands cancels all outstanding commands for the specified context.
func CancelCommands(ctx uintptr) error {
	err := tpmDeviceIoControl(ctx, 0x22C004, nil, nil, nil)
	if err != nil {
		return ErrInvalidContext
	}
	return nil
}

// PhysicalPresenceCommand passes a physical presence ACPI command through TBS to the driver.
func PhysicalPresenceCommand(ctx uintptr, command, out []byte) (uint32, error) {
	var size uint32
	if err := tpmDeviceIoControl(ctx, 0x22C014, command, out, &size); err != nil {
		return 0, err
	}
	return size, nil
}

func tpmDeviceIoControl(ctx uintptr, code uint32, in, out []byte, size *uint32) error {
	return deviceIoControl(ctx, code, in, out, size)
}

// GetDeviceInfo obtains the version of the TPM on the computer.
func GetDeviceInfo() (*TpmDeviceInfo, error) {
	var handle uintptr
	if err := ntCreateFile(&handle); err != nil {
		return nil, err
	}
	var info TpmDeviceInfo
	out := make([]byte, unsafe.Sizeof(info))
	err := tpmDeviceIoControl(handle, 0x22C01C, nil, out, nil)
	if err != nil {
		return nil, err
	}
	defer CloseContext(handle)
	return (*TpmDeviceInfo)(unsafe.Pointer(&out[0])), nil
}

// CreateContext creates a context handle that can be used to pass commands to TBS.
func CreateContext(version uint32, attr Attribute) (uintptr, error) {
	info, err := GetDeviceInfo()
	if err != nil {
		return 0, err
	}
	if version != 2 && version != 1 {
		return 0, errors.New("not supported version: " + strconv.Itoa(int(version)))
	}
	if info.Version != version {
		return 0, errors.New("mismatch TPM version")
	}
	var handle uintptr
	if err := ntCreateFile(&handle); err != nil {
		return 0, err
	}
	if version != 1 {
		if info.Version != 2 || (attr&IncludeTpm20) != 0 {
			return handle, nil
		}
	}
	if (attr & IncludeTpm12) == 0 {
		return 0, ErrTpmDeviceNotFound
	}
	return 0, ErrTpmDeviceNotFound
}

// CloseContext closes a context handle, which releases resources associated with the context in TBS
// and closes the binding handle used to communicate with TBS.
func CloseContext(ctx uintptr) error {
	if err := closeHandle(ctx); err != nil {
		return ErrInvalidContext
	}
	return nil
}

func getBootConfigLog(flag bool) ([]byte, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, pcrBanksPath, registry.READ)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	reg := "WBCL"
	if flag {
		// Dynamic Root of Trust for Measurement
		reg = "WBCLDrtm"
	}

	log, _, err := key.GetBinaryValue(reg)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, ErrUnavailableLog
	}
	// ToDo: Implementation WBCLTrustPoint
	return log, nil
}

// GetTCGLog Retrieves the most recent Windows Boot Configuration Log (WBCL), also referred to as a TCG log.
func GetTCGLog() ([]byte, error) {
	log, err := getBootConfigLog(false)
	if err != nil {
		return nil, err
	}
	return log, nil
}

func getDeviceIDWithTimeout() ([]byte, error) {
	dp := filepath.Join(tpmServicePath, "WMI")
	path, err := getRedirectionMapFromSid("TpmRegDriverPersistedData", dp, 0)
	if err != nil {
		return nil, err
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
	if err != nil {
		return nil, err
	}
	val, _, err := key.GetBinaryValue("WindowsAIKHash")
	if err != nil {
		return nil, err
	}
	return val, nil
}

func GetDeviceId() ([]byte, error) {
	return getDeviceIDWithTimeout()
}

func isDrtmBoot() bool {
	info := make([]byte, 32)
	// SystemBootEnvironmentInformation
	if err := ntQuerySystemInformation(90, info, 32); err != nil {
		return false
	}
	// BootFlags
	return info[24]&8 != 0
}

func getCurrentLog(flag bool) ([]byte, error) {
	if !flag || isDrtmBoot() {
		return getBootConfigLog(flag)
	}
	return nil, ErrUnavailableLog
}

func getTCGLogs(flag bool, first uint32) ([]byte, error) {
	path, err := getRedirectionMapFromSid("TpmRegDriverTpm", tpmServicePath, 0)
	if err != nil {
		return nil, err
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
	if err != nil {
		return nil, err
	}
	defer key.Close()
	count, _, err := key.GetIntegerValue("OsBootCount")
	if err != nil {
		return nil, err
	}
	p, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return nil, err
	}
	logPath, _, err := key.GetStringValue("WBCLPath")
	if errors.Is(err, registry.ErrNotExist) {
		logPath = filepath.Join(p, "Logs\\MeasuredBoot")
	}
	path, err = getRedirectionMapFromSid("TpmDriverLogPath", logPath, 1)
	if err != nil {
		return nil, err
	}
	// PlatformLogFileDrtm
	name := "%010d-%010d-DRTM.log"
	if !flag {
		// PlatformLogFile
		name = "%010d-%010d.log"
	}
	name = fmt.Sprintf(name, count, first)

	data, err := os.ReadFile(filepath.Join(path, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrUnavailableLog
	}

	return data, nil
}

func getCurrentLogIfResume(flag bool) ([]byte, error) {
	if _, err := getTCGLogs(false, 1); err != nil {
		return nil, ErrUnavailableLog
	}

	return getCurrentLog(flag)
}

// GetTCGLogEx gets the Windows Boot Configuration Log (WBCL),
// also referred to as the TCG log, of the specified type.
func GetTCGLogEx(logType LogType) ([]byte, error) {
	if !isTpmPresent() {
		return nil, ErrTpmDeviceNotFound
	}

	var flag bool
	switch logType {
	case LogTypeSRTMCurrent:
		return getCurrentLog(false)
	case LogTypeDRTMCurrent:
		return getCurrentLog(true)
	case LogTypeSRTMBoot:
		return getTCGLogs(false, 0)
	case LogTypeSRTMResume:
	case LogTypeDRTMBoot:
		return getTCGLogs(true, 0)
	case LogTypeDRTMResume:
		flag = true
	default:
		return nil, errors.New("not supported logType: " + strconv.Itoa(int(logType)))
	}

	return getCurrentLogIfResume(flag)
}

func tpmOpen(handle uintptr) error {
	return ntCreateFile(&handle)
}

func isTpmPresent() bool {
	var handle uintptr
	if err := tpmOpen(handle); err != nil {
		return false
	}
	defer CloseContext(handle)
	return true
}

// GetOwnerAuth retrieves the owner authorization of the TPM
// if the information is available in the local registry.
//
// Only TPM2.0 or later is supported.
// Root privileges are required for execution.
func GetOwnerAuth(ctx uintptr, oaType OwnerAuthType) ([]byte, error) {
	if err := ntQueryInfoFile(ctx); err != nil {
		return nil, errors.New("tbs: A context parameter that is not valid was passed when attempting to create a TBS context")
	}

	// Type:     TBS_OWNERAUTH_TYPE_ADMIN(2), TPM 1.2 only
	// SourceId: TpmRegDriverPersistedDataAdmin
	// Path:     System\CurrentControlSet\Services\TPM\WMI\Admin
	// Key:      OwnerAuthAdmin

	// Type:     TBS_OWNERAUTH_TYPE_USER(3), TPM 1.2 only
	// SourceId: TpmRegDriverPersistedDataUser
	// Path:     System\\CurrentControlSet\\Services\\TPM\\WMI\\User
	// Key:      OwnerAuthUser

	// Type:     TBS_OWNERAUTH_TYPE_ENDORSEMENT(4), TPM 1.2 only
	// SourceId: TpmRegDriverPersistedDataEndorsement
	// Path:     System\\CurrentControlSet\\Services\\TPM\\WMI\\Endorsement
	// Key:      OwnerAuthEndorsement

	var sid, dPath *uint16
	var name string

	switch oaType {
	case OwnerAuthTypeFull, OwnerAuthTypeEndorsementStorage20:
		sid, _ = syscall.UTF16PtrFromString("TpmRegDriverPersistedDataAdmin")
		dPath, _ = syscall.UTF16PtrFromString(filepath.Join(tpmServicePath, "WMI\\Admin"))
		name = "StorageOwnerAuth"
		if oaType != OwnerAuthTypeEndorsementStorage20 {
			// "LockoutHash" is used in Windows 10.
			name = "OwnerAuthFull"
		}
	case OwnerAuthTypeEndorsement20:
		sid, _ = syscall.UTF16PtrFromString("TpmRegDriverPersistedDataEndorsement")
		dPath, _ = syscall.UTF16PtrFromString(filepath.Join(tpmServicePath, "WMI\\Endorsement"))
		name = "EndorsementAuth"
	default:
		return nil, errors.New("tbs: unsupported OwnerAuthType or TPM 2.0 only supported")
	}

	path, err := ntGetPersistedStateLocation(sid, dPath, 0)
	if err != nil {
		return nil, err
	}

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
	if err != nil {
		return nil, err
	}
	defer key.Close()
	value, _, err := key.GetStringValue(name)
	if err != nil {
		return nil, err
	}
	dv, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return dv, nil
}

func CreateWindowsKey(kh uint32) error {
	ctx, err := CreateContext(2, IncludeTpm20)
	if err != nil {
		return err
	}
	if ((kh + 0x7EFFFFFF) & 0xFFFEFFFF) != 0 {
		return errors.New("invalid Key Handle")
	}
	var handle [4]byte
	binary.BigEndian.PutUint32(handle[:], kh)
	err = tpmDeviceIoControl(ctx, 0x22C19C, handle[:], nil, nil)
	if err != nil {
		return err
	}
	defer CloseContext(ctx)
	return nil
}

// RevokeAttestation invalidates the PCRs if the ELAM driver detects a policy-violation (a rootkit, for example).
func RevokeAttestation() error {
	ctx, err := CreateContext(2, IncludeTpm12|IncludeTpm20)
	if err != nil {
		return err
	}
	err = tpmDeviceIoControl(ctx, 0x22C018, nil, nil, nil)
	if err != nil {
		return err
	}
	defer CloseContext(ctx)
	return nil
}

// - Tbsip_TestMorBit
//   Code: 0x22C198
//   Req: in: nil, out: 4Byte
//   Context: 0x600000002

// - Tbsip_TestInterruptInformation
//   Code: 0x22C1A0
//   Req: in: nil, out: 4Byte
//   ctx: 0x600000002
