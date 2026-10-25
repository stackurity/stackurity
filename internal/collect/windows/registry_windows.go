//go:build windows

package windows

import (
	"fmt"
	"strconv"

	"golang.org/x/sys/windows/registry"
)

// System reads the live registry.
type System struct{}

func readValues(k registry.Key) map[string]string {
	names, err := k.ReadValueNames(0)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, n := range names {
		if s, _, err := k.GetStringValue(n); err == nil {
			out[n] = s
		} else if i, _, err := k.GetIntegerValue(n); err == nil {
			out[n] = strconv.FormatUint(i, 10)
		}
	}
	return out
}

func (System) OSInfo() (map[string]string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	return readValues(k), nil
}

func (System) Uninstall(view string) ([]map[string]string, error) {
	access := uint32(registry.ENUMERATE_SUB_KEYS | registry.QUERY_VALUE)
	switch view {
	case "native":
		access |= registry.WOW64_64KEY
	case "wow64":
		access |= registry.WOW64_32KEY
	default:
		return nil, fmt.Errorf("unknown view %q", view)
	}
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, access)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	subs, err := root.ReadSubKeyNames(0)
	if err != nil {
		return nil, err
	}
	var out []map[string]string
	for _, s := range subs {
		k, err := registry.OpenKey(root, s, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		out = append(out, readValues(k))
		k.Close()
	}
	return out, nil
}

func (System) MachineGUID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	g, _, _ := k.GetStringValue("MachineGuid")
	return g
}
