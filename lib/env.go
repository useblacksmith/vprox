package lib

import (
	"errors"
	"os"
	"strings"
)

func GetVproxPassword() (string, error) {
	password := os.Getenv("VPROX_PASSWORD")
	if password == "" {
		return "", errors.New("VPROX_PASSWORD environment variable is not set")
	}
	return password, nil
}

// GetVproxPasswords returns the passwords accepted by a server or relay.
// VPROX_PASSWORD remains a literal single password; VPROX_PASSWORDS adds
// comma-separated passwords with surrounding whitespace removed.
func GetVproxPasswords() ([]string, error) {
	var passwords []string
	if password := os.Getenv("VPROX_PASSWORD"); password != "" {
		passwords = append(passwords, password)
	}
	if list := os.Getenv("VPROX_PASSWORDS"); list != "" {
		for _, password := range strings.Split(list, ",") {
			password = strings.TrimSpace(password)
			if password == "" {
				return nil, errors.New("VPROX_PASSWORDS must not contain empty passwords")
			}
			passwords = append(passwords, password)
		}
	}
	if len(passwords) == 0 {
		return nil, errors.New("VPROX_PASSWORD or VPROX_PASSWORDS environment variable must be set")
	}
	return passwords, nil
}
