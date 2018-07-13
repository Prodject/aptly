package pgp

import (
	"errors"
	"os/exec"
	"strings"
)

// Skip GPG version check for GPG 1.x
var skipGPGVersionCheck bool

// GPGVersion stores discovered GPG version
//
// 1 for 1.x, and 2 for 2.x
type GPGVersion int

// GPGFinder implement search for gpg executables and returns version of discovered executables
type GPGFinder interface {
	FindGPG() (gpg string, version GPGVersion, err error)
	FindGPGV() (gpgv string, version GPGVersion, err error)
}

type pathGPGFinder struct {
	gpgNames     []string
	gpgvNames    []string
	execPath     string
	errorMessage string

	expectedVersionSubstring string
	version                  GPGVersion
}

type iteratingGPGFinder struct {
	finders      []GPGFinder
	errorMessage string
}

// GPGDefaultFinder looks for GPG1 first, but falls back to GPG2 if GPG1 is not available
func GPGDefaultFinder() GPGFinder {
	return &iteratingGPGFinder{
		finders:      []GPGFinder{GPG1Finder(), GPG2Finder()},
		errorMessage: "Couldn't find a suitable gpg executable. Make sure gnupg is installed",
	}
}

// GPG1Finder looks for GnuPG1.x only
func GPG1Finder() GPGFinder {
	return &pathGPGFinder{
		gpgNames:                 []string{"gpg", "gpg1"},
		gpgvNames:                []string{"gpgv", "gpgv1"},
		expectedVersionSubstring: "(GnuPG) 1.",
		errorMessage:             "Couldn't find a suitable gpg executable. Make sure gnupg1 is available as either gpg(v) or gpg(v)1 in $PATH",
		version:                  1,
	}
}

// GPG2Finder looks for GnuPG2.x only
func GPG2Finder() GPGFinder {
	return &pathGPGFinder{
		gpgNames:                 []string{"gpg", "gpg2"},
		gpgvNames:                []string{"gpgv", "gpgv2"},
		expectedVersionSubstring: "(GnuPG) 2.",
		errorMessage:             "Couldn't find a suitable gpg executable. Make sure gnupg2 is available as either gpg(v) or gpg(v)2 in $PATH",
		version:                  2,
	}
}

func (pgf *pathGPGFinder) FindGPG() (gpg string, version GPGVersion, err error) {
	for _, cmd := range pgf.gpgNames {
		if cliVersionCheck(cmd, pgf.expectedVersionSubstring) {
			gpg = cmd
			break
		}
	}

	version = pgf.version

	if gpg == "" {
		err = errors.New(pgf.errorMessage)
	}

	return
}

func (pgf *pathGPGFinder) FindGPGV() (gpgv string, version GPGVersion, err error) {
	for _, cmd := range pgf.gpgvNames {
		if cliVersionCheck(cmd, pgf.expectedVersionSubstring) {
			gpgv = cmd
			break
		}
	}

	version = pgf.version

	if gpgv == "" {
		err = errors.New(pgf.errorMessage)
	}

	return
}

func (it *iteratingGPGFinder) FindGPG() (gpg string, version GPGVersion, err error) {
	for _, finder := range it.finders {
		gpg, version, err = finder.FindGPG()
		if err == nil {
			return
		}
	}

	err = errors.New(it.errorMessage)

	return
}

func (it *iteratingGPGFinder) FindGPGV() (gpg string, version GPGVersion, err error) {
	for _, finder := range it.finders {
		gpg, version, err = finder.FindGPGV()
		if err == nil {
			return
		}
	}

	err = errors.New(it.errorMessage)

	return
}

func cliVersionCheck(cmd string, marker string) bool {
	output, err := exec.Command(cmd, "--version").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), marker)
}
