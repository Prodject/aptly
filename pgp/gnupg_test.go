package pgp

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	. "gopkg.in/check.v1"
)

type GnupgSuite struct {
	verifier Verifier
	bins     string
}

var _ = Suite(&GnupgSuite{})

func (s *GnupgSuite) SetUpSuite(c *C) {
	_, _File, _, _ := runtime.Caller(0)
	s.bins = filepath.Join(filepath.Dir(_File), "test-bins")
}

// If gpg == gpg1 = pick gpg
func (s *GnupgSuite) TestGPG1(c *C) {
	origPath := os.Getenv("PATH")
	os.Setenv("PATH", filepath.Join(s.bins, "gpg1"))
	defer func() { os.Setenv("PATH", origPath) }()

	signer := NewGpgSigner(GPG1Finder())
	c.Assert(signer.gpg, Equals, "gpg")
}

// gpg(2) + gpg1 installed = pick gpg1
func (s *GnupgSuite) TestGPG1Not2(c *C) {
	origPath := os.Getenv("PATH")
	os.Setenv("PATH", filepath.Join(s.bins, "gpg2-and-1"))
	defer func() { os.Setenv("PATH", origPath) }()

	signer := NewGpgSigner(GPG1Finder())
	c.Assert(signer.gpg, Equals, "gpg1")
}

// If gpg == gpg2 and no gpg1 is available = error
func (s *GnupgSuite) TestGPGNothing(c *C) {
	origPath := os.Getenv("PATH")
	os.Setenv("PATH", filepath.Join(s.bins, "gpg2-only"))
	defer func() { os.Setenv("PATH", origPath) }()

	c.Assert(func() { NewGpgSigner(GPG1Finder()) }, PanicMatches, `Couldn't find a suitable gpg executable.+`)
}

// If gpgv == gpgv1 = pick gpgv
func (s *GnupgSuite) TestGPGV1(c *C) {
	origPath := os.Getenv("PATH")
	os.Setenv("PATH", filepath.Join(s.bins, "gpgv1")+":"+filepath.Join(s.bins, "gpg1"))
	defer func() { os.Setenv("PATH", origPath) }()

	verifier := NewGpgVerifier(GPG1Finder())
	c.Assert(verifier.gpgv, Equals, "gpgv")
}

// gpgv(2) + gpgv1 installed = pick gpgv1
func (s *GnupgSuite) TestGPGV1Not2(c *C) {
	origPath := os.Getenv("PATH")
	os.Setenv("PATH", filepath.Join(s.bins, "gpgv2-and-1")+":"+filepath.Join(s.bins, "gpg1"))
	defer func() { os.Setenv("PATH", origPath) }()

	verifier := NewGpgVerifier(GPG1Finder())
	c.Assert(verifier.gpgv, Equals, "gpgv1")
}

// If gpgv == gpgv2 and no gpgv1 is available = error
func (s *GnupgSuite) TestGPGVNothing(c *C) {
	origPath := os.Getenv("PATH")
	os.Setenv("PATH", filepath.Join(s.bins, "gpgv2-only")+":"+filepath.Join(s.bins, "gpg1"))
	defer func() { os.Setenv("PATH", origPath) }()

	c.Assert(func() { NewGpgVerifier(GPG1Finder()) }, PanicMatches, `Couldn't find a suitable gpg executable.+`)
}

type Gnupg1VerifierSuite struct {
	VerifierSuite
}

var _ = Suite(&Gnupg1VerifierSuite{})

func (s *Gnupg1VerifierSuite) SetUpTest(c *C) {
	finder := GPG1Finder()
	_, _, err := finder.FindGPG()
	if err != nil {
		c.Skip(err.Error())
	}

	s.verifier = NewGpgVerifier(finder)
	s.verifier.AddKeyring("./trusted.gpg")

	c.Assert(s.verifier.InitKeyring(), IsNil)
}

type Gnupg1SignerSuite struct {
	SignerSuite
}

var _ = Suite(&Gnupg1SignerSuite{})

func (s *Gnupg1SignerSuite) SetUpTest(c *C) {
	finder := GPG1Finder()
	_, _, err := finder.FindGPG()
	if err != nil {
		c.Skip(err.Error())
	}

	s.keyringNoPassphrase = [2]string{"keyrings/aptly.pub", "keyrings/aptly.sec"}
	s.keyringPassphrase = [2]string{"keyrings/aptly_passphrase.pub", "keyrings/aptly_passphrase.sec"}
	s.passphraseKey = "F30E8CB9CDDE2AF8"
	s.noPassphraseKey = "21DBB89C16DB3E6D"

	s.signer = NewGpgSigner(finder)
	s.signer.SetBatch(true)

	s.verifier = &GoVerifier{}
	s.verifier.AddKeyring("./keyrings/aptly.pub")
	s.verifier.AddKeyring("./keyrings/aptly_passphrase.pub")

	c.Assert(s.verifier.InitKeyring(), IsNil)

	s.SignerSuite.SetUpTest(c)
}

type Gnupg2VerifierSuite struct {
	VerifierSuite
}

var _ = Suite(&Gnupg2VerifierSuite{})

func (s *Gnupg2VerifierSuite) SetUpTest(c *C) {
	finder := GPG2Finder()
	_, _, err := finder.FindGPG()
	if err != nil {
		c.Skip(err.Error())
	}

	s.verifier = NewGpgVerifier(finder)
	s.verifier.AddKeyring("./trusted.gpg")

	c.Assert(s.verifier.InitKeyring(), IsNil)
}

type Gnupg2SignerSuite struct {
	SignerSuite
}

var _ = Suite(&Gnupg2SignerSuite{})

func (s *Gnupg2SignerSuite) SetUpTest(c *C) {
	finder := GPG2Finder()
	gpg, _, err := finder.FindGPG()
	if err != nil {
		c.Skip(err.Error())
	}

	output, err := exec.Command(gpg, "--import", "keyrings/aptly2.sec.armor").CombinedOutput()
	c.Log(string(output))
	c.Check(err, IsNil)

	output, err = exec.Command(gpg, "--import", "--passphrase", "verysecret", "--no-tty", "--batch", "--pinentry-mode", "loopback", "keyrings/aptly2_passphrase.sec.armor").CombinedOutput()
	c.Log(string(output))
	c.Check(err, IsNil)

	s.keyringNoPassphrase = [2]string{"keyrings/aptly2.gpg", ""}
	s.keyringPassphrase = [2]string{"keyrings/aptly2_passphrase.gpg", ""}
	s.noPassphraseKey = "751DF85C2B220D45"
	s.passphraseKey = "6656CD181E92D2D5"

	s.signer = NewGpgSigner(finder)
	s.signer.SetBatch(true)

	s.verifier = &GoVerifier{}
	s.verifier.AddKeyring("./keyrings/aptly2_trusted.pub")

	c.Assert(s.verifier.InitKeyring(), IsNil)

	s.SignerSuite.SetUpTest(c)
}

func (s *Gnupg2SignerSuite) TearDownTest(c *C) {
	s.SignerSuite.TearDownTest(c)
}
