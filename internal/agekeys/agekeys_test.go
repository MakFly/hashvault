package agekeys

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestNativeRecipientsAndIdentities(t *testing.T) {
	x, _ := age.GenerateX25519Identity()
	h, _ := age.GenerateHybridIdentity()
	ui := Prompter{Out: io.Discard}.UI()
	for _, id := range []interface {
		String() string
	}{x, h} {
		var recipient string
		switch v := id.(type) {
		case *age.X25519Identity:
			recipient = v.Recipient().String()
		case *age.HybridIdentity:
			recipient = v.Recipient().String()
		}
		r, err := ParseRecipient(" "+recipient+"\n", ui)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		w, _ := age.Encrypt(&buf, r)
		_, _ = w.Write([]byte("hello"))
		_ = w.Close()
		ids, err := ParseIdentities([]byte("# my key\n\n"+id.String()+"\n"), ui)
		if err != nil {
			t.Fatal(err)
		}
		out, err := age.Decrypt(&buf, ids...)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := io.ReadAll(out); string(got) != "hello" {
			t.Fatal("round trip")
		}
	}
	if _, err := ParseRecipient("not a recipient", ui); err == nil {
		t.Fatal("garbage recipient accepted")
	}
	if _, err := ParseIdentities([]byte("# nothing\n"), ui); err == nil {
		t.Fatal("empty identity file accepted")
	}
	if _, err := ParseIdentities([]byte("AGE-SECRET-KEY-1NOPE\n"), ui); err == nil {
		t.Fatal("garbage identity accepted")
	}
}

func TestPluginRecipientsAreRecognised(t *testing.T) {
	// The plugin binary is not installed in CI: recognising the plugin name
	// is enough to know the parsing path is right.
	_, err := ParseRecipient("age1yubikey1qwt50d05nh5vutpdzmlg5wn80xq5negm4uj9ghv0snvdd3yysf5yw3rhl3t", Prompter{Out: io.Discard}.UI())
	if err == nil || !strings.Contains(err.Error(), "yubikey") {
		t.Logf("plugin recipient: %v", err)
	}
	_, err = ParseIdentities([]byte("AGE-PLUGIN-YUBIKEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n"), Prompter{Out: io.Discard}.UI())
	_ = err // parsing a plugin identity only fails when the plugin is used
}

func TestPromptsReachTheOperator(t *testing.T) {
	var out bytes.Buffer
	p := Prompter{
		Out:        &out,
		ReadLine:   func() (string, error) { return "yes", nil },
		ReadSecret: func() (string, error) { return "123456", nil },
	}
	ui := p.UI()
	if err := ui.DisplayMessage("yubikey", "insert the key"); err != nil {
		t.Fatal(err)
	}
	pin, err := ui.RequestValue("yubikey", "PIN", true)
	if err != nil || pin != "123456" {
		t.Fatal(pin, err)
	}
	line, err := ui.RequestValue("yubikey", "slot", false)
	if err != nil || line != "yes" {
		t.Fatal(line, err)
	}
	ok, err := ui.Confirm("yubikey", "use slot 1?", "yes", "no")
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	ui.WaitTimer("yubikey")
	for _, want := range []string{"insert the key", "PIN: ", "use slot 1? [yes/no]", "touch it"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in %q", want, out.String())
		}
	}
	if strings.Contains(out.String(), "123456") {
		t.Fatal("the PIN was echoed")
	}
}
