package secrets_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/MakFly/hashvault/internal/envelope"
	"github.com/MakFly/hashvault/internal/openbao"
	"github.com/MakFly/hashvault/internal/openbao/baotest"
	"github.com/MakFly/hashvault/internal/secrets"
)

var ctx = context.Background()

func store(t *testing.T) (*secrets.Store, *baotest.Server) {
	t.Helper()
	srv := baotest.Start(t)
	w := openbao.NewTransitWrapper(srv.Client, baotest.TransitMount, baotest.KEK)
	return secrets.New(srv.Client, baotest.KVMount, w), srv
}

var db = secrets.Ref{Env: "prod", App: "acme-api", Key: "DATABASE_URL"}

func TestRefValidation(t *testing.T) {
	if db.Resource() != "hv:prod:secret/acme-api/DATABASE_URL" {
		t.Fatalf("resource: %s", db.Resource())
	}
	bad := []secrets.Ref{
		{Env: "Prod", App: "acme", Key: "K"},
		{Env: "prod", App: "Acme", Key: "K"},
		{Env: "prod", App: "acme/x", Key: "K"},
		{Env: "prod", App: "acme", Key: "lower"},
		{Env: "prod", App: "acme", Key: "K-DASH"},
		{Env: "prod", App: "acme", Key: ""},
		{Env: "prod", App: "", Key: "K"},
	}
	for _, r := range bad {
		if err := r.Validate(); !errors.Is(err, secrets.ErrInvalidRef) {
			t.Errorf("%+v accepted", r)
		}
	}
}

func TestPutGetVersions(t *testing.T) {
	s, _ := store(t)
	if _, _, err := s.Get(ctx, db, 0); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("empty: got %v", err)
	}
	for i, v := range []string{"one", "two", "three"} {
		n, err := s.Put(ctx, db, []byte(v))
		if err != nil || n != uint64(i+1) {
			t.Fatalf("put %q: version %d, %v", v, n, err)
		}
	}
	got, n, err := s.Get(ctx, db, 0)
	if err != nil || string(got) != "three" || n != 3 {
		t.Fatalf("latest: %q v%d %v", got, n, err)
	}
	got, n, err = s.Get(ctx, db, 1)
	if err != nil || string(got) != "one" || n != 1 {
		t.Fatalf("v1: %q v%d %v", got, n, err)
	}
	if _, _, err := s.Get(ctx, db, 9); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("v9: got %v", err)
	}
}

func TestConcurrentWritersGetDistinctVersions(t *testing.T) {
	s, _ := store(t)
	const writers = 6
	var wg sync.WaitGroup
	versions := make(chan uint64, writers)
	errs := make(chan error, writers)
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := s.Put(ctx, db, []byte{byte('a' + i)})
			if err != nil {
				errs <- err
				return
			}
			versions <- n
		}()
	}
	wg.Wait()
	close(versions)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var got []uint64
	for v := range versions {
		got = append(got, v)
	}
	slices.Sort(got)
	if !slices.Equal(got, []uint64{1, 2, 3, 4, 5, 6}) {
		t.Fatalf("versions %v", got)
	}
	for _, v := range got {
		if _, _, err := s.Get(ctx, db, v); err != nil {
			t.Fatalf("v%d unreadable: %v", v, err)
		}
	}
}

func TestDestroyIsPermanentAndKeepsTheNumberReserved(t *testing.T) {
	s, _ := store(t)
	for _, v := range []string{"a", "b"} {
		if _, err := s.Put(ctx, db, []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Destroy(ctx, db, 2); err != nil {
		t.Fatal(err)
	}
	if live, err := s.VersionLive(ctx, db, 1); err != nil || !live {
		t.Fatal("live version missing from history", live, err)
	}
	if live, err := s.VersionLive(ctx, db, 2); err != nil || live {
		t.Fatal("destroyed version marked live", live, err)
	}
	if _, err := s.VersionLive(ctx, db, 7); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatal(err)
	}
	if _, _, err := s.Get(ctx, db, 2); !errors.Is(err, secrets.ErrDestroyed) {
		t.Fatalf("destroyed version: got %v", err)
	}
	if _, _, err := s.Get(ctx, db, 0); !errors.Is(err, secrets.ErrDestroyed) {
		t.Fatalf("latest is the destroyed one: got %v", err)
	}
	n, err := s.Put(ctx, db, []byte("c"))
	if err != nil || n != 3 {
		t.Fatalf("a destroyed number must not be reused: got v%d, %v", n, err)
	}
	if err := s.Destroy(ctx, db, 7); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("destroy of a missing version: got %v", err)
	}
}

// A record copied by someone with raw KV access to another secret's path must
// not open: the associated data names the original secret.
func TestARecordCopiedToAnotherSecretDoesNotOpen(t *testing.T) {
	s, srv := store(t)
	if _, err := s.Put(ctx, db, []byte("s3cr3t")); err != nil {
		t.Fatal(err)
	}
	entry, err := srv.Client.KVGet(ctx, baotest.KVMount, "prod/acme-api/DATABASE_URL/1", 0)
	if err != nil {
		t.Fatal(err)
	}
	other := secrets.Ref{Env: "prod", App: "acme-api", Key: "STRIPE_KEY"}
	if _, err := srv.Client.KVPut(ctx, baotest.KVMount, "prod/acme-api/STRIPE_KEY/1", entry.Data, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Get(ctx, other, 1); !errors.Is(err, envelope.ErrAuthentication) {
		t.Fatalf("want ErrAuthentication, got %v", err)
	}
	staging := secrets.Ref{Env: "staging", App: "acme-api", Key: "DATABASE_URL"}
	if _, err := srv.Client.KVPut(ctx, baotest.KVMount, "staging/acme-api/DATABASE_URL/1", entry.Data, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Get(ctx, staging, 1); !errors.Is(err, envelope.ErrAuthentication) {
		t.Fatalf("other env: want ErrAuthentication, got %v", err)
	}
}

func TestRewrapAfterKEKRotation(t *testing.T) {
	s, srv := store(t)
	for _, v := range []string{"a", "b", "c"} {
		if _, err := s.Put(ctx, db, []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Destroy(ctx, db, 2); err != nil {
		t.Fatal(err)
	}
	if err := srv.Client.TransitRotate(ctx, baotest.TransitMount, baotest.KEK); err != nil {
		t.Fatal(err)
	}
	n, err := s.Rewrap(ctx, db)
	if err != nil || n != 2 {
		t.Fatalf("rewrapped %d, %v", n, err)
	}
	if n, err := s.Rewrap(ctx, db); err != nil || n != 0 {
		t.Fatalf("second rewrap must be a no-op: %d, %v", n, err)
	}
	// The pre-rotation KV version of each record is gone.
	md, err := srv.Client.KVMetadata(ctx, baotest.KVMount, "prod/acme-api/DATABASE_URL/1")
	if err != nil || !slices.Equal(md.Live, []int{2}) {
		t.Fatalf("old wrapped key still live: %+v %v", md, err)
	}
	if err := srv.Client.TransitSetMinDecryptionVersion(ctx, baotest.TransitMount, baotest.KEK, 2); err != nil {
		t.Fatal(err)
	}
	for v, want := range map[uint64]string{1: "a", 3: "c"} {
		got, _, err := s.Get(ctx, db, v)
		if err != nil || string(got) != want {
			t.Fatalf("v%d after retirement: %q %v", v, got, err)
		}
	}
}

func TestKeysListsAnAppsSecrets(t *testing.T) {
	s, _ := store(t)
	for _, k := range []string{"ZED", "API_KEY", "DATABASE_URL"} {
		if _, err := s.Put(ctx, secrets.Ref{Env: "prod", App: "acme-api", Key: k}, []byte("v")); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := s.Keys(ctx, "prod", "acme-api")
	if err != nil || !slices.Equal(keys, []string{"API_KEY", "DATABASE_URL", "ZED"}) {
		t.Fatalf("keys %v, %v", keys, err)
	}
	if keys, err := s.Keys(ctx, "prod", "nothing"); err != nil || len(keys) != 0 {
		t.Fatalf("empty app: %v %v", keys, err)
	}
	if _, err := s.Keys(ctx, "Prod", "acme"); !errors.Is(err, secrets.ErrInvalidRef) {
		t.Fatalf("invalid env: %v", err)
	}
}

func TestStoreFailsClosedWhenOpenBaoIsUnreachable(t *testing.T) {
	c, err := openbao.New(openbao.Config{Address: "http://127.0.0.1:1", Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	s := secrets.New(c, "hv", openbao.NewTransitWrapper(c, "transit", "k"))
	if _, err := s.Put(ctx, db, []byte("v")); err == nil {
		t.Fatal("put succeeded without OpenBao")
	}
	if _, _, err := s.Get(ctx, db, 0); err == nil {
		t.Fatal("get succeeded without OpenBao")
	}
	if _, _, err := s.Get(ctx, db, 1); err == nil {
		t.Fatal("get of a version succeeded without OpenBao")
	}
	if err := s.Destroy(ctx, db, 1); err == nil {
		t.Fatal("destroy succeeded without OpenBao")
	}
	if _, err := s.Rewrap(ctx, db); err == nil {
		t.Fatal("rewrap succeeded without OpenBao")
	}
	if _, err := s.Keys(ctx, "prod", "acme-api"); err == nil {
		t.Fatal("keys succeeded without OpenBao")
	}
	if _, err := s.VersionLive(ctx, db, 1); err == nil {
		t.Fatal("version metadata succeeded without OpenBao")
	}
}

func TestEveryMethodRefusesAnInvalidRef(t *testing.T) {
	s, _ := store(t)
	bad := secrets.Ref{Env: "prod", App: "acme-api", Key: "bad key"}
	if _, err := s.Put(ctx, bad, nil); !errors.Is(err, secrets.ErrInvalidRef) {
		t.Fatalf("put: %v", err)
	}
	if _, _, err := s.Get(ctx, bad, 0); !errors.Is(err, secrets.ErrInvalidRef) {
		t.Fatalf("get: %v", err)
	}
	if err := s.Destroy(ctx, bad, 1); !errors.Is(err, secrets.ErrInvalidRef) {
		t.Fatalf("destroy: %v", err)
	}
	if _, err := s.Rewrap(ctx, bad); !errors.Is(err, secrets.ErrInvalidRef) {
		t.Fatalf("rewrap: %v", err)
	}
	if _, err := s.VersionLive(ctx, bad, 1); !errors.Is(err, secrets.ErrInvalidRef) {
		t.Fatal(err)
	}
}

func TestCorruptedStorageIsReportedNotTrusted(t *testing.T) {
	s, srv := store(t)
	if _, err := srv.Client.KVPut(ctx, baotest.KVMount, "prod/acme-api/DATABASE_URL/1", map[string]string{"record": "%%% not base64"}, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Get(ctx, db, 1); err == nil {
		t.Fatal("a non-base64 record was accepted")
	}
	if _, err := srv.Client.KVPut(ctx, baotest.KVMount, "prod/acme-api/DATABASE_URL/2", map[string]string{"record": "e30="}, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Get(ctx, db, 2); !errors.Is(err, envelope.ErrInvalidRecord) {
		t.Fatalf("an empty record: got %v", err)
	}
	if _, err := srv.Client.KVPut(ctx, baotest.KVMount, "prod/acme-api/DATABASE_URL/007", map[string]string{"record": "x"}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Versions(ctx, db); err == nil {
		t.Fatal("a non-canonical version entry was accepted")
	}
	if _, err := s.Put(ctx, db, []byte("v")); err == nil {
		t.Fatal("put must refuse to pick a version over a corrupted listing")
	}
}
