// Command e2esetup prepares and runs the "offsite" side of the squid end-to-end
// test: it mints the TLS and token material both sides need, publishes it on the
// shared volume, and runs a CEDAR target the tunneled node can reach outbound.
//
// It exists because the material has to be generated somewhere both containers
// agree on, and generating it here -- rather than baking it into the image --
// keeps the test honest about certificate names: the carrier endpoint is reached
// as ccb.offsite.test, so that is the name the certificate must carry.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
)

// shared is the volume both containers see.
const shared = "/shared"

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: e2esetup <material|target>")
	}
	switch os.Args[1] {
	case "material":
		if err := writeMaterial(); err != nil {
			log.Fatalf("generating material: %v", err)
		}
	case "target":
		if err := runTarget(); err != nil {
			log.Fatalf("running target: %v", err)
		}
	default:
		log.Fatalf("unknown subcommand %q", os.Args[1])
	}
}

// writeMaterial generates the CA and host certificate for the carrier endpoint
// and the pool signing key that authenticates tunnels, then writes a marker the
// other container polls for. The marker is written LAST so its presence means
// everything before it is complete -- the containers start concurrently and
// there is no ordering between them beyond this.
func writeMaterial() error {
	caCert := filepath.Join(shared, "ca.pem")
	caKey := filepath.Join(shared, "ca.key")
	if err := security.GenerateTestCA(caCert, caKey); err != nil {
		return fmt.Errorf("CA: %w", err)
	}
	// The carrier is dialed as ccb.offsite.test, so that is the name on the
	// certificate; a mismatch here is exactly what the probe's TLS stage reports.
	if err := security.GenerateTestHostCert(
		filepath.Join(shared, "carrier.pem"),
		filepath.Join(shared, "carrier.key"),
		caCert, caKey, "ccb.offsite.test",
	); err != nil {
		return fmt.Errorf("host certificate: %w", err)
	}

	passwords := filepath.Join(shared, "passwords.d")
	if err := os.MkdirAll(passwords, 0o700); err != nil {
		return err
	}
	if err := security.GeneratePoolSigningKey(filepath.Join(passwords, "POOL")); err != nil {
		return fmt.Errorf("pool signing key: %w", err)
	}

	return os.WriteFile(filepath.Join(shared, "material.ready"), []byte("ok\n"), 0o644)
}

// runTarget serves CEDAR DC_NOP on the offsite network. The tunneled node reaches
// it through the outbound chain -- inside broker, carrier through squid, outside
// broker, dial -- so a handshake completing here proves that whole path.
func runTarget() error {
	addr := os.Getenv("TARGET_ADDR")
	if addr == "" {
		addr = "0.0.0.0:9700"
	}
	sec := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{},
		Authentication: security.SecurityNever,
		Encryption:     security.SecurityNever,
		Integrity:      security.SecurityNever,
		RemoteVersion:  "$CondorVersion: 25.13.0 2026-06-21 BuildID: e2e $",
	}
	srv := cedarserver.New(sec)
	srv.Handle(commands.DC_NOP, func(ctx context.Context, _ *cedarserver.Conn) error {
		log.Print("target: DC_NOP dispatched through the tunnel")
		// Linger briefly so the reply drains back through both splices before the
		// close does; see the relay half-close work.
		select {
		case <-ctx.Done():
		case <-time.After(250 * time.Millisecond):
		}
		return nil
	})
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("target: listening on %s", ln.Addr())
	return srv.Serve(context.Background(), ln)
}
