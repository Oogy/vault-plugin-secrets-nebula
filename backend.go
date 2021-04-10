package nebula

import (
	"crypto/rand"
	"context"
	"fmt"
	"strings"
	"time"
	"net"

	"github.com/slackhq/nebula/cert"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/ed25519"
)

type backend struct {
	*framework.Backend
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := Backend()
	if err != nil {
		return nil, err
	}

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func Backend() (*backend, error) {
	var b backend

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		Paths: []*framework.Path{
			pathConfigCA(&b),
		},
	}

	return &b, nil
}

func pathConfigCA(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/ca",

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: `Required: name of the certificate authority`,
			},
			"duration": {
				Type:        framework.TypeString,
				Description: `Optional: amount of time the certificate should be valid for. Valid time units are seconds: "s", minutes: "m", hours: "h" (default 8760h0m0s)`,
			},
			"groups": {
				Type:        framework.TypeString,
				Description: `Optional: list of groups. This will limit which groups subordinate certs can use.`,
			},
			"ips": {
				Type:        framework.TypeString,
				Description: `Optional: list of ip and network in CIDR notation. This will limit which ip addresses and networks subordinate certs can use.`,
			},
			"subnets": {
				Type:        framework.TypeString,
				Description: `Optional: list of ip and network in CIDR notation. This will limit which subnet addresses and networks subordinate certs can use.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigCAUpdate,
				Summary:  "",
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigCARead,
				Summary:  "",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigCADelete,
				Summary:  "",
			},
		},
	}
}

func (b *backend) pathConfigCAUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return nil, fmt.Errorf("Nebula CA Name may not be empty")
	}

	groups := data.Get("groups").(string)
	var _groups []string
	if groups != "" {
		for _, rg := range strings.Split(groups, ",") {
			g := strings.TrimSpace(rg)
			if g != "" {
				_groups = append(_groups, g)
			}
		}
	}

	duration := data.Get("duration").(string)
	var _duration time.Duration
	_duration, err := time.ParseDuration(duration)
	if err != nil {
		return nil, fmt.Errorf("Invalid time format: %s", err)
	}

	ips := data.Get("ips").(string)
	var _ips []*net.IPNet
	if ips != "" {
		for _, rs := range strings.Split(ips, ",") {
			rs := strings.Trim(rs, " ")
			if rs != "" {
				ip, ipNet, err := net.ParseCIDR(rs)
				if err != nil {
					return nil, fmt.Errorf("invalid ip definition: %s", err)
				}
				ipNet.IP = ip
				_ips = append(_ips, ipNet)
			}
		}
	}

	subnets := data.Get("subnets").(string)
	var _subnets []*net.IPNet
	if subnets != "" {
		for _, rs := range strings.Split(subnets, ",") {
			rs := strings.Trim(rs, " ")
			if rs != "" {
				_, s, err := net.ParseCIDR(rs)
				if err != nil {
					return nil, fmt.Errorf("invalid subnet definition: %s", err)
				}
				_subnets = append(_subnets, s)
			}
		}
	}

	pub, rawPriv, err := ed25519.GenerateKey(rand.Reader)

	nc := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:      name,
			Groups:    _groups,
			Ips:       _ips,
			Subnets:   _subnets,
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(_duration),
			PublicKey: pub,
			IsCA:      true,
		},
	}

	/* store private key internally i.e. not accessible by user */
	/* store the rest of the cert structure + QR code, accessible by user */

	return nil, nil
}

func (b *backend) pathConfigCARead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

func (b *backend) pathConfigCADelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

const backendHelp = `
The Nebula backend generates Nebula style Curve25519 certs.
`
