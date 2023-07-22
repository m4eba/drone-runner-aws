package hetznercloud

import (
	"context"
	"fmt"
	"net"

	"strconv"
	"time"

	"github.com/drone-runners/drone-runner-aws/internal/drivers"
	"github.com/drone-runners/drone-runner-aws/internal/lehelper"
	"github.com/drone-runners/drone-runner-aws/types"
	"github.com/drone/runner-go/logger"

	"github.com/dchest/uniuri"
	"github.com/hetznercloud/hcloud-go/v2/hcloud"
)

// config is a struct that implements drivers.Pool interface
type config struct {
	token             string
	region            string
	image             string
	size              string
	FirewallID        int64
	tags              []string
	userData          string
	rootDir           string
	hibernate         bool
}

func New(opts ...Option) (drivers.Driver, error) {
	p := new(config)
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

func (p *config) DriverName() string {
	return string(types.HetznerCloud)
}

func (p *config) CanHibernate() bool {
	return p.hibernate
}

func (p *config) Create(ctx context.Context, opts *types.InstanceCreateOpts) (instance *types.Instance, err error) {
	startTime := time.Now()
	logr := logger.FromContext(ctx).
		WithField("driver", types.DigitalOcean).
		WithField("pool", opts.PoolName).
		// WithField("image", p.image).
		WithField("hibernate", p.CanHibernate())
	var name = fmt.Sprintf("%s-%s-%s", opts.RunnerName, opts.PoolName, uniuri.NewLen(8)) //nolint:gomnd
	logr.Infof("hetznercloud: creating instance %s", name)


	// convert tags to map
	tags := make(map[string]string)
	for _, tag := range p.tags {
		tags[tag] = ""
	}

	serverOpts := hcloud.ServerCreateOpts{
		Name:       name,
		Location:   &hcloud.Location{Name: p.region},
		ServerType: &hcloud.ServerType{Name: p.size},
		Image:      &hcloud.Image{Name: p.image},
		UserData:   p.userData,
		Labels:     tags,
	}

	client := hcloud.NewClient(hcloud.WithToken(p.token))
	server, _, err := client.Server.Create(ctx, serverOpts)
	if err != nil {
		logr.WithError(err).
			Errorln("cannot create instance")
		return nil, err
	}
	logr.Infof("hetznercloud: instance created %s", name)

	// get firewall id
	if p.FirewallID == 0 {
		id, getFirewallErr := getFirewallID(ctx, client)
		if getFirewallErr != nil {
			logr.WithError(getFirewallErr).
				Errorln("cannot get firewall id")
			return nil, getFirewallErr
		}
		p.FirewallID = id
	}
	firewall, _, err := client.Firewall.GetByID(ctx, p.FirewallID)
	if err != nil || firewall == nil {
		logr.WithError(err).
			Errorln("could not get firewall")
		return nil, err
	}
	// setup the firewall
	_, _, firewallErr := client.Firewall.ApplyResources(ctx, firewall, []hcloud.FirewallResource{
		{
			Type: hcloud.FirewallResourceTypeServer,
			Server: &hcloud.FirewallResourceServer{
				ID: server.Server.ID,
			},
		},
	})
	if firewallErr != nil {
		logr.WithError(firewallErr).
			Errorln("cannot assign instance to firewall")
		return nil, firewallErr
	}
	logr.Infof("hetznercloud: firewall configured %s", name)

	// initialize the instance
	return &types.Instance{
		Name:         name,
		Provider:     types.HetznerCloud, // this is driver, though its the old legacy name of provider
		State:        types.StateCreated,
		Pool:         opts.PoolName,
		Region:       p.region,
		Image:        p.image,
		Size:         p.size,
		Platform:     opts.Platform,
		Address:      string(server.Server.PublicNet.IPv4.IP),
		CAKey:        opts.CAKey,
		CACert:       opts.CACert,
		TLSKey:       opts.TLSKey,
		TLSCert:      opts.TLSCert,
		Started:      startTime.Unix(),
		Updated:      startTime.Unix(),
		IsHibernated: false,
		Port:         lehelper.LiteEnginePort,
	}, nil
}

func (p *config) Start(ctx context.Context, instanceID, poolName string) (ipAddress string, err error) {
	logr := logger.FromContext(ctx).
		WithField("id", instanceID).
		WithField("cloud", types.HetznerCloud)
	
	id, err := strconv.ParseInt(instanceID, 10, 64)
	if err != nil {
		return "", err
	}

	client := hcloud.NewClient(hcloud.WithToken(p.token))
	_, _, err = client.Server.Poweron(ctx, &hcloud.Server{ID: id})
	if err != nil {
		logr.WithError(err).Errorln("hetznercloud: failed to poweron VM")
		return "", err
	}

	logr.Traceln("hetznercloud: VM started")

	server, _, err := client.Server.GetByID(ctx, id)
	if err != nil {
		logr.WithError(err).Errorln("hetznercloud: failed to get VM")
		return "", err
	}

	return string(server.PublicNet.IPv4.IP), nil
}

func (p *config) Hibernate(ctx context.Context, instanceID, poolName string) error {
	logr := logger.FromContext(ctx).
		WithField("id", instanceID).
		WithField("cloud", types.HetznerCloud)
	
	id, err := strconv.ParseInt(instanceID, 10, 64)
	if err != nil {
		return err
	}

	client := hcloud.NewClient(hcloud.WithToken(p.token))
	_, _, err = client.Server.Poweroff(ctx, &hcloud.Server{ID: id})
	if err != nil {
		logr.WithError(err).Errorln("hetznercloud: failed to poweroff VM")
		return err
	}

	logr.Traceln("hetznercloud: VM hibernated")
	return nil
}

func (p *config) Destroy(ctx context.Context, instances []*types.Instance) (err error) {
	var instanceIDs []string
	for _, instance := range instances {
		instanceIDs = append(instanceIDs, instance.ID)
	}
	if len(instanceIDs) == 0 {
		return fmt.Errorf("no instance ids provided")
	}

	logr := logger.FromContext(ctx).
		WithField("id", instanceIDs).
		WithField("driver", types.DigitalOcean)

	client := hcloud.NewClient(hcloud.WithToken(p.token))
	for _, instanceID := range instanceIDs {
		id, err := strconv.ParseInt(instanceID, 10, 64)
		if err != nil {
			return err
		}

		_, res, err := client.Server.GetByID(ctx, id)
		if err != nil && res.StatusCode == 404 {
			logr.WithError(err).
				Warnln("server does not exist")
			return fmt.Errorf("server does not exist '%s'", err)
		} else if err != nil {
			logr.WithError(err).
				Errorln("cannot find server")
			return err
		}
		logr.Debugln("deleting droplet")

		_, _, err = client.Server.DeleteWithResult(ctx, &hcloud.Server{ID: id})
		if err != nil {
			logr.WithError(err).
				Errorln("deleting server failed")
			return err
		}
		logr.Debugln("server deleted")
	}
	logr.Traceln("hetznercloud: VM terminated")

	return
}

func (p *config) Ping(ctx context.Context) error {
	client := hcloud.NewClient(hcloud.WithToken(p.token))
	_, _, err := client.Server.List(ctx, hcloud.ServerListOpts{})
	return err
}

func (p *config) SetTags(context.Context, *types.Instance, map[string]string) error {
	return nil
}

func (p *config) Logs(ctx context.Context, instanceID string) (string, error) {
	return "no logs here", nil
}

func (p *config) RootDir() string {
	return p.rootDir
}

// retrieve the runner firewall id or create a new one.
func getFirewallID(ctx context.Context, client *hcloud.Client) (int64, error) {
	firewalls, _, listErr := client.Firewall.List(ctx, hcloud.FirewallListOpts{})
	if listErr != nil {
		return 0, listErr
	}
	// if the firewall already exists, return the id. NB we do not update any new firewall rules.
	for i := range firewalls {
		if firewalls[i].Name == "harness-runner" {
			return firewalls[i].ID, nil
		}
	}

	rules := []hcloud.FirewallRule{
		{
			Direction: hcloud.FirewallRuleDirectionIn,
			Protocol: hcloud.FirewallRuleProtocolTCP,
			Port:     hcloud.Ptr("9079"),
			SourceIPs: []net.IPNet{
				{
					IP:   net.IPv4zero,
					Mask: net.IPv4Mask(0, 0, 0, 0),
				},
				{
					IP:   net.IPv6zero,
				},
			},
		},
		{
			Direction:      hcloud.FirewallRuleDirectionOut,
			Protocol:       hcloud.FirewallRuleProtocolICMP,
			Port:           hcloud.Ptr("0"),
			DestinationIPs: []net.IPNet{
				{
					IP:   net.IPv4zero,
					Mask: net.IPv4Mask(0, 0, 0, 0),
				},
				{
					IP:   net.IPv6zero,
				},
			},
		},
		{
			Direction:      hcloud.FirewallRuleDirectionOut,
			Protocol:       hcloud.FirewallRuleProtocolTCP,
			Port:           hcloud.Ptr("0"),
			DestinationIPs: []net.IPNet{
				{
					IP:   net.IPv4zero,
					Mask: net.IPv4Mask(0, 0, 0, 0),
				},
				{
					IP:   net.IPv6zero,
				},
			},
		},
		{
			Direction:      hcloud.FirewallRuleDirectionOut,
			Protocol:       hcloud.FirewallRuleProtocolUDP,
			Port:           hcloud.Ptr("0"),
			DestinationIPs: []net.IPNet{
				{
					IP:   net.IPv4zero,
					Mask: net.IPv4Mask(0, 0, 0, 0),
				},
				{
					IP:   net.IPv6zero,
				},
			},
		},
	}

	// firewall does not exist, create one.
	firewall, _, createErr := client.Firewall.Create(ctx, hcloud.FirewallCreateOpts{
		Name:         "harness-runner",
		Rules:        rules,
	})

	if createErr != nil {
		return 0, createErr
	}
	return firewall.Firewall.ID, nil
}
