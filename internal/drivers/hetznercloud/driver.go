package hetznercloud

import (
	"context"
	"fmt"
	"net"
	"strings"

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
	token            string
	location         string
	image            string
	size             string
	FirewallID       int64
	tags             []string
	userData         string
	rootDir          string
	hibernate        bool
	disablePublicNet bool
	defaultGateway   string
	network          string
}

func New(opts ...Option) (drivers.Driver, error) {
	p := new(config)
	fmt.Println("opts %s", opts)
	for _, opt := range opts {
		fmt.Println("opt??? %s", p)
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
		WithField("driver", types.HetznerCloud).
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

	logr.Infof("Token :%s: :%s:", p.network, p.token)
	client := hcloud.NewClient(hcloud.WithToken(p.token))

	network, _, err := client.Network.GetByName(ctx, p.network)
	if err != nil {
		logr.WithError(err).
			Errorln("cannot get network")
		return nil, err
	}

	if network == nil && p.disablePublicNet {
		logr.Error("hetznercloud: public net diasabled but not network found")
	}

	networks := []*hcloud.Network{}
	if network != nil {
		networks = append(networks, network)
	}

	userData := lehelper.GenerateUserdata(p.userData, opts)
	/*if p.defaultGateway != "" {
			userData = strings.Replace(userData, "runcmd:\n", `runcmd:
	- route add default gw `+p.defaultGateway+`
	- echo "DNS=8.8.8.8" >> /etc/systemd/resolved.conf
	- systemctl restart systemd-resolved.service
	`, 1)
			logr.Debugf("user data %s", userData)
		}*/
	/*if p.defaultGateway != "" {
			userData = strings.Replace(userData, "#cloud-config", `#cloud-config
	bootcmd:
	- route add default gw `+p.defaultGateway+`
	- echo "DNS=8.8.8.8" >> /etc/systemd/resolved.conf
	- systemctl restart systemd-resolved.service
	`, 1)
			logr.Debugf("user data %s", userData)
		}*/
	if p.defaultGateway != "" {
		userData = strings.Replace(userData, "#cloud-config", `#cloud-config
bootcmd:
- echo "DNS=8.8.8.8" >> /etc/systemd/resolved.conf
- 'echo "network:\n  version: 2\n  ethernets:\n    ens10:\n      routes:\n      - to: 0.0.0.0/0\n        via: `+p.defaultGateway+`" > /etc/netplan/51-netcfg.yaml'
`, 1)
		logr.Debugf("user data %s", userData)
	}

	serverOpts := hcloud.ServerCreateOpts{
		Name:       name,
		Location:   &hcloud.Location{Name: p.location},
		ServerType: &hcloud.ServerType{Name: p.size},
		Image:      &hcloud.Image{Name: p.image},
		UserData:   userData,
		Labels:     tags,
		PublicNet: &hcloud.ServerCreatePublicNet{
			EnableIPv4: !p.disablePublicNet,
			EnableIPv6: !p.disablePublicNet,
		},
		Networks: networks,
	}

	serverCreate, _, err := client.Server.Create(ctx, serverOpts)
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
	if p.FirewallID > 0 {
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
					ID: serverCreate.Server.ID,
				},
			},
		})
		if firewallErr != nil {
			logr.WithError(firewallErr).
				Errorln("cannot assign instance to firewall")
			return nil, firewallErr
		}
		logr.Infof("hetznercloud: firewall configured %s", name)
	}

	// initialize the instance
	instance = &types.Instance{
		ID:           fmt.Sprint(serverCreate.Server.ID),
		Name:         name,
		Provider:     types.HetznerCloud, // this is driver, though its the old legacy name of provider
		State:        types.StateCreated,
		Pool:         opts.PoolName,
		Region:       p.location,
		Image:        p.image,
		Size:         p.size,
		Platform:     opts.Platform,
		CAKey:        opts.CAKey,
		CACert:       opts.CACert,
		TLSKey:       opts.TLSKey,
		TLSCert:      opts.TLSCert,
		Started:      startTime.Unix(),
		Updated:      startTime.Unix(),
		IsHibernated: false,
		Port:         lehelper.LiteEnginePort,
	}
	// poll the hetznercloud endpoint for server updates and exit when a network address is allocated.
	interval := time.Duration(0)
poller:
	for {
		select {
		case <-ctx.Done():
			logr.WithField("name", instance.Name).
				Debugln("cannot ascertain network")

			return instance, ctx.Err()
		case <-time.After(interval):
			interval = time.Minute

			logr.WithField("name", instance.Name).
				Debugln("find instance network")

			server, _, err := client.Server.GetByID(ctx, serverCreate.Server.ID)

			if err != nil {
				logr.WithError(err).
					Errorln("cannot find instance")
				return instance, err
			}
			logr.Debugf("instance %d %s", server.ID, instance.ID)
			logr.Debugf("status %s", server.Status)
			logr.Debugf("private network %s", server.PrivateNet)
			if p.disablePublicNet && len(server.PrivateNet) > 0 {
				instance.Address = server.PrivateNet[0].IP.String()
			} else {
				instance.Address = server.PublicNet.IPv4.IP.String()
			}
			logr.Debugf("instance address %s", instance.Address)

			if server.Status == hcloud.ServerStatusRunning {
				break poller
			}

		}
	}
	logr.Debugf("server created %s", instance.Address)

	return instance, err
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
		WithField("driver", types.HetznerCloud)

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
			Protocol:  hcloud.FirewallRuleProtocolTCP,
			Port:      hcloud.Ptr("9079"),
			SourceIPs: []net.IPNet{
				{
					IP:   net.ParseIP("0.0.0.0"),
					Mask: net.CIDRMask(0, 32),
				},
				{
					IP:   net.ParseIP("::"),
					Mask: net.CIDRMask(0, 128),
				},
			},
		},
		{
			Direction: hcloud.FirewallRuleDirectionOut,
			Protocol:  hcloud.FirewallRuleProtocolICMP,
			DestinationIPs: []net.IPNet{
				{
					IP:   net.ParseIP("0.0.0.0"),
					Mask: net.CIDRMask(0, 32),
				},
				{
					IP:   net.ParseIP("::"),
					Mask: net.CIDRMask(0, 128),
				},
			},
		},
		{
			Direction: hcloud.FirewallRuleDirectionOut,
			Protocol:  hcloud.FirewallRuleProtocolTCP,
			Port:      hcloud.Ptr("any"),
			DestinationIPs: []net.IPNet{
				{
					IP:   net.ParseIP("0.0.0.0"),
					Mask: net.CIDRMask(0, 32),
				},
				{
					IP:   net.ParseIP("::"),
					Mask: net.CIDRMask(0, 128),
				},
			},
		},
		{
			Direction: hcloud.FirewallRuleDirectionOut,
			Protocol:  hcloud.FirewallRuleProtocolUDP,
			Port:      hcloud.Ptr("any"),
			DestinationIPs: []net.IPNet{
				{
					IP:   net.ParseIP("0.0.0.0"),
					Mask: net.CIDRMask(0, 32),
				},
				{
					IP:   net.ParseIP("::"),
					Mask: net.CIDRMask(0, 128),
				},
			},
		},
	}

	// firewall does not exist, create one.
	firewall, _, createErr := client.Firewall.Create(ctx, hcloud.FirewallCreateOpts{
		Name:  "harness-runner",
		Rules: rules,
	})

	if createErr != nil {
		return 0, createErr
	}
	return firewall.Firewall.ID, nil
}
