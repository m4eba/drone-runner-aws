package hetznercloud

import (
	"fmt"
	"os"

	"github.com/drone-runners/drone-runner-aws/internal/oshelp"
	"github.com/drone-runners/drone-runner-aws/types"
	"github.com/sirupsen/logrus"
)

type Option func(*config)

func SetPlatformDefaults(platform *types.Platform) (*types.Platform, error) {
	if platform.Arch == "" {
		platform.Arch = oshelp.ArchAMD64
	}
	if platform.Arch != oshelp.ArchAMD64 && platform.Arch != oshelp.ArchARM64 {
		return platform, fmt.Errorf("invalid arch %s, has to be '%s/%s'", platform.Arch, oshelp.ArchAMD64, oshelp.ArchARM64)
	}
	// verify that we are using sane values for OS
	if platform.OS == "" {
		platform.OS = oshelp.OSLinux
	}
	if platform.OS != oshelp.OSLinux {
		return platform, fmt.Errorf("hetznercloud - invalid OS %s, has to be '%s'", platform.OS, oshelp.OSLinux)
	}

	return platform, nil
}

func WithToken(token string) Option {
	return func(p *config) {
		p.token = token
	}
}

func WithLocation(location string) Option {
	return func(p *config) {
		if location == "" {
			p.location = "nbg1"
		} else {
			p.location = location
		}
	}
}

func WithImage(image string) Option {
	return func(p *config) {
		if image == "" {
			p.image = "ubuntu-20.04"
		} else {
			p.image = image
		}
	}
}

func WithSize(size string) Option {
	return func(p *config) {
		if size == "" {
			p.size = "cx11"
		} else {
			p.size = size
		}
	}
}

func WithFirewallID(firewallID int64) Option {
	return func(p *config) {
		p.FirewallID = firewallID
	}
}

func WithTags(tags []string) Option {
	return func(p *config) {
		p.tags = tags
	}
}

func WithUserData(text, path string) Option {
	if text != "" {
		return func(p *config) {
			p.userData = text
		}
	}
	return func(p *config) {
		if path != "" {
			data, err := os.ReadFile(path)
			if err != nil {
				logrus.WithError(err).
					Fatalln("failed to read user_data file")
				return
			}
			p.userData = string(data)
		}
	}
}

// WithRootDirectory sets the root directory for the virtual machine.
func WithRootDirectory(dir string) Option {
	return func(p *config) {
		p.rootDir = oshelp.JoinPaths(oshelp.OSLinux, "/tmp", "hetznercloud")
	}
}

func WithDisablePublicNet(disable bool) Option {
	return func(p *config) {
		p.disablePublicNet = disable
	}
}

func WithDefaultGateway(gateway string) Option {
	return func(p *config) {
		p.defaultGateway = gateway
	}
}

func WithNetwork(network string) Option {
	return func(p *config) {
		p.network = network
	}
}
