package harness

import (
	"context"
	"math"
	"time"

	"github.com/drone-runners/drone-runner-aws/command/config"
	"github.com/drone-runners/drone-runner-aws/internal/drivers"
	"github.com/drone-runners/drone-runner-aws/internal/poolfile"
	"github.com/sirupsen/logrus"
)

func SetupPool(ctx context.Context, env *config.EnvConfig, poolManager drivers.IManager, poolFile string) (*config.PoolFile, error) {
	configPool, confErr := poolfile.ConfigPoolFile(poolFile, env)
	if confErr != nil {
		logrus.WithError(confErr).Fatalln("Unable to load pool file, or use an in memory pool")
	}

	pools, err := poolfile.ProcessPool(configPool, env.Runner.Name)
	if err != nil {
		logrus.WithError(err).Errorln("unable to process pool file")
		return configPool, err
	}

	if poolManager.IsDistributed() {
		for i := range pools {
			// use minimum of these for distributed pool
			pools[i].MinSize = int(math.Min(float64(pools[i].MinSize), float64(env.Settings.MinPoolSize)))
		}
	}

	err = poolManager.Add(pools...)
	if err != nil {
		logrus.WithError(err).Errorln("unable to add pools")
		return configPool, err
	}

	err = poolManager.PingDriver(ctx)
	if err != nil {
		logrus.WithError(err).
			Errorln("unable to ping driver")
		return configPool, err
	}

	err = poolManager.AddTmate(env)
	if err != nil {
		logrus.WithError(err).
			Errorln("unable to set tmate configuration")
		return configPool, err
	}

	// setup lifetimes of instances
	busyMaxAge := time.Hour * time.Duration(env.Settings.BusyMaxAge) // includes time required to setup an instance
	freeMaxAge := time.Hour * time.Duration(env.Settings.FreeMaxAge)
	err = poolManager.StartInstancePurger(ctx, busyMaxAge, freeMaxAge)
	if err != nil {
		logrus.WithError(err).
			Errorln("failed to start instance purger")
		return configPool, err
	}
	// lets remove any old instances.
	if !env.Settings.ReusePool {
		cleanErr := poolManager.CleanPools(ctx, true, true)
		if cleanErr != nil {
			return configPool, cleanErr
		}
		logrus.Infoln("pools cleaned")
	}
	// seed pools
	buildPoolErr := poolManager.BuildPools(ctx)
	if buildPoolErr != nil {
		logrus.WithError(buildPoolErr).
			Errorln("unable to build pool")
		return configPool, buildPoolErr
	}
	logrus.Infoln("pool created")
	return configPool, nil
}

func Cleanup(env *config.EnvConfig, poolManager drivers.IManager, destroyBusy, destroyFree bool) error {
	if env.Settings.ReusePool {
		return nil
	}

	cleanErr := poolManager.CleanPools(context.Background(), destroyBusy, destroyFree)
	if cleanErr != nil {
		logrus.WithError(cleanErr).Errorln("unable to clean pools")
	} else {
		logrus.Infoln("pools cleaned")
	}

	return cleanErr
}
