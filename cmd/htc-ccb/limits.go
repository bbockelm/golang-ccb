package main

import (
	"github.com/htcondor/golang-htcondor/config"
	"github.com/htcondor/golang-htcondor/logging"

	ccbserver "github.com/bbockelm/golang-ccb"
)

// spliceDescriptorShare is the fraction of the descriptor limit the default
// broker-wide relay cap allows. A relay holds two descriptors; a quarter of
// the limit in relays leaves the other half for registrations (one each) and
// connections mid-handshake, so a relay flood cannot take the descriptors the
// broker needs to accept anything at all.
const spliceDescriptorShare = 4

// brokerLimits reads the rate-limit policy from configuration. When
// CCB_LIMIT_MAX_SPLICES_TOTAL is unset it is derived from the process's
// descriptor limit.
func brokerLimits(cfg *config.Config) (ccbserver.Limits, error) {
	l, err := ccbserver.LimitsFromConfig(cfg.Get)
	if err != nil {
		return l, err
	}
	if v, ok := cfg.Get(ccbserver.MaxSplicesTotalKnob); (!ok || v == "") && l.Total.MaxSplices == 0 {
		if n := descriptorLimit(); n > 0 {
			l.Total.MaxSplices = int(n / spliceDescriptorShare)
		}
	}
	return l, nil
}

// logLimits records the policy in force, one line per network class.
func logLimits(log *logging.Logger, l ccbserver.Limits) {
	for _, line := range l.Describe() {
		log.Info(logging.DestinationGeneral, "rate limits", "policy", line)
	}
}

// reloadLimits applies a reconfigured policy. A configuration that does not
// parse keeps the policy already in force: a broker that dropped its limits
// because of a typo would be open to exactly the traffic they were set for.
func reloadLimits(log *logging.Logger, srv *ccbserver.Server, cfg *config.Config) {
	l, err := brokerLimits(cfg)
	if err == nil {
		err = srv.SetLimits(l)
	}
	if err != nil {
		log.Error(logging.DestinationGeneral, "rate limits not reconfigured; keeping the previous policy", "error", err)
		return
	}
	logLimits(log, l)
}
