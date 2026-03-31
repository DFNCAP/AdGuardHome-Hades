//go:build iptables

package dnsforward

import (
	"strings"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/log"
	"github.com/jeremmfr/go-iptables/iptables"
	"github.com/miekg/dns"
)

const (
	defaultFRChainName = "AdGuardFirewall"
	defaultInterface   = "wlan1"
)

type firewallRule struct {
	table       string
	proto       string
	ifaceIn     string
	ifaceOut    string
	source      string
	notSource   bool
	destination string
	// notDestination bool
	action string
	dport  string
	// sport       string
	ctstate string
	state   string
	dports  string
	custom  []string
}

func initFirewallRule() *firewallRule {
	return &firewallRule{
		proto:       "all",
		ifaceIn:     "*",
		ifaceOut:    "*",
		source:      "0.0.0.0_0",
		destination: "0.0.0.0_0",
		action:      "ACCEPT",
		notSource:   false,
	}
}

func (f *firewallRule) generateRulespec() []string {
	var specEnd []string

	if f.ctstate != "" {
		specEnd = append(specEnd, "-m", "conntrack", "--ctstate", f.ctstate)
	}
	if f.dport != "" {
		specEnd = append(specEnd, "--dport", f.dport)
	}
	if f.dports != "" {
		specEnd = append(specEnd, "-m", "multiport", "--dports", f.dports)
	}
	if f.state != "" {
		specEnd = append(specEnd, "-m", "state", "--state", f.state)
	}
	if len(f.custom) > 0 {
		specEnd = append(specEnd, f.custom...)
	}
	if f.ifaceIn != "*" && f.ifaceIn != "" {
		specEnd = append(specEnd, "-i", f.ifaceIn)
	}
	if f.ifaceOut != "*" && f.ifaceOut != "" {
		specEnd = append(specEnd, "-o", f.ifaceOut)
	}

	ruleSpecs := []string{}
	if f.proto != "all" && f.proto != "" {
		ruleSpecs = append(ruleSpecs, "-p", f.proto)
	}
	if f.notSource {
		ruleSpecs = append(ruleSpecs, "!", "-s", strings.ReplaceAll(f.source, "_", "/"))
	} else {
		ruleSpecs = append(ruleSpecs, "-s", strings.ReplaceAll(f.source, "_", "/"))
	}
	ruleSpecs = append(ruleSpecs, "-d", strings.ReplaceAll(f.destination, "_", "/"))
	ruleSpecs = append(ruleSpecs, "-j", f.action)
	ruleSpecs = append(ruleSpecs, specEnd...)
	log.Debug("FireRule Generation: %s", ruleSpecs)
	return ruleSpecs
}

type firewallContext struct {
	ipt             *iptables.IPTables
	ipt6            *iptables.IPTables
	enabled         bool
	homeAddress     string
	monitoredChains map[string]bool
}

func initialiseFirewall(homeAddress string) *firewallContext {
	log.Info("Firewall Initialised with IP: %s", homeAddress)
	f := firewallContext{
		enabled:         true,
		homeAddress:     homeAddress,
		monitoredChains: make(map[string]bool),
	}
	ipt, err := iptables.New()
	if err != nil {
		return nil
	}
	f.ipt = ipt

	ipt, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		return nil
	}
	f.ipt6 = ipt

	log.Debug("%+v", f)
	return &f
}

func (fctx *firewallContext) removeChainFromFilter(cn string) error {
	fr := initFirewallRule()
	fr.action = cn
	clear := false
	for !clear {
		respErr := fctx.ipt.Delete("filter", "INPUT", fr.generateRulespec()...)
		if respErr != nil {
			if strings.Contains(respErr.Error(), "No chain/target/match by that name.") {
				clear = true
			} else if strings.Contains(respErr.Error(), "does a matching rule exist in that chain?") {
				clear = true
			} else {
				log.Error("%+v", respErr)
				return respErr
			}
		}
	}
	clear = false
	for !clear {
		respErr := fctx.ipt.Delete("filter", "FORWARD", fr.generateRulespec()...)
		if respErr != nil {
			if strings.Contains(respErr.Error(), "No chain/target/match by that name.") {
				clear = true
			} else if strings.Contains(respErr.Error(), "does a matching rule exist in that chain?") {
				clear = true
			} else {
				log.Error("%+v", respErr)
				return respErr
			}
		}
	}
	respErr := fctx.ipt.ClearChain("filter", cn)
	if respErr != nil {
		log.Error("Failing Silently: %+v", respErr)
	}
	respErr = fctx.ipt.DeleteChain("filter", cn)
	if respErr != nil {
		log.Error("%+v", respErr)
		return respErr
	}

	return nil
}

func (fctx *firewallContext) setFILTERTable(add bool) error {
	if add {
		// Create the chain in ipTables
		respErr := fctx.ipt.ClearChain("filter", defaultFRChainName)
		if respErr != nil {
			log.Error("%+v", respErr)
			return respErr
		}

		var aFRRules []*firewallRule

		// All traffic from wlan0 to port 53 tcp/udp ACCEPT (DNS)
		fr := initFirewallRule()
		fr.table = "filter"
		fr.ifaceIn = defaultInterface
		fr.dport = "53"
		fr.proto = "tcp"
		fr.source = fctx.homeAddress
		fr.notSource = true
		fr.destination = fctx.homeAddress
		aFRRules = append(aFRRules, fr)

		fr = initFirewallRule()
		fr.table = "filter"
		fr.ifaceIn = defaultInterface
		fr.dport = "53"
		fr.proto = "udp"
		fr.source = fctx.homeAddress
		fr.notSource = true
		fr.destination = fctx.homeAddress
		aFRRules = append(aFRRules, fr)

		// All traffic from wlan0 to port 67/68 udp ACCEPT (DHCP)
		fr = initFirewallRule()
		fr.table = "filter"
		fr.ifaceIn = defaultInterface
		fr.dport = "67:68"
		fr.proto = "udp"
		aFRRules = append(aFRRules, fr)

		// All traffic from wlan0 to port 80 tcp ACCEPT (HTTP Captive Port / Site Blocker)
		fr = initFirewallRule()
		fr.table = "filter"
		fr.ifaceIn = defaultInterface
		fr.dport = "80"
		fr.proto = "tcp"
		fr.source = fctx.homeAddress
		fr.notSource = true
		fr.destination = fctx.homeAddress
		aFRRules = append(aFRRules, fr)

		// Allow SSH from wlan0
		fr = initFirewallRule()
		fr.table = "filter"
		fr.ifaceIn = defaultInterface
		fr.dport = "22"
		fr.proto = "tcp"
		fr.source = fctx.homeAddress
		fr.notSource = true
		fr.destination = fctx.homeAddress
		aFRRules = append(aFRRules, fr)

		// RETURN at end of CHAIN
		fr = initFirewallRule()
		fr.table = "filter"
		fr.action = "RETURN"
		aFRRules = append(aFRRules, fr)

		for _, rule := range aFRRules {
			respErr = fctx.ipt.AppendUnique(rule.table, defaultFRChainName, rule.generateRulespec()...)
			if respErr != nil {
				log.Error("%+v", respErr)
				return nil
			}
		}

		// Default chain append to end of current INPUT and FORWARD
		fr = initFirewallRule()
		fr.ifaceIn = defaultInterface
		fr.action = defaultFRChainName
		respErr = fctx.ipt.AppendUnique("filter", "INPUT", fr.generateRulespec()...)
		if respErr != nil {
			log.Error("%+v", respErr)
			return nil
		}
		respErr = fctx.ipt.AppendUnique("filter", "FORWARD", fr.generateRulespec()...)
		if respErr != nil {
			log.Error("%+v", respErr)
			return nil
		}

		// Drop all IPv6 packets
		respErr = fctx.ipt6.ChangePolicy("filter", "INPUT", "DROP")
		if respErr != nil {
			log.Error("%+v", respErr)
			return nil
		}
		respErr = fctx.ipt6.ChangePolicy("filter", "FORWARD", "DROP")
		if respErr != nil {
			log.Error("%+v", respErr)
			return nil
		}
		respErr = fctx.ipt6.ChangePolicy("filter", "OUTPUT", "DROP")
		if respErr != nil {
			log.Error("%+v", respErr)
			return nil
		}
	} else {
		// Remove any monitored chains
		log.Debug("Length of MonChains: %s", len(fctx.monitoredChains))
		if len(fctx.monitoredChains) > 0 {
			for chain := range fctx.monitoredChains {
				fctx.removeChainFromFilter(chain)
			}
		}

		fr := initFirewallRule()
		fr.ifaceIn = defaultInterface
		fr.action = defaultFRChainName
		clear := false
		for !clear {
			respErr := fctx.ipt.Delete("filter", "INPUT", fr.generateRulespec()...)
			if respErr != nil {
				if strings.Contains(respErr.Error(), "No chain/target/match by that name.") {
					clear = true
				} else if strings.Contains(respErr.Error(), "does a matching rule exist in that chain?") {
					clear = true
				} else {
					log.Error("%+v", respErr)
					return respErr
				}
			}
		}
		clear = false
		for !clear {
			respErr := fctx.ipt.Delete("filter", "FORWARD", fr.generateRulespec()...)
			if respErr != nil {
				if strings.Contains(respErr.Error(), "No chain/target/match by that name.") {
					clear = true
				} else if strings.Contains(respErr.Error(), "does a matching rule exist in that chain?") {
					clear = true
				} else {
					log.Error("%+v", respErr)
					return respErr
				}
			}
		}
		respErr := fctx.ipt.ClearChain("filter", defaultFRChainName)
		if respErr != nil {
			log.Error("Failing Silently: %+v", respErr)
		}
		respErr = fctx.ipt.DeleteChain("filter", defaultFRChainName)
		if respErr != nil {
			log.Error("%+v", respErr)
			return respErr
		}
	}

	return nil
}

func (fctx *firewallContext) setNATTable(add bool) error {
	if add {
		// Create the chain in ipTables
		respErr := fctx.ipt.ClearChain("nat", defaultFRChainName)
		if respErr != nil {
			log.Error("Failing Silently: %+v", respErr)
		}

		aFRRules := []*firewallRule{}
		// All traffic from wlan0 to dest (Global DNS Server) port 53 tcp/udp FORWARD to 172.10.10.1
		fr := initFirewallRule()
		fr.table = "nat"
		fr.ifaceIn = defaultInterface
		fr.dport = "53"
		fr.proto = "tcp"
		fr.source = fctx.homeAddress
		fr.notSource = true
		fr.action = "DNAT"
		fr.custom = []string{"--to-destination", fctx.homeAddress + ":53"}
		aFRRules = append(aFRRules, fr)

		fr = initFirewallRule()
		fr.table = "nat"
		fr.ifaceIn = defaultInterface
		fr.dport = "53"
		fr.proto = "udp"
		fr.source = fctx.homeAddress
		fr.notSource = true
		fr.action = "DNAT"
		fr.custom = []string{"--to-destination", fctx.homeAddress + ":53"}
		aFRRules = append(aFRRules, fr)

		fr = initFirewallRule()
		fr.table = "nat"
		fr.action = "RETURN"
		aFRRules = append(aFRRules, fr)

		for _, rule := range aFRRules {
			respErr := fctx.ipt.AppendUnique(rule.table, defaultFRChainName, rule.generateRulespec()...)
			if respErr != nil {
				log.Error("%+v", respErr)
				return nil
			}
		}

		fr = initFirewallRule()
		fr.action = defaultFRChainName
		fr.ifaceIn = defaultInterface
		respErr = fctx.ipt.AppendUnique("nat", "PREROUTING", fr.generateRulespec()...)
		if respErr != nil {
			log.Error("%+v", respErr)
			return nil
		}

		// Drop all IPv6 packets (not supported in NAT Table)
		// respErr = fctx.ipt6.ChangePolicy("nat", "INPUT", "DROP")
		// if respErr != nil {
		// 	log.Error("%+v", respErr)
		// 	return nil
		// }
		// respErr = fctx.ipt6.ChangePolicy("nat", "OUTPUT", "DROP")
		// if respErr != nil {
		// 	log.Error("%+v", respErr)
		// 	return nil
		// }

	} else {
		fr := initFirewallRule()
		fr.ifaceIn = defaultInterface
		fr.action = defaultFRChainName
		clear := false
		for !clear {
			respErr := fctx.ipt.Delete("nat", "PREROUTING", fr.generateRulespec()...)
			if respErr != nil {
				if strings.Contains(respErr.Error(), "No chain/target/match by that name.") {
					clear = true
				} else if strings.Contains(respErr.Error(), "does a matching rule exist in that chain?") {
					clear = true
				} else {
					log.Error("%+v", respErr)
					return respErr
				}
			}
		}
		// This always creates a new one, therefore must delete (acts as a flush)
		respErr := fctx.ipt.ClearChain("nat", defaultFRChainName)
		if respErr != nil {
			log.Error("%+v", respErr)
			return respErr
		}
		respErr = fctx.ipt.DeleteChain("nat", defaultFRChainName)
		if respErr != nil {
			log.Error("%+v", respErr)
			return respErr
		}
	}

	return nil
}

func (fctx *firewallContext) start() error {
	respErr := fctx.setFILTERTable(true)
	if respErr != nil {
		return respErr
	}

	respErr = fctx.setNATTable(true)
	if respErr != nil {
		return respErr
	}

	fctx.enabled = true
	log.Info("Firewall Started.")

	return nil
}

func (fctx *firewallContext) close() error {
	var respErr error
	respErr = fctx.setFILTERTable(false)
	if respErr != nil {
		return respErr
	}
	respErr = fctx.setNATTable(false)
	if respErr != nil {
		return respErr
	}

	fctx.enabled = false
	log.Info("Firewall Stopped.")

	return nil
}

func (fctx *firewallContext) openRoute(cn, ipSource, ipDest string) error {
	chainName := cn
	// Verify Chain Exists
	chains, respErr := fctx.ipt.ListChains("filter")
	if respErr != nil {
		return respErr
	}
	// If it doesn't exist create the Chain
	if !contains(chains, chainName) {
		respErr = fctx.addClientFunc(chainName, ipSource)
		if respErr != nil {
			return respErr
		}
	}

	// Open Firewall at position 1
	fr := initFirewallRule()
	fr.table = "filter"
	fr.ifaceIn = defaultInterface
	fr.source = ipSource
	fr.destination = ipDest
	fr.action = "ACCEPT"
	exists, respErr := fctx.ipt.Exists(fr.table, chainName, fr.generateRulespec()...)
	if respErr != nil {
		return respErr
	}
	if !exists {
		respErr = fctx.ipt.Insert(fr.table, chainName, 1, fr.generateRulespec()...)
		if respErr != nil {
			return respErr
		}
	}

	return nil
}

// func createID(ip string) string {
// 	return "ADGUARD_" + ip
// }

// Contains tells whether a contains x.
func contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

func (fctx *firewallContext) addClientFunc(chainName, ipAddress string) error {
	// Create the chain in ipTables
	respErr := fctx.ipt.ClearChain("filter", chainName)
	if respErr != nil {
		return respErr
	}

	var aFRRules []*firewallRule

	// ACCEPT Establish Connections from Internet to Client
	fr := initFirewallRule()
	fr.table = "filter"
	fr.ifaceOut = defaultInterface
	fr.destination = ipAddress
	fr.ctstate = "ESTABLISHED,RELATED"
	fr.action = "ACCEPT"
	aFRRules = append(aFRRules, fr)

	// Make sure we DROP if it falls through
	fr = initFirewallRule()
	fr.table = "filter"
	fr.ifaceIn = defaultInterface
	fr.source = ipAddress
	fr.action = "DROP"
	aFRRules = append(aFRRules, fr)

	for _, rule := range aFRRules {
		respErr = fctx.ipt.AppendUnique(rule.table, chainName, rule.generateRulespec()...)
		if respErr != nil {
			log.Error("%+v", respErr)
			return respErr
		}
	}

	// Append Chain to end of INPUT and FORWARD
	fr = initFirewallRule()
	fr.action = chainName
	respErr = fctx.ipt.AppendUnique("filter", "INPUT", fr.generateRulespec()...)
	if respErr != nil {
		log.Error("%+v", respErr)
		return respErr
	}
	respErr = fctx.ipt.AppendUnique("filter", "FORWARD", fr.generateRulespec()...)
	if respErr != nil {
		log.Error("%+v", respErr)
		return respErr
	}

	fctx.monitoredChains[chainName] = true
	return nil
}

func (fctx *firewallContext) removeClientFunc(chainName string) error {
	err := fctx.removeChainFromFilter(chainName)
	if err != nil {
		return err
	}

	delete(fctx.monitoredChains, chainName)
	return nil
}

func processIPTables(dctx *dnsContext) (rc resultCode) {
	log.Debug("--------- PROCESSIPTABLES ------------")
	if dctx.result != nil {
		if dctx.result.Reason != filtering.NotFilteredAllowList && dctx.result.Reason != filtering.NotFilteredNotFound && dctx.result.Reason != filtering.RewrittenRule {
			log.Debug("NO: Shall not add IPTables")
			return resultCodeSuccess
		}
	}
	var ipSource string
	var ipDestinations []string
	var clientName string
	if dctx.setts != nil {
		if dctx.setts.ClientName == "" {
			log.Debug("NO: Client has no name")
			return resultCodeSuccess
		}
		ipSource = dctx.setts.ClientIP.String()
		clientName = dctx.setts.ClientName
	}
	if dctx.proxyCtx != nil {
		// Get all A Records
		for _, a := range dctx.proxyCtx.Res.Answer {
			switch v := a.(type) {
			case *dns.A:
				ipDestinations = append(ipDestinations, v.A.String())
			default:
				continue
			}
		}
	}

	if ipSource == "" || clientName == "" || len(ipDestinations) == 0 {
		log.Debug("NO: Not enough information to open Firewall. IS: %s, ID: %s, CN: %s", ipSource, ipDestinations, clientName)
		return resultCodeSuccess
	}
	// Now we open the firewall for each
	if dctx.srv.firewall != nil {
		for _, d := range ipDestinations {
			respErr := dctx.srv.firewall.openRoute(clientName, ipSource, d)
			if respErr != nil {
				log.Error("Process IP Tables Error: %w", respErr)
				return resultCodeError
			}
		}
	} else {
		log.Error("NO: Firewall not in Server context")
		return resultCodeError
	}

	return resultCodeSuccess
}
