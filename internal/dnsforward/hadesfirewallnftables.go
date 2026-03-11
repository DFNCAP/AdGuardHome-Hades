//go:build !iptables

package dnsforward

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/log"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

const (
	defaultFRChainName = "AdGuardFirewall"
	defaultInterface   = "wlan1"
	nftTableName       = "adguard"
)

type firewallContext struct {
	conn            *nftables.Conn
	filterTable     *nftables.Table
	natTable        *nftables.Table
	filterTable6    *nftables.Table
	inputChain      *nftables.Chain
	forwardChain    *nftables.Chain
	preroutingChain *nftables.Chain
	enabled         bool
	homeAddress     string
	interfaceName   string
	monitoredChains map[string]*nftables.Chain
	allowedIPs      map[string]map[string]bool // chainName -> {ipDest -> true}
}

func initialiseFirewall(homeAddress, interfaceName string) *firewallContext {
	// Use default interface if none provided
	if interfaceName == "" {
		interfaceName = defaultInterface
	}
	log.Info("Firewall Initialised with IP: %s, Interface: %s", homeAddress, interfaceName)
	conn, err := nftables.New()
	if err != nil {
		log.Error("Failed to create nftables connection: %v", err)
		return nil
	}

	f := &firewallContext{
		conn:            conn,
		enabled:         true,
		homeAddress:     homeAddress,
		interfaceName:   interfaceName,
		monitoredChains: make(map[string]*nftables.Chain),
		allowedIPs:      make(map[string]map[string]bool),
	}

	// Create filter table for IPv4
	f.filterTable = conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   nftTableName,
	})

	// Create nat table for IPv4
	f.natTable = conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   nftTableName + "_nat",
	})

	// Create filter table for IPv6
	f.filterTable6 = conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv6,
		Name:   nftTableName + "_v6",
	})

	// Flush to create tables in kernel
	if err := conn.Flush(); err != nil {
		log.Error("Failed to create nftables tables: %v", err)
		return nil
	}

	log.Debug("%+v", f)
	return f
}

// Helper function to create accept rule expressions
func createAcceptRule(iface, proto, srcIP, dstIP string, dport uint16, invertSrc bool) []expr.Any {
	var exprs []expr.Any

	// Match input interface
	if iface != "" && iface != "*" {
		exprs = append(exprs, &expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1})
		exprs = append(exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte(iface + "\x00"),
		})
	}

	// Match protocol
	if proto == "tcp" {
		exprs = append(exprs, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1})
		exprs = append(exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{unix.IPPROTO_TCP},
		})
	} else if proto == "udp" {
		exprs = append(exprs, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1})
		exprs = append(exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{unix.IPPROTO_UDP},
		})
	}

	// Match source IP
	if srcIP != "" && srcIP != "0.0.0.0/0" {
		ip := net.ParseIP(srcIP)
		if ip != nil {
			exprs = append(exprs, &expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12,
				Len:          4,
			})
			cmpOp := expr.CmpOpEq
			if invertSrc {
				cmpOp = expr.CmpOpNeq
			}
			exprs = append(exprs, &expr.Cmp{
				Op:       cmpOp,
				Register: 1,
				Data:     ip.To4(),
			})
		}
	}

	// Match destination IP
	if dstIP != "" && dstIP != "0.0.0.0/0" {
		ip := net.ParseIP(dstIP)
		if ip != nil {
			exprs = append(exprs, &expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16,
				Len:          4,
			})
			exprs = append(exprs, &expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ip.To4(),
			})
		}
	}

	// Match destination port
	if dport > 0 {
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, dport)
		exprs = append(exprs, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		})
		exprs = append(exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     portBytes,
		})
	}

	// Accept verdict
	exprs = append(exprs, &expr.Verdict{
		Kind: expr.VerdictAccept,
	})

	return exprs
}

func createDropRule(iface, srcIP string) []expr.Any {
	var exprs []expr.Any

	// Match input interface
	if iface != "" && iface != "*" {
		exprs = append(exprs, &expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1})
		exprs = append(exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte(iface + "\x00"),
		})
	}

	// Match source IP
	if srcIP != "" && srcIP != "0.0.0.0/0" {
		ip := net.ParseIP(srcIP)
		if ip != nil {
			exprs = append(exprs, &expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12,
				Len:          4,
			})
			exprs = append(exprs, &expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ip.To4(),
			})
		}
	}

	// Drop verdict
	exprs = append(exprs, &expr.Verdict{
		Kind: expr.VerdictDrop,
	})

	return exprs
}

func createDNATRule(iface, proto, srcIP, dstAddr string, dport uint16) []expr.Any {
	var exprs []expr.Any

	// Match input interface
	if iface != "" && iface != "*" {
		exprs = append(exprs, &expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1})
		exprs = append(exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte(iface + "\x00"),
		})
	}

	// Match protocol
	if proto == "tcp" {
		exprs = append(exprs, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1})
		exprs = append(exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{unix.IPPROTO_TCP},
		})
	} else if proto == "udp" {
		exprs = append(exprs, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1})
		exprs = append(exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{unix.IPPROTO_UDP},
		})
	}

	// Match source IP (inverted - not from home address)
	if srcIP != "" && srcIP != "0.0.0.0/0" {
		ip := net.ParseIP(srcIP)
		if ip != nil {
			exprs = append(exprs, &expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12,
				Len:          4,
			})
			exprs = append(exprs, &expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     ip.To4(),
			})
		}
	}

	// Match destination port
	if dport > 0 {
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, dport)
		exprs = append(exprs, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		})
		exprs = append(exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     portBytes,
		})
	}

	// DNAT to destination
	parts := strings.Split(dstAddr, ":")
	dstIP := parts[0]
	dstPort := uint16(53)
	if len(parts) > 1 {
		if p, err := strconv.ParseUint(parts[1], 10, 16); err == nil {
			dstPort = uint16(p)
		}
	}

	ip := net.ParseIP(dstIP)
	if ip != nil {
		exprs = append(exprs, &expr.Immediate{
			Register: 1,
			Data:     ip.To4(),
		})
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, dstPort)
		exprs = append(exprs, &expr.Immediate{
			Register: 2,
			Data:     portBytes,
		})
		exprs = append(exprs, &expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      unix.NFPROTO_IPV4,
			RegAddrMin:  1,
			RegProtoMin: 2,
		})
	}

	return exprs
}

func createCTStateRule(states string) []expr.Any {
	var exprs []expr.Any

	// Load conntrack state
	exprs = append(exprs, &expr.Ct{
		Register: 1,
		Key:      expr.CtKeySTATE,
	})

	// Parse states (e.g., "ESTABLISHED,RELATED")
	var stateMask uint32
	for _, state := range strings.Split(states, ",") {
		switch strings.TrimSpace(state) {
		case "ESTABLISHED":
			stateMask |= expr.CtStateBitESTABLISHED
		case "RELATED":
			stateMask |= expr.CtStateBitRELATED
		case "NEW":
			stateMask |= expr.CtStateBitNEW
		}
	}

	stateBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(stateBytes, stateMask)

	exprs = append(exprs, &expr.Bitwise{
		SourceRegister: 1,
		DestRegister:   1,
		Len:            4,
		Mask:           stateBytes,
		Xor:            []byte{0, 0, 0, 0},
	})

	exprs = append(exprs, &expr.Cmp{
		Op:       expr.CmpOpNeq,
		Register: 1,
		Data:     []byte{0, 0, 0, 0},
	})

	return exprs
}

func (fctx *firewallContext) removeChainFromFilter(cn string) error {
	chain, exists := fctx.monitoredChains[cn]
	if !exists {
		return nil
	}

	// First, remove all jump rules that reference this chain
	// Get all rules from INPUT chain
	inputRules, err := fctx.conn.GetRules(fctx.filterTable, fctx.inputChain)
	if err != nil {
		log.Error("Failed to get INPUT chain rules: %v", err)
		return err
	}

	// Remove jump rules to this chain from INPUT
	for _, rule := range inputRules {
		for _, e := range rule.Exprs {
			if verdict, ok := e.(*expr.Verdict); ok {
				if verdict.Kind == expr.VerdictJump && verdict.Chain == cn {
					if err := fctx.conn.DelRule(rule); err != nil {
						log.Error("Failed to delete jump rule from INPUT: %v", err)
						return err
					}
				}
			}
		}
	}

	// Get all rules from FORWARD chain
	forwardRules, err := fctx.conn.GetRules(fctx.filterTable, fctx.forwardChain)
	if err != nil {
		log.Error("Failed to get FORWARD chain rules: %v", err)
		return err
	}

	// Remove jump rules to this chain from FORWARD
	for _, rule := range forwardRules {
		for _, e := range rule.Exprs {
			if verdict, ok := e.(*expr.Verdict); ok {
				if verdict.Kind == expr.VerdictJump && verdict.Chain == cn {
					if err := fctx.conn.DelRule(rule); err != nil {
						log.Error("Failed to delete jump rule from FORWARD: %v", err)
						return err
					}
				}
			}
		}
	}

	// Flush the rule deletions
	if err := fctx.conn.Flush(); err != nil {
		log.Error("Failed to flush jump rule deletions for chain %s: %v", cn, err)
		return err
	}

	// Now delete the chain itself
	fctx.conn.DelChain(chain)
	if err := fctx.conn.Flush(); err != nil {
		log.Error("Failed to delete chain %s: %v", cn, err)
		return err
	}

	return nil
}

func (fctx *firewallContext) setFILTERTable(add bool) error {
	if add {
		// Create INPUT chain
		fctx.inputChain = fctx.conn.AddChain(&nftables.Chain{
			Name:     defaultFRChainName + "_input",
			Table:    fctx.filterTable,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookInput,
			Priority: nftables.ChainPriorityFilter,
		})

		// Create FORWARD chain with drop policy
		// Traffic must match DNS rules or client chain rules to be allowed
		// Jump rules to client chains are added dynamically, then policy drop handles the rest
		forwardDropPolicy := nftables.ChainPolicyDrop
		fctx.forwardChain = fctx.conn.AddChain(&nftables.Chain{
			Name:     defaultFRChainName + "_forward",
			Table:    fctx.filterTable,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookForward,
			Priority: nftables.ChainPriorityFilter,
			Policy:   &forwardDropPolicy,
		})

		// Add rules to INPUT chain
		// DNS TCP (port 53)
		fctx.conn.AddRule(&nftables.Rule{
			Table: fctx.filterTable,
			Chain: fctx.inputChain,
			Exprs: createAcceptRule(defaultInterface, "tcp", fctx.homeAddress, fctx.homeAddress, 53, true),
		})

		// DNS UDP (port 53)
		fctx.conn.AddRule(&nftables.Rule{
			Table: fctx.filterTable,
			Chain: fctx.inputChain,
			Exprs: createAcceptRule(defaultInterface, "udp", fctx.homeAddress, fctx.homeAddress, 53, true),
		})

		// DHCP (ports 67-68)
		fctx.conn.AddRule(&nftables.Rule{
			Table: fctx.filterTable,
			Chain: fctx.inputChain,
			Exprs: createAcceptRule(defaultInterface, "udp", "", "", 67, false),
		})

		// HTTP (port 80)
		fctx.conn.AddRule(&nftables.Rule{
			Table: fctx.filterTable,
			Chain: fctx.inputChain,
			Exprs: createAcceptRule(defaultInterface, "tcp", fctx.homeAddress, fctx.homeAddress, 80, true),
		})

		// SSH (port 22)
		fctx.conn.AddRule(&nftables.Rule{
			Table: fctx.filterTable,
			Chain: fctx.inputChain,
			Exprs: createAcceptRule(defaultInterface, "tcp", fctx.homeAddress, fctx.homeAddress, 22, true),
		})

		// Add same rules to FORWARD chain
		fctx.conn.AddRule(&nftables.Rule{
			Table: fctx.filterTable,
			Chain: fctx.forwardChain,
			Exprs: createAcceptRule(defaultInterface, "tcp", fctx.homeAddress, fctx.homeAddress, 53, true),
		})

		fctx.conn.AddRule(&nftables.Rule{
			Table: fctx.filterTable,
			Chain: fctx.forwardChain,
			Exprs: createAcceptRule(defaultInterface, "udp", fctx.homeAddress, fctx.homeAddress, 53, true),
		})

		// Note: Jump rules to client chains are added dynamically by addClientFunc
		// The chain policy (drop) will handle unmatched traffic after all rules are evaluated

		// IPv6 chains use drop policy to block all IPv6 traffic
		dropPolicy := nftables.ChainPolicyDrop
		inputChain6 := fctx.conn.AddChain(&nftables.Chain{
			Name:     defaultFRChainName + "_input_v6",
			Table:    fctx.filterTable6,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookInput,
			Priority: nftables.ChainPriorityFilter,
			Policy:   &dropPolicy,
		})

		forwardChain6 := fctx.conn.AddChain(&nftables.Chain{
			Name:     defaultFRChainName + "_forward_v6",
			Table:    fctx.filterTable6,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookForward,
			Priority: nftables.ChainPriorityFilter,
			Policy:   &dropPolicy,
		})

		outputChain6 := fctx.conn.AddChain(&nftables.Chain{
			Name:     defaultFRChainName + "_output_v6",
			Table:    fctx.filterTable6,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookOutput,
			Priority: nftables.ChainPriorityFilter,
			Policy:   &dropPolicy,
		})

		_ = inputChain6
		_ = forwardChain6
		_ = outputChain6

		if err := fctx.conn.Flush(); err != nil {
			log.Error("Failed to create filter chains: %v", err)
			return err
		}
	} else {
		// Remove any monitored chains
		log.Debug("Length of MonChains: %d", len(fctx.monitoredChains))
		if len(fctx.monitoredChains) > 0 {
			for chain := range fctx.monitoredChains {
				fctx.removeChainFromFilter(chain)
			}
		}

		// Delete main chains
		if fctx.inputChain != nil {
			fctx.conn.DelChain(fctx.inputChain)
		}
		if fctx.forwardChain != nil {
			fctx.conn.DelChain(fctx.forwardChain)
		}

		// Delete IPv6 table
		fctx.conn.DelTable(fctx.filterTable6)
		fctx.conn.DelTable(fctx.filterTable)

		if err := fctx.conn.Flush(); err != nil {
			log.Error("Failed to remove filter chains: %v", err)
			return err
		}
	}

	return nil
}

func (fctx *firewallContext) setNATTable(add bool) error {
	if add {
		// Create PREROUTING chain for NAT
		fctx.preroutingChain = fctx.conn.AddChain(&nftables.Chain{
			Name:     defaultFRChainName + "_prerouting",
			Table:    fctx.natTable,
			Type:     nftables.ChainTypeNAT,
			Hooknum:  nftables.ChainHookPrerouting,
			Priority: nftables.ChainPriorityNATDest,
		})

		// DNS TCP DNAT
		fctx.conn.AddRule(&nftables.Rule{
			Table: fctx.natTable,
			Chain: fctx.preroutingChain,
			Exprs: createDNATRule(defaultInterface, "tcp", fctx.homeAddress, fctx.homeAddress+":53", 53),
		})

		// DNS UDP DNAT
		fctx.conn.AddRule(&nftables.Rule{
			Table: fctx.natTable,
			Chain: fctx.preroutingChain,
			Exprs: createDNATRule(defaultInterface, "udp", fctx.homeAddress, fctx.homeAddress+":53", 53),
		})

		if err := fctx.conn.Flush(); err != nil {
			log.Error("Failed to create NAT chains: %v", err)
			return err
		}
	} else {
		// Delete NAT chain
		if fctx.preroutingChain != nil {
			fctx.conn.DelChain(fctx.preroutingChain)
		}
		fctx.conn.DelTable(fctx.natTable)

		if err := fctx.conn.Flush(); err != nil {
			log.Error("Failed to remove NAT chains: %v", err)
			return err
		}
	}

	return nil
}

func (fctx *firewallContext) start() error {
	if err := fctx.setFILTERTable(true); err != nil {
		return fmt.Errorf("could not start the DNS/Firewall server properly: %w", err)
	}

	if err := fctx.setNATTable(true); err != nil {
		return fmt.Errorf("could not start the DNS/Firewall server properly: %w", err)
	}

	fctx.enabled = true
	log.Info("Firewall Started.")

	return nil
}

func (fctx *firewallContext) close() error {
	if err := fctx.setFILTERTable(false); err != nil {
		return fmt.Errorf("could not stop the DNS/Firewall server properly: %w", err)
	}
	if err := fctx.setNATTable(false); err != nil {
		return fmt.Errorf("could not stop the DNS/Firewall server properly: %w", err)
	}

	fctx.enabled = false
	log.Info("Firewall Stopped.")

	return nil
}

func (fctx *firewallContext) openRoute(cn, ipSource, ipDest string) error {
	chainName := cn

	// Check if chain already exists
	chain, exists := fctx.monitoredChains[chainName]
	if !exists {
		// Create new chain for this client
		if err := fctx.addClientFunc(chainName, ipSource); err != nil {
			return err
		}
		chain = fctx.monitoredChains[chainName]
	}

	// Initialize the allowed IPs map for this chain if it doesn't exist
	if fctx.allowedIPs[chainName] == nil {
		fctx.allowedIPs[chainName] = make(map[string]bool)
	}

	// Check if this destination IP is already allowed for this client
	if fctx.allowedIPs[chainName][ipDest] {
		// Already allowed, skip adding duplicate rule
		return nil
	}

	// Add rule to allow traffic from ipSource to ipDest
	srcIP := net.ParseIP(ipSource)
	dstIP := net.ParseIP(ipDest)
	if srcIP == nil || dstIP == nil {
		return fmt.Errorf("invalid IP addresses: src=%s, dst=%s", ipSource, ipDest)
	}

	var exprs []expr.Any

	// Match input interface
	exprs = append(exprs, &expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1})
	exprs = append(exprs, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     []byte(defaultInterface + "\x00"),
	})

	// Match source IP
	exprs = append(exprs, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       12,
		Len:          4,
	})
	exprs = append(exprs, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     srcIP.To4(),
	})

	// Match destination IP
	exprs = append(exprs, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       16,
		Len:          4,
	})
	exprs = append(exprs, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     dstIP.To4(),
	})

	// Accept verdict
	exprs = append(exprs, &expr.Verdict{
		Kind: expr.VerdictAccept,
	})

	// Add rule at the beginning of the chain
	fctx.conn.InsertRule(&nftables.Rule{
		Table:    fctx.filterTable,
		Chain:    chain,
		Exprs:    exprs,
		Position: 0,
	})

	if err := fctx.conn.Flush(); err != nil {
		log.Error("Failed to add route rule: %v", err)
		return err
	}

	// Mark this IP as allowed for this client
	fctx.allowedIPs[chainName][ipDest] = true

	return nil
}

func contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

func (fctx *firewallContext) addClientFunc(chainName, ipAddress string) error {
	// Create a new chain for this client
	chain := fctx.conn.AddChain(&nftables.Chain{
		Name:  chainName,
		Table: fctx.filterTable,
	})

	// Add rule to accept established/related connections
	var exprs []expr.Any
	exprs = append(exprs, &expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1})
	exprs = append(exprs, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     []byte(defaultInterface + "\x00"),
	})

	ip := net.ParseIP(ipAddress)
	if ip != nil {
		exprs = append(exprs, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       16,
			Len:          4,
		})
		exprs = append(exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ip.To4(),
		})
	}

	exprs = append(exprs, createCTStateRule("ESTABLISHED,RELATED")...)
	exprs = append(exprs, &expr.Verdict{
		Kind: expr.VerdictAccept,
	})

	fctx.conn.AddRule(&nftables.Rule{
		Table: fctx.filterTable,
		Chain: chain,
		Exprs: exprs,
	})

	// Add DROP rule for traffic from this client
	fctx.conn.AddRule(&nftables.Rule{
		Table: fctx.filterTable,
		Chain: chain,
		Exprs: createDropRule(defaultInterface, ipAddress),
	})

	// Add jump rules from INPUT and FORWARD chains
	fctx.conn.AddRule(&nftables.Rule{
		Table: fctx.filterTable,
		Chain: fctx.inputChain,
		Exprs: []expr.Any{
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: chainName,
			},
		},
	})

	fctx.conn.AddRule(&nftables.Rule{
		Table: fctx.filterTable,
		Chain: fctx.forwardChain,
		Exprs: []expr.Any{
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: chainName,
			},
		},
	})

	if err := fctx.conn.Flush(); err != nil {
		log.Error("Failed to add client chain: %v", err)
		return err
	}

	fctx.monitoredChains[chainName] = chain
	return nil
}

func (fctx *firewallContext) removeClientFunc(chainName string) error {
	err := fctx.removeChainFromFilter(chainName)
	if err != nil {
		return err
	}

	delete(fctx.monitoredChains, chainName)
	delete(fctx.allowedIPs, chainName)
	return nil
}

func processIPTables(ctx context.Context, dctx *dnsContext) (rc resultCode) {
	if dctx.result != nil {
		if dctx.result.Reason != filtering.NotFilteredAllowList && dctx.result.Reason != filtering.NotFilteredNotFound && dctx.result.Reason != filtering.RewrittenRule {
			dctx.srv.logger.DebugContext(ctx, "NFTABLES - NO: Shall not add IPTables")
			return resultCodeSuccess
		}
	}
	var ipSource string
	var ipDestinations []string
	var clientName string
	if dctx.setts != nil {
		if dctx.setts.ClientName == "" {
			dctx.srv.logger.DebugContext(ctx, "NFTABLES - NO: Client has no name")
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
				log.Error("Process IP Tables Error: %v", respErr)
				return resultCodeError
			}
		}
	} else {
		log.Error("NO: Firewall not in Server context")
		return resultCodeError
	}

	return resultCodeSuccess
}
