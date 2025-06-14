package internal

import (
	"log"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

type Rule struct {
	Action   string `yaml:"action"`
	Protocol string `yaml:"protocol"`
	Port     uint16 `yaml:"port"`
	Source   string `yaml:"source"`
}

type Firewall struct {
	conn  *nftables.Conn
	table *nftables.Table
	chain *nftables.Chain
}

func NewFirewall() *Firewall {
	conn := &nftables.Conn{}
	table := conn.AddTable(&nftables.Table{
		Name:   "filter",
		Family: nftables.TableFamilyINet,
	})
	chain := conn.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})

	conn.Flush()

	return &Firewall{conn: conn, table: table, chain: chain}
}

func (fw *Firewall) ApplyRules(rules []Rule) error {
	for _, rule := range rules {
		ipNet, _, err := net.ParseCIDR(rule.Source)
		if err != nil {
			log.Printf("CIDR invalide : %s", rule.Source)
			continue
		}

		proto := uint8(6) // TCP
		if rule.Protocol == "udp" {
			proto = 17
		}

		exprs := []expr.Any{
			// Match du protocole
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       9, // Champ Protocole
				Len:          1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{proto},
			},
			// Match de l'IP source
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12, // IP source
				Len:          4,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ipNet.IP.To4(),
			},
		}

		if rule.Action == "allow" {
			fw.conn.AddRule(&nftables.Rule{
				Table: fw.table,
				Chain: fw.chain,
				Exprs: exprs,
			})
		} else if rule.Action == "drop" {
			fw.conn.AddRule(&nftables.Rule{
				Table: fw.table,
				Chain: fw.chain,
				Exprs: append(exprs, &expr.Verdict{
					Kind: expr.VerdictDrop,
				}),
			})
		}
	}

	return fw.conn.Flush()
}
