package nftctrl

import (
	"git.dolansoft.org/dolansoft/k8s-nft-npc/nfds"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	newRegOffset = 8
)

type direction uint8

const (
	dirIngress direction = iota
	dirEgress
)

// loadIP loads the IP address in the relevant direction (source for ingress,
// destination for egress) for a packet into the given register (new register
// numbers).
func loadIP(dir direction, dstReg uint32) *expr.Dynamic {
	return &expr.Dynamic{
		Expr: func(fam uint8) expr.Any {
			var addressOffset uint32
			var addressSize uint32
			if fam == unix.NFPROTO_IPV4 {
				addressOffset = 12
				addressSize = 4
			} else {
				addressOffset = 8
				addressSize = 16
			}
			if dir == dirEgress {
				// If egress, load destination address, not source
				addressOffset += addressSize
			}

			return &expr.Payload{
				Base:         expr.PayloadBaseNetworkHeader,
				DestRegister: newRegOffset + dstReg,
				Offset:       addressOffset,
				Len:          addressSize,
			}
		},
	}
}

func rejectAdministrative() *expr.Dynamic {
	return &expr.Dynamic{
		Expr: func(fam uint8) expr.Any {
			if fam == unix.NFPROTO_IPV4 {
				return &expr.Reject{
					Type: unix.NFT_REJECT_ICMP_UNREACH, // Destination unreachable
					Code: 13,                           // Communication administratively prohibited
				}
			} else {
				return &expr.Reject{
					Type: unix.NFT_REJECT_ICMP_UNREACH, // Destination unreachable
					Code: 1,                            // Communication administratively prohibited
				}
			}
		},
	}
}

func loadDstPort(dstReg uint32) *expr.Payload {
	return &expr.Payload{
		Base:         expr.PayloadBaseTransportHeader,
		DestRegister: newRegOffset + dstReg,
		Offset:       2,
		Len:          2,
	}
}

type Lookup struct {
	SourceRegister uint32
	DestRegister   uint32
	IsDestRegSet   bool
	Invert         bool
	Set            *nfds.Set
}

func lookup(l Lookup) *expr.Dynamic {
	return &expr.Dynamic{
		Expr: func(fam uint8) expr.Any {
			setId, setName := l.Set.Reference(fam)
			return &expr.Lookup{
				SourceRegister: l.SourceRegister,
				DestRegister:   l.DestRegister,
				IsDestRegSet:   l.IsDestRegSet,
				Invert:         l.Invert,
				SetID:          setId,
				SetName:        setName,
			}
		},
	}
}
