package config

import (
	"encoding/json"
)

type WireGuardServer struct {
	Enable     bool                  `yaml:"enable" json:"enable"`
	Listen     string                `yaml:"listen" json:"listen"`
	PrivateKey string                `yaml:"private-key" json:"private-key"`
	IP         string                `yaml:"ip" json:"ip,omitempty"`
	IPv6       string                `yaml:"ipv6" json:"ipv6,omitempty"`
	MTU        int                   `yaml:"mtu" json:"mtu,omitempty"`
	Workers    int                   `yaml:"workers" json:"workers,omitempty"`
	Peers      []WireGuardServerPeer `yaml:"peers" json:"peers,omitempty"`
}

type WireGuardServerPeer struct {
	PublicKey    string   `yaml:"public-key" json:"public-key"`
	PreSharedKey string   `yaml:"pre-shared-key" json:"pre-shared-key,omitempty"`
	AllowedIPs   []string `yaml:"allowed-ips" json:"allowed-ips,omitempty"`
}

func (t WireGuardServer) String() string {
	b, _ := json.Marshal(t)
	return string(b)
}
