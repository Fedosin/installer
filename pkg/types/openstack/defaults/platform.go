package defaults

import (
	"net"
	"os"

	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	"github.com/gophercloud/utils/openstack/clientconfig"

	"github.com/openshift/installer/pkg/ipnet"
	"github.com/openshift/installer/pkg/types"
	"github.com/openshift/installer/pkg/types/openstack"
)

const (
	// DefaultCloudName is the default name of the cloud in clouds.yaml file.
	DefaultCloudName = "openstack"
)

// SetPlatformDefaults sets the defaults for the platform.
func SetPlatformDefaults(p *openstack.Platform, n *types.Networking) {
	if p.Cloud == "" {
		p.Cloud = os.Getenv("OS_CLOUD")
		if p.Cloud == "" {
			p.Cloud = DefaultCloudName
		}
	}

	if len(n.MachineNetwork) == 0 && p.MachinesSubnet != "" {
		cidr, err := getSubnetCIDR(p.Cloud, p.MachinesSubnet)
		if err != nil {
			// We cannot return errors from this function, so we just keep
			// MachinesSubnet empty and allow the validator to catch the error
			// later.
			return
		}

		parsedCIDR, err := ipnet.ParseCIDR(cidr)
		if err != nil {
			return
		}

		n.MachineNetwork = []types.MachineNetworkEntry{
			{CIDR: *parsedCIDR},
		}
	}

	// APIVIP returns the internal virtual IP address (VIP) put in front
	// of the Kubernetes API server for use by components inside the
	// cluster. The DNS static pods running on the nodes resolve the
	// api-int record to APIVIP.
	if p.APIVIP == "" {
		vip, _ := cidr.Host(&n.MachineNetwork[0].CIDR.IPNet, 5)
		p.APIVIP = vip.String()
	}

	// IngressVIP returns the internal virtual IP address (VIP) put in
	// front of the OpenShift router pods. This provides the internal
	// accessibility to the internal pods running on the worker nodes,
	// e.g. `console`. The DNS static pods running on the nodes resolve
	// the wildcard apps record to IngressVIP.
	if p.IngressVIP == "" {
		vip, _ := cidr.Host(&n.MachineNetwork[0].CIDR.IPNet, 7)
		p.IngressVIP = vip.String()
	}
}

// DNSVIP returns the internal virtual IP address (VIP) put in front
// of the DNS static pods running on the nodes. Unlike the DNS
// operator these services provide name resolution for the nodes
// themselves.
func DNSVIP(networking *types.Networking) (net.IP, error) {
	return cidr.Host(&networking.MachineNetwork[0].CIDR.IPNet, 6)
}

func getSubnetCIDR(cloud string, subnetID string) (string, error) {
	opts := &clientconfig.ClientOpts{
		Cloud: cloud,
	}

	networkClient, err := clientconfig.NewServiceClient("network", opts)
	if err != nil {
		return "", err
	}

	subnet, err := subnets.Get(networkClient, subnetID).Extract()
	if err != nil {
		return "", err
	}

	return subnet.CIDR, nil
}
