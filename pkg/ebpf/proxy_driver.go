package ebpf

import (
	"fmt"
	_ "unsafe"

	log "github.com/sirupsen/logrus"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go proxy ../../bpf/srv6_proxy.c -- -I../../bpf/ -I/usr/include/

type ProxyDriver struct {
	proxyObjects
	XdpIfaces []string
	InIfaces  []string
	InFilters []*netlink.BpfFilter
	InQdiscs  []*netlink.GenericQdisc
	EIfaces   []string
	EFilters  []*netlink.BpfFilter
	EQdiscs   []*netlink.GenericQdisc
}

func NewProxyDriver(options *ebpf.CollectionOptions) (*ProxyDriver, error) {
	driver := &ProxyDriver{}

	spec, err := loadProxy()
	if err != nil {
		return nil, err
	}

	if err := spec.LoadAndAssign(driver, options); err != nil {
		return nil, err
	}
	return driver, nil
}

func (driver *ProxyDriver) AttachAll(tcInFd int, tcEnFd int, xdpFd int) error {
	links, err := netlink.LinkList()
	if err != nil {
		return err
	}
	for _, l := range links {
		iface := l.Attrs().Name
		if tcInFd > 0 {
			if err := driver.AttachTcIngress(iface, tcInFd); err != nil {
				return err
			}
		}
		if tcEnFd > 0 {
			if err := driver.AttachTcEgress(iface, tcEnFd); err != nil {
				return err
			}
		}
		if xdpFd > 0 {
			if err := driver.AttachXdp(iface, tcEnFd); err != nil {
				return err
			}
		}
	}

	return nil
}

func (driver *ProxyDriver) DettachAll() {
	if err := driver.DettachXdp(); err != nil {
		log.Fatal(err)
	}
	if err := driver.DettachTcIngresses(); err != nil {
		log.Fatal(err)
	}
	if err := driver.DettachTcEgresses(); err != nil {
		log.Fatal(err)
	}
}

func (driver *ProxyDriver) AttachXdp(iface string, fd int) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("Attach XDP Error: %s", err)
	}

	if err := netlink.LinkSetXdpFd(link, fd); err != nil {
		return err
	}

	driver.XdpIfaces = append(driver.XdpIfaces, iface)

	return nil
}

func (driver *ProxyDriver) DettachXdp() error {
	for _, iface := range driver.XdpIfaces {
		link, err := netlink.LinkByName(iface)
		if err != nil {
			return fmt.Errorf("Look up Link Error: %s", err)
		}

		if err := netlink.LinkSetXdpFd(link, -1); err != nil {
			return fmt.Errorf("Dettach XDP Error: %s", err)
		}
	}

	return nil
}

func (driver *ProxyDriver) AttachTcIngress(iface string, fd int) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}

	// Qdic
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdic := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}
	if err := netlink.QdiscAdd(qdic); err != nil {
		return fmt.Errorf("Attach Ingress Qdisc Add Error: %s", err)
	}
	driver.InQdiscs = append(driver.InQdiscs, qdic)

	// filter
	filterAttrs := netlink.FilterAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}
	filter := &netlink.BpfFilter{
		FilterAttrs:  filterAttrs,
		Fd:           fd,
		Name:         "ingress",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("Attach Ingress Filter Add Error: %s", err)
	}

	driver.InIfaces = append(driver.InIfaces, iface)
	driver.InFilters = append(driver.InFilters, filter)

	return nil
}

func (driver *ProxyDriver) AttachTcEgress(iface string, fd int) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}

	// Qdic
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdic := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}
	if err := netlink.QdiscAdd(qdic); err != nil {
		return fmt.Errorf("Attach Egress Qdisc Add Error: %s", err)
	}
	driver.EQdiscs = append(driver.EQdiscs, qdic)

	// filter
	filterAttrs := netlink.FilterAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}
	filter := &netlink.BpfFilter{
		FilterAttrs:  filterAttrs,
		Fd:           fd,
		Name:         "egress",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("Attach Egress Filter Add Error: %s", err)
	}

	driver.EIfaces = append(driver.EIfaces, iface)
	driver.EFilters = append(driver.EFilters, filter)

	return nil
}

func (driver *ProxyDriver) DettachTcIngresses() error {
	for _, f := range driver.InFilters {
		if err := netlink.FilterDel(f); err != nil {
			return fmt.Errorf("Dettach Ingress Error: %s", err)
		}
	}
	for _, q := range driver.InQdiscs {
		if err := netlink.QdiscDel(q); err != nil {
			return fmt.Errorf("Dettach Ingress Qdisc Error: %s", err)
		}
	}
	return nil
}

func (driver *ProxyDriver) DettachTcEgresses() error {
	for _, f := range driver.EFilters {
		if err := netlink.FilterDel(f); err != nil {
			return fmt.Errorf("Dettach Egress Error: %s", err)
		}
	}
	for _, q := range driver.EQdiscs {
		if err := netlink.QdiscDel(q); err != nil {
			return fmt.Errorf("Dettach Egress Qdisc Error: %s", err)
		}
	}
	return nil
}

func (driver *ProxyDriver) SetSID() error {
	// pass
	return nil
}

func (driver *ProxyDriver) SetConfig() error {
	// pass
	return nil
}

func (driver *ProxyDriver) SetMapConf(nid uint32) error {
	//if err := driver.ConfigMap.Put(uint32(0), uint32(1)); err != nil {
	//	return fmt.Errorf("Config Map Error: %s", err)
	//}
	//if err := driver.ConfigMap.Put(uint32(1), nid); err != nil {
	//	return fmt.Errorf("Set Nodeid Error: %s", err)
	//}
	//if err := driver.CounterMap.Put(uint32(0), uint32(1)); err != nil {
	//	return fmt.Errorf("Counter Map Error: %s", err)
	//}
	return nil
}
