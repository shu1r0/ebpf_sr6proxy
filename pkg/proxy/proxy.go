package proxy

type SRv6Proxy interface {
	Run() error
	AddRoute(route SRv6Route) error
	DeleteRoute(route SRv6Route) error
	Close() error
}
