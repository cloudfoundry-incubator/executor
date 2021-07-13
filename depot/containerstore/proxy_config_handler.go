package containerstore

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"code.cloudfoundry.org/clock"
	"code.cloudfoundry.org/executor"
	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/lager"
	envoy_bootstrap "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	envoy_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_metrics "github.com/envoyproxy/go-control-plane/envoy/config/metrics/v3"
	envoy_tcp_proxy "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	envoy_matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	ghodss_yaml "github.com/ghodss/yaml"
	"github.com/gogo/protobuf/proto"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/golang/protobuf/ptypes/duration"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/tedsuo/ifrit"
)

const (
	StartProxyPort = 61001
	EndProxyPort   = 65534

	TimeOut = 250000000

	IngressListener = "ingress_listener"
	TcpProxy        = "envoy.tcp_proxy"
	AdsClusterName  = "pilot-ads"

	AdminAccessLog = os.DevNull
)

var (
	ErrNoPortsAvailable   = errors.New("no ports available")
	ErrInvalidCertificate = errors.New("cannot parse invalid certificate")

	AlpnProtocols         = []string{"h2,http/1.1"}
	SupportedCipherSuites = []string{"ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256"}
)

var dummyRunner = func(credRotatedChan <-chan Credential) ifrit.Runner {
	return ifrit.RunFunc(func(signals <-chan os.Signal, ready chan<- struct{}) error {
		close(ready)
		for {
			select {
			case <-credRotatedChan:
			case <-signals:
				return nil
			}
		}
	})
}

type ProxyConfigHandler struct {
	logger                             lager.Logger
	containerProxyPath                 string
	containerProxyConfigPath           string
	containerProxyTrustedCACerts       []string
	containerProxyVerifySubjectAltName []string
	containerProxyRequireClientCerts   bool

	reloadDuration time.Duration
	reloadClock    clock.Clock

	adsServers []string
}

type NoopProxyConfigHandler struct{}

func (p *NoopProxyConfigHandler) CreateDir(logger lager.Logger, container executor.Container) ([]garden.BindMount, []executor.EnvironmentVariable, error) {
	return nil, nil, nil
}
func (p *NoopProxyConfigHandler) RemoveDir(logger lager.Logger, container executor.Container) error {
	return nil
}
func (p *NoopProxyConfigHandler) Update(credentials Credential, container executor.Container) error {
	return nil
}
func (p *NoopProxyConfigHandler) Close(invalidCredentials Credential, container executor.Container) error {
	return nil
}

func (p *NoopProxyConfigHandler) RemoveProxyConfigDir(logger lager.Logger, container executor.Container) error {
	return nil
}

func (p *NoopProxyConfigHandler) ProxyPorts(lager.Logger, *executor.Container) ([]executor.ProxyPortMapping, []uint16) {
	return nil, nil
}

func (p *NoopProxyConfigHandler) Runner(logger lager.Logger, container executor.Container, credRotatedChan <-chan Credential) (ifrit.Runner, error) {
	return dummyRunner(credRotatedChan), nil
}

func NewNoopProxyConfigHandler() *NoopProxyConfigHandler {
	return &NoopProxyConfigHandler{}
}

func NewProxyConfigHandler(
	logger lager.Logger,
	containerProxyPath string,
	containerProxyConfigPath string,
	ContainerProxyTrustedCACerts []string,
	ContainerProxyVerifySubjectAltName []string,
	containerProxyRequireClientCerts bool,
	reloadDuration time.Duration,
	reloadClock clock.Clock,
	adsServers []string,
) *ProxyConfigHandler {
	return &ProxyConfigHandler{
		logger:                             logger.Session("proxy-manager"),
		containerProxyPath:                 containerProxyPath,
		containerProxyConfigPath:           containerProxyConfigPath,
		containerProxyTrustedCACerts:       ContainerProxyTrustedCACerts,
		containerProxyVerifySubjectAltName: ContainerProxyVerifySubjectAltName,
		containerProxyRequireClientCerts:   containerProxyRequireClientCerts,
		reloadDuration:                     reloadDuration,
		reloadClock:                        reloadClock,
		adsServers:                         adsServers,
	}
}

// This modifies the container pointer in order to create garden NetIn rules in the storenode.Create
func (p *ProxyConfigHandler) ProxyPorts(logger lager.Logger, container *executor.Container) ([]executor.ProxyPortMapping, []uint16) {
	if !container.EnableContainerProxy {
		return nil, nil
	}

	proxyPortMapping := []executor.ProxyPortMapping{}

	existingPorts := make(map[uint16]interface{})
	containerPorts := make([]uint16, len(container.Ports))
	for i, portMap := range container.Ports {
		existingPorts[portMap.ContainerPort] = struct{}{}
		containerPorts[i] = portMap.ContainerPort
	}

	extraPorts := []uint16{}

	portCount := 0
	for port := uint16(StartProxyPort); port < EndProxyPort; port++ {
		if portCount == len(existingPorts) {
			break
		}

		if existingPorts[port] != nil {
			continue
		}

		extraPorts = append(extraPorts, port)
		proxyPortMapping = append(proxyPortMapping, executor.ProxyPortMapping{
			AppPort:   containerPorts[portCount],
			ProxyPort: port,
		})

		portCount++
	}

	return proxyPortMapping, extraPorts
}

func (p *ProxyConfigHandler) CreateDir(logger lager.Logger, container executor.Container) ([]garden.BindMount, []executor.EnvironmentVariable, error) {
	if !container.EnableContainerProxy {
		return nil, nil, nil
	}

	logger.Info("adding-container-proxy-bindmounts")
	proxyConfigDir := filepath.Join(p.containerProxyConfigPath, container.Guid)
	mounts := []garden.BindMount{
		{
			Origin:  garden.BindMountOriginHost,
			SrcPath: p.containerProxyPath,
			DstPath: "/etc/cf-assets/envoy",
		},
		{
			Origin:  garden.BindMountOriginHost,
			SrcPath: proxyConfigDir,
			DstPath: "/etc/cf-assets/envoy_config",
		},
	}

	err := os.MkdirAll(proxyConfigDir, 0755)
	if err != nil {
		return nil, nil, err
	}

	return mounts, nil, nil
}

func (p *ProxyConfigHandler) RemoveDir(logger lager.Logger, container executor.Container) error {
	if !container.EnableContainerProxy {
		return nil
	}

	logger.Info("removing-container-proxy-config-dir")
	proxyConfigDir := filepath.Join(p.containerProxyConfigPath, container.Guid)
	return os.RemoveAll(proxyConfigDir)
}

func (p *ProxyConfigHandler) Update(credentials Credential, container executor.Container) error {
	if !container.EnableContainerProxy {
		return nil
	}

	return p.writeConfig(credentials, container)
}

func (p *ProxyConfigHandler) Close(invalidCredentials Credential, container executor.Container) error {
	if !container.EnableContainerProxy {
		return nil
	}

	err := p.writeConfig(invalidCredentials, container)
	if err != nil {
		return err
	}

	p.reloadClock.Sleep(p.reloadDuration)
	return nil
}

func (p *ProxyConfigHandler) writeConfig(credentials Credential, container executor.Container) error {
	proxyConfigPath := filepath.Join(p.containerProxyConfigPath, container.Guid, "envoy.yaml")
	sdsServerCertAndKeyPath := filepath.Join(p.containerProxyConfigPath, container.Guid, "sds-server-cert-and-key.yaml")
	sdsServerValidationContextPath := filepath.Join(p.containerProxyConfigPath, container.Guid, "sds-server-validation-context.yaml")

	adminPort, err := getAvailablePort(container.Ports)
	if err != nil {
		return err
	}

	proxyConfig, err := generateProxyConfig(
		container,
		adminPort,
		p.containerProxyRequireClientCerts,
		p.adsServers,
	)
	if err != nil {
		return err
	}

	err = writeProxyConfig(proxyConfig, proxyConfigPath)
	if err != nil {
		return err
	}

	sdsServerCertAndKey := generateSDSCertAndKey(container, credentials)
	err = writeDiscoveryResponseYAML(sdsServerCertAndKey, sdsServerCertAndKeyPath)
	if err != nil {
		return err
	}

	sdsServerValidationContext, err := generateSDSCAResource(
		container,
		credentials,
		p.containerProxyTrustedCACerts,
		p.containerProxyVerifySubjectAltName,
	)
	if err != nil {
		return err
	}
	err = writeDiscoveryResponseYAML(sdsServerValidationContext, sdsServerValidationContextPath)
	if err != nil {
		return err
	}

	return nil
}

func envoyAddr(ip string, port uint16) *envoy_core.Address {
	return &envoy_core.Address{
		Address: &envoy_core.Address_SocketAddress{
			SocketAddress: &envoy_core.SocketAddress{
				Address: ip,
				PortSpecifier: &envoy_core.SocketAddress_PortValue{
					PortValue: uint32(port),
				},
			},
		},
	}
}

func generateProxyConfig(
	container executor.Container,
	adminPort uint16,
	requireClientCerts bool,
	adsServers []string,
) (*envoy_bootstrap.Bootstrap, error) {
	clusters := []*envoy_cluster.Cluster{}
	for index, portMap := range container.Ports {
		clusterName := fmt.Sprintf("%d-service-cluster", index)
		clusters = append(clusters, &envoy_cluster.Cluster{
			Name:                 clusterName,
			ClusterDiscoveryType: &envoy_cluster.Cluster_Type{Type: envoy_cluster.Cluster_STATIC},
			ConnectTimeout:       &duration.Duration{Nanos: TimeOut},
			LoadAssignment: &envoy_endpoint.ClusterLoadAssignment{
				ClusterName: clusterName,
				Endpoints: []*envoy_endpoint.LocalityLbEndpoints{{
					LbEndpoints: []*envoy_endpoint.LbEndpoint{{
						HostIdentifier: &envoy_endpoint.LbEndpoint_Endpoint{
							Endpoint: &envoy_endpoint.Endpoint{
								Address: envoyAddr(container.InternalIP, portMap.ContainerPort),
							},
						},
					}},
				}},
			},
			CircuitBreakers: &envoy_cluster.CircuitBreakers{
				Thresholds: []*envoy_cluster.CircuitBreakers_Thresholds{
					{MaxConnections: &wrappers.UInt32Value{Value: math.MaxUint32}},
				}},
		})
	}

	listeners, err := generateListeners(container, requireClientCerts)
	if err != nil {
		return nil, fmt.Errorf("generating listeners: %s", err)
	}

	config := &envoy_bootstrap.Bootstrap{
		Admin: &envoy_bootstrap.Admin{
			AccessLogPath: AdminAccessLog,
			Address:       envoyAddr("127.0.0.1", adminPort),
		},
		StatsConfig: &envoy_metrics.StatsConfig{
			StatsMatcher: &envoy_metrics.StatsMatcher{
				StatsMatcher: &envoy_metrics.StatsMatcher_RejectAll{
					RejectAll: true,
				},
			},
		},
		Node: &envoy_core.Node{
			Id:      fmt.Sprintf("sidecar~%s~%s~x", container.InternalIP, container.Guid),
			Cluster: "proxy-cluster",
		},
		StaticResources: &envoy_bootstrap.Bootstrap_StaticResources{
			Listeners: listeners,
		},
	}

	if len(adsServers) > 0 {
		var adsEndpoints []*envoy_endpoint.LbEndpoint
		for _, a := range adsServers {
			address, port, err := splitHost(a)
			if err != nil {
				return nil, err
			}
			adsEndpoints = append(adsEndpoints, &envoy_endpoint.LbEndpoint{
				HostIdentifier: &envoy_endpoint.LbEndpoint_Endpoint{
					Endpoint: &envoy_endpoint.Endpoint{
						Address: envoyAddr(address, port),
					},
				},
			})
		}

		clusters = append(clusters, &envoy_cluster.Cluster{
			Name:                 AdsClusterName,
			ClusterDiscoveryType: &envoy_cluster.Cluster_Type{Type: envoy_cluster.Cluster_STATIC},
			ConnectTimeout:       &duration.Duration{Nanos: TimeOut},
			LoadAssignment: &envoy_endpoint.ClusterLoadAssignment{
				ClusterName: AdsClusterName,
				Endpoints: []*envoy_endpoint.LocalityLbEndpoints{{
					LbEndpoints: adsEndpoints,
				}},
			},
			Http2ProtocolOptions: &envoy_core.Http2ProtocolOptions{},
		})

		dynamicResources := &envoy_bootstrap.Bootstrap_DynamicResources{
			LdsConfig: adsConfigSource,
			CdsConfig: adsConfigSource,
			AdsConfig: &envoy_core.ApiConfigSource{
				ApiType: envoy_core.ApiConfigSource_GRPC,
				GrpcServices: []*envoy_core.GrpcService{
					{
						TargetSpecifier: &envoy_core.GrpcService_EnvoyGrpc_{
							EnvoyGrpc: &envoy_core.GrpcService_EnvoyGrpc{
								ClusterName: "pilot-ads",
							},
						},
					},
				},
			},
		}
		config.DynamicResources = dynamicResources
	}

	config.StaticResources.Clusters = clusters

	return config, nil
}

var adsConfigSource = &envoy_core.ConfigSource{
	ConfigSourceSpecifier: &envoy_core.ConfigSource_Ads{
		Ads: &envoy_core.AggregatedConfigSource{},
	},
}

func splitHost(host string) (string, uint16, error) {
	parts := strings.Split(host, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("ads server address is invalid: %s", host)
	}

	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("ads server address is invalid: %s", host)
	}
	return parts[0], uint16(port), nil
}

func writeProxyConfig(proxyConfig *envoy_bootstrap.Bootstrap, path string) error {
	jsonMarshaler := jsonpb.Marshaler{OrigName: true, EmitDefaults: false}
	jsonStr, err := jsonMarshaler.MarshalToString(proxyConfig)
	if err != nil {
		return err
	}
	yamlStr, err := ghodss_yaml.JSONToYAML([]byte(jsonStr))
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, yamlStr, 0666)
}

func generateListeners(container executor.Container, requireClientCerts bool) ([]*envoy_listener.Listener, error) {
	listeners := []*envoy_listener.Listener{}

	for index, portMap := range container.Ports {
		filterName := TcpProxy
		clusterName := fmt.Sprintf("%d-service-cluster", index)

		filterConfig, err := ptypes.MarshalAny(&envoy_tcp_proxy.TcpProxy{
			StatPrefix: fmt.Sprintf("%d-stats", index),
			ClusterSpecifier: &envoy_tcp_proxy.TcpProxy_Cluster{
				Cluster: clusterName,
			},
		})
		if err != nil {
			return nil, err
		}

		tlsContext := &envoy_tls.DownstreamTlsContext{
			RequireClientCertificate: &wrappers.BoolValue{Value: requireClientCerts},
			CommonTlsContext: &envoy_tls.CommonTlsContext{
				AlpnProtocols: AlpnProtocols,
				TlsCertificateSdsSecretConfigs: []*envoy_tls.SdsSecretConfig{
					{
						Name: "server-cert-and-key",
						SdsConfig: &envoy_core.ConfigSource{
							ConfigSourceSpecifier: &envoy_core.ConfigSource_Path{
								Path: "/etc/cf-assets/envoy_config/sds-server-cert-and-key.yaml",
							},
						},
					},
				},
				TlsParams: &envoy_tls.TlsParameters{
					CipherSuites: SupportedCipherSuites,
				},
			},
		}

		if requireClientCerts {
			tlsContext.CommonTlsContext.ValidationContextType = &envoy_tls.CommonTlsContext_ValidationContextSdsSecretConfig{
				ValidationContextSdsSecretConfig: &envoy_tls.SdsSecretConfig{
					Name: "server-validation-context",
					SdsConfig: &envoy_core.ConfigSource{
						ConfigSourceSpecifier: &envoy_core.ConfigSource_Path{
							Path: "/etc/cf-assets/envoy_config/sds-server-validation-context.yaml",
						},
					},
				},
			}
		}

		tlsContextAny, err := ptypes.MarshalAny(tlsContext)
		if err != nil {
			return nil, err
		}

		listenerName := fmt.Sprintf("listener-%d", portMap.ContainerPort)
		listener := &envoy_listener.Listener{
			Name:    listenerName,
			Address: envoyAddr("0.0.0.0", portMap.ContainerTLSProxyPort),
			FilterChains: []*envoy_listener.FilterChain{{
				Filters: []*envoy_listener.Filter{
					{
						Name: filterName,
						ConfigType: &envoy_listener.Filter_TypedConfig{
							TypedConfig: filterConfig,
						},
					},
				},
				TransportSocket: &envoy_core.TransportSocket{
					Name: listenerName,
					ConfigType: &envoy_core.TransportSocket_TypedConfig{
						TypedConfig: tlsContextAny,
					},
				},
			},
			},
		}

		listeners = append(listeners, listener)
	}

	return listeners, nil
}

func generateSDSCertAndKey(container executor.Container, creds Credential) proto.Message {
	return &envoy_tls.Secret{
		Name: "server-cert-and-key",
		Type: &envoy_tls.Secret_TlsCertificate{
			TlsCertificate: &envoy_tls.TlsCertificate{
				CertificateChain: &envoy_core.DataSource{
					Specifier: &envoy_core.DataSource_InlineString{
						InlineString: creds.Cert,
					},
				},
				PrivateKey: &envoy_core.DataSource{
					Specifier: &envoy_core.DataSource_InlineString{
						InlineString: creds.Key,
					},
				},
			},
		},
	}
}

func generateSDSCAResource(container executor.Container, creds Credential, trustedCaCerts []string, subjectAltNames []string) (proto.Message, error) {
	certs, err := pemConcatenate(trustedCaCerts)
	if err != nil {
		return nil, err
	}

	var matchers []*envoy_matcher.StringMatcher
	for _, s := range subjectAltNames {
		matchers = append(matchers, &envoy_matcher.StringMatcher{
			MatchPattern: &envoy_matcher.StringMatcher_Exact{Exact: s},
		})
	}

	return &envoy_tls.Secret{
		Name: "server-validation-context",
		Type: &envoy_tls.Secret_ValidationContext{
			ValidationContext: &envoy_tls.CertificateValidationContext{
				TrustedCa: &envoy_core.DataSource{
					Specifier: &envoy_core.DataSource_InlineString{
						InlineString: certs,
					},
				},
				MatchSubjectAltNames: matchers,
			},
		},
	}, nil
}

func writeDiscoveryResponseYAML(resourceMsg proto.Message, outPath string) error {
	resourceAny, err := ptypes.MarshalAny(resourceMsg)
	if err != nil {
		return err
	}
	dr := &envoy_discovery.DiscoveryResponse{
		VersionInfo: "0",
		Resources: []*any.Any{
			resourceAny,
		},
	}
	jsonMarshaler := jsonpb.Marshaler{OrigName: true, EmitDefaults: false}
	fullJSON, err := jsonMarshaler.MarshalToString(dr)
	if err != nil {
		return err
	}

	yamlStr, err := ghodss_yaml.JSONToYAML([]byte(fullJSON))
	if err != nil {
		return err
	}

	tmpPath := outPath + ".tmp"
	if err := ioutil.WriteFile(tmpPath, yamlStr, 0666); err != nil {
		return err
	}

	return os.Rename(tmpPath, outPath)
}

func pemConcatenate(certs []string) (string, error) {
	var certificateBuf bytes.Buffer
	for _, cert := range certs {
		rest := []byte(cert)
		totalCertLen := len(rest)
		var block *pem.Block
		for {
			block, rest = pem.Decode(rest)
			if block == nil {
				if len(rest) == totalCertLen {
					return "", errors.New("failed to read certificate")
				}
				break
			}
			err := pem.Encode(&certificateBuf, block)
			if err != nil {
				return "", err
			}
		}
	}
	return certificateBuf.String(), nil
}

func getAvailablePort(allocatedPorts []executor.PortMapping, extraKnownPorts ...uint16) (uint16, error) {
	existingPorts := make(map[uint16]interface{})
	for _, portMap := range allocatedPorts {
		existingPorts[portMap.ContainerPort] = struct{}{}
		existingPorts[portMap.ContainerTLSProxyPort] = struct{}{}
	}

	for _, extraKnownPort := range extraKnownPorts {
		existingPorts[extraKnownPort] = struct{}{}
	}

	for port := uint16(StartProxyPort); port < EndProxyPort; port++ {
		if existingPorts[port] != nil {
			continue
		}
		return port, nil
	}
	return 0, ErrNoPortsAvailable
}
