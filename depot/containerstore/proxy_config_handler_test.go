package containerstore_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"code.cloudfoundry.org/clock/fakeclock"
	"code.cloudfoundry.org/executor"
	"code.cloudfoundry.org/executor/depot/containerstore"
	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/lager/lagertest"
	envoy_bootstrap "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	envoy_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_tcp_proxy "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	envoy_matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/fsnotify/fsnotify"
	ghodss_yaml "github.com/ghodss/yaml"
	"github.com/gogo/protobuf/proto"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/duration"
	uuid "github.com/nu7hatch/gouuid"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	yaml "gopkg.in/yaml.v2"
)

var _ = Describe("ProxyConfigHandler", func() {

	var (
		logger                             *lagertest.TestLogger
		proxyConfigDir                     string
		proxyDir                           string
		configPath                         string
		rotatingCredChan                   chan containerstore.Credential
		container                          executor.Container
		sdsServerCertAndKeyFile            string
		sdsServerValidationContextFile     string
		proxyConfigFile                    string
		proxyConfigHandler                 *containerstore.ProxyConfigHandler
		reloadDuration                     time.Duration
		reloadClock                        *fakeclock.FakeClock
		containerProxyTrustedCACerts       []string
		containerProxyVerifySubjectAltName []string
		containerProxyRequireClientCerts   bool
		adsServers                         []string
	)

	BeforeEach(func() {
		var err error

		SetDefaultEventuallyTimeout(10 * time.Second)

		container = executor.Container{
			Guid:       fmt.Sprintf("container-guid-%d", GinkgoParallelNode()),
			InternalIP: "10.0.0.1",
			RunInfo: executor.RunInfo{
				EnableContainerProxy: true,
			},
		}

		proxyConfigDir, err = ioutil.TempDir("", "proxymanager-config")
		Expect(err).ToNot(HaveOccurred())

		proxyDir, err = ioutil.TempDir("", "proxymanager-envoy")
		Expect(err).ToNot(HaveOccurred())

		configPath = filepath.Join(proxyConfigDir, container.Guid)

		proxyConfigFile = filepath.Join(configPath, "envoy.yaml")
		sdsServerCertAndKeyFile = filepath.Join(configPath, "sds-server-cert-and-key.yaml")
		sdsServerValidationContextFile = filepath.Join(configPath, "sds-server-validation-context.yaml")

		logger = lagertest.NewTestLogger("proxymanager")

		rotatingCredChan = make(chan containerstore.Credential, 1)
		reloadDuration = 1 * time.Second
		reloadClock = fakeclock.NewFakeClock(time.Now())

		containerProxyTrustedCACerts = []string{}
		containerProxyVerifySubjectAltName = []string{}
		containerProxyRequireClientCerts = false

		adsServers = []string{
			"10.255.217.2:15010",
			"10.255.217.3:15010",
		}
	})

	JustBeforeEach(func() {
		proxyConfigHandler = containerstore.NewProxyConfigHandler(
			logger,
			proxyDir,
			proxyConfigDir,
			containerProxyTrustedCACerts,
			containerProxyVerifySubjectAltName,
			containerProxyRequireClientCerts,
			reloadDuration,
			reloadClock,
			adsServers,
		)
		Eventually(rotatingCredChan).Should(BeSent(containerstore.Credential{
			Cert: "some-cert",
			Key:  "some-key",
		}))
	})

	AfterEach(func() {
		os.RemoveAll(proxyConfigDir)
		os.RemoveAll(proxyDir)
	})

	Describe("NoopProxyConfigHandler", func() {
		var (
			proxyConfigHandler *containerstore.NoopProxyConfigHandler
		)

		JustBeforeEach(func() {
			proxyConfigHandler = containerstore.NewNoopProxyConfigHandler()
		})

		Describe("CreateDir", func() {
			It("returns an empty bind mount", func() {
				mounts, _, err := proxyConfigHandler.CreateDir(logger, container)
				Expect(err).NotTo(HaveOccurred())
				Expect(mounts).To(BeEmpty())
			})

			It("returns an empty environment variables", func() {
				_, env, err := proxyConfigHandler.CreateDir(logger, container)
				Expect(err).NotTo(HaveOccurred())
				Expect(env).To(BeEmpty())
			})
		})

		Describe("Close", func() {
			JustBeforeEach(func() {
				Expect(proxyConfigFile).NotTo(BeAnExistingFile())
				err := proxyConfigHandler.Update(containerstore.Credential{Cert: "cert", Key: "key"}, container)
				Expect(err).NotTo(HaveOccurred())
			})

			It("does nothing", func() {
				Expect(proxyConfigFile).NotTo(BeAnExistingFile())
			})
		})

		Describe("Update", func() {
			JustBeforeEach(func() {
				Expect(proxyConfigFile).NotTo(BeAnExistingFile())
				err := proxyConfigHandler.Update(containerstore.Credential{Cert: "cert", Key: "key"}, container)
				Expect(err).NotTo(HaveOccurred())
			})

			It("does nothing", func() {
				Expect(proxyConfigFile).NotTo(BeAnExistingFile())
			})
		})

		It("returns an empty proxy port mapping", func() {
			ports, extraPorts := proxyConfigHandler.ProxyPorts(logger, &container)
			Expect(ports).To(BeEmpty())
			Expect(extraPorts).To(BeEmpty())
		})
	})

	Describe("CreateDir", func() {
		Context("the EnableContainerProxy is disabled on the container", func() {
			BeforeEach(func() {
				container.EnableContainerProxy = false
			})

			It("returns an empty bind mount", func() {
				mounts, _, err := proxyConfigHandler.CreateDir(logger, container)
				Expect(err).NotTo(HaveOccurred())
				Expect(mounts).To(BeEmpty())
			})
		})

		It("returns the appropriate bind mounts for container proxy", func() {
			mounts, _, err := proxyConfigHandler.CreateDir(logger, container)
			Expect(err).NotTo(HaveOccurred())
			Expect(mounts).To(ConsistOf([]garden.BindMount{
				{
					Origin:  garden.BindMountOriginHost,
					SrcPath: proxyDir,
					DstPath: "/etc/cf-assets/envoy",
				},
				{
					Origin:  garden.BindMountOriginHost,
					SrcPath: filepath.Join(proxyConfigDir, container.Guid),
					DstPath: "/etc/cf-assets/envoy_config",
				},
			}))
		})

		It("makes the proxy config directory on the host", func() {
			_, _, err := proxyConfigHandler.CreateDir(logger, container)
			Expect(err).NotTo(HaveOccurred())
			proxyConfigDir := fmt.Sprintf("%s/%s", proxyConfigDir, container.Guid)
			Expect(proxyConfigDir).To(BeADirectory())
		})

		Context("when the manager fails to create the proxy config directory", func() {
			BeforeEach(func() {
				_, err := os.Create(configPath)
				Expect(err).NotTo(HaveOccurred())
			})

			It("returns an error", func() {
				_, _, err := proxyConfigHandler.CreateDir(logger, container)
				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("RemoveDir", func() {
		It("removes the directory created by CreateDir", func() {
			_, _, err := proxyConfigHandler.CreateDir(logger, container)
			Expect(err).NotTo(HaveOccurred())
			Expect(configPath).To(BeADirectory())

			err = proxyConfigHandler.RemoveDir(logger, container)
			Expect(err).NotTo(HaveOccurred())
			Expect(configPath).NotTo(BeADirectory())
		})

		Context("the EnableContainerProxy is disabled on the container", func() {
			BeforeEach(func() {
				container.EnableContainerProxy = false
			})

			It("does not return an error when deleting a non existing directory", func() {
				err := proxyConfigHandler.RemoveDir(logger, container)
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

	Describe("ProxyPorts", func() {
		BeforeEach(func() {
			container.Ports = []executor.PortMapping{
				{
					ContainerPort: 8080,
				},
				{
					ContainerPort: 9090,
				},
			}
		})

		Context("the EnableContainerProxy is disabled on the container", func() {
			BeforeEach(func() {
				container.EnableContainerProxy = false
			})

			It("returns an empty proxy port mapping", func() {
				ports, extraPorts := proxyConfigHandler.ProxyPorts(logger, &container)
				Expect(ports).To(BeEmpty())
				Expect(extraPorts).To(BeEmpty())
			})
		})

		It("each port gets an equivalent extra proxy port", func() {
			ports, extraPorts := proxyConfigHandler.ProxyPorts(logger, &container)
			Expect(ports).To(ConsistOf([]executor.ProxyPortMapping{
				{
					AppPort:   8080,
					ProxyPort: 61001,
				},
				{
					AppPort:   9090,
					ProxyPort: 61002,
				},
			}))

			Expect(extraPorts).To(ConsistOf([]uint16{61001, 61002}))
		})

		Context("when the requested ports are in the 6100n range", func() {
			BeforeEach(func() {

				container.Ports = []executor.PortMapping{
					{ContainerPort: 61001},
					{ContainerPort: 9090},
				}
			})

			It("the additional proxy ports don't collide with requested ports", func() {
				ports, extraPorts := proxyConfigHandler.ProxyPorts(logger, &container)
				Expect(ports).To(ConsistOf([]executor.ProxyPortMapping{
					{
						AppPort:   61001,
						ProxyPort: 61002,
					},
					{
						AppPort:   9090,
						ProxyPort: 61003,
					},
				}))

				Expect(extraPorts).To(ConsistOf([]uint16{61002, 61003}))
			})
		})
	})

	Describe("Update", func() {
		BeforeEach(func() {
			err := os.MkdirAll(configPath, 0755)
			Expect(err).ToNot(HaveOccurred())

			container.Ports = []executor.PortMapping{
				{
					ContainerPort:         8080,
					ContainerTLSProxyPort: 61001,
				},
			}

			containerProxyRequireClientCerts = true
		})

		Context("the EnableContainerProxy is disabled on the container", func() {
			BeforeEach(func() {
				container.EnableContainerProxy = false
			})

			It("does not write a envoy config file", func() {
				err := proxyConfigHandler.Update(containerstore.Credential{Cert: "", Key: ""}, container)
				Expect(err).NotTo(HaveOccurred())

				Expect(proxyConfigFile).NotTo(BeAnExistingFile())
			})
		})

		Context("with containerProxyRequireClientCerts set to false", func() {
			BeforeEach(func() {
				containerProxyRequireClientCerts = false
			})

			It("creates a proxy config without tls_context", func() {
				err := proxyConfigHandler.Update(containerstore.Credential{Cert: "cert", Key: "key"}, container)
				Expect(err).NotTo(HaveOccurred())

				Eventually(proxyConfigFile).Should(BeAnExistingFile())

				var proxyConfig envoy_bootstrap.Bootstrap
				Expect(yamlFileToProto(proxyConfigFile, &proxyConfig)).To(Succeed())

				admin := proxyConfig.Admin
				Expect(admin.AccessLogPath).To(Equal(os.DevNull))
				Expect(admin.Address).To(Equal(envoyAddr("127.0.0.1", 61002)))
				statsMatcher := proxyConfig.StatsConfig
				Expect(fmt.Sprintf("%+v", statsMatcher.StatsMatcher.StatsMatcher)).To(Equal("&{RejectAll:true}"))

				Expect(proxyConfig.Node.Id).To(Equal(fmt.Sprintf("sidecar~10.0.0.1~%s~x", container.Guid)))
				Expect(proxyConfig.Node.Cluster).To(Equal("proxy-cluster"))

				Expect(proxyConfig.StaticResources.Clusters).To(HaveLen(2))
				expectedCluster{
					name:           "0-service-cluster",
					hosts:          []*envoy_core.Address{envoyAddr("10.0.0.1", 8080)},
					maxConnections: math.MaxUint32,
				}.check(proxyConfig.StaticResources.Clusters[0])

				adsCluster := proxyConfig.StaticResources.Clusters[1]
				expectedCluster{
					name: "pilot-ads",
					hosts: []*envoy_core.Address{
						envoyAddr("10.255.217.2", 15010),
						envoyAddr("10.255.217.3", 15010),
					}}.check(adsCluster)
				Expect(adsCluster.Http2ProtocolOptions).To(Equal(&envoy_core.Http2ProtocolOptions{}))

				Expect(proxyConfig.StaticResources.Listeners).To(HaveLen(1))
				expectedListener{
					name:                     "listener-8080",
					listenPort:               61001,
					statPrefix:               "0-stats",
					clusterName:              "0-service-cluster",
					requireClientCertificate: false,
				}.check(proxyConfig.StaticResources.Listeners[0])
			})
		})

		It("creates appropriate sds-server-cert-and-key.yaml configuration file", func() {
			err := proxyConfigHandler.Update(containerstore.Credential{Cert: "cert", Key: "key"}, container)
			Expect(err).NotTo(HaveOccurred())
			Eventually(sdsServerCertAndKeyFile).Should(BeAnExistingFile())

			var sdsCertificateDiscoveryResponse envoy_discovery.DiscoveryResponse
			Expect(yamlFileToProto(sdsServerCertAndKeyFile, &sdsCertificateDiscoveryResponse)).To(Succeed())

			Expect(sdsCertificateDiscoveryResponse.VersionInfo).To(Equal("0"))
			Expect(sdsCertificateDiscoveryResponse.Resources).To(HaveLen(1))

			var secret envoy_tls.Secret
			Expect(ptypes.UnmarshalAny(sdsCertificateDiscoveryResponse.Resources[0], &secret)).To(Succeed())

			Expect(secret.Name).To(Equal("server-cert-and-key"))
			Expect(secret.Type).To(Equal(&envoy_tls.Secret_TlsCertificate{
				TlsCertificate: &envoy_tls.TlsCertificate{
					CertificateChain: &envoy_core.DataSource{
						Specifier: &envoy_core.DataSource_InlineString{
							InlineString: "cert",
						},
					},
					PrivateKey: &envoy_core.DataSource{
						Specifier: &envoy_core.DataSource_InlineString{
							InlineString: "key",
						},
					},
				},
			}))
		})

		Context("when configuration files already exist", func() {
			var fileWatcher *fsnotify.Watcher

			BeforeEach(func() {
				if runtime.GOOS == "windows" {
					Skip("windows only generates a WRITE event regardless of just a write or rename")
				}

				var err error
				fileWatcher, err = fsnotify.NewWatcher()
				Expect(err).NotTo(HaveOccurred())
			})

			AfterEach(func() {
				Expect(fileWatcher.Close()).To(Succeed())
			})

			It("should ensure the sds-server-cert-and-key.yaml file is recreated when updating the config", func() {
				Expect(ioutil.WriteFile(sdsServerCertAndKeyFile, []byte("old-content"), 0666)).To(Succeed())
				Expect(fileWatcher.Add(sdsServerCertAndKeyFile)).To(Succeed())
				err := proxyConfigHandler.Update(containerstore.Credential{Cert: "cert", Key: "key"}, container)
				Expect(err).NotTo(HaveOccurred())

				Eventually(fileWatcher.Events).Should(Receive(Equal(fsnotify.Event{Name: sdsServerCertAndKeyFile, Op: fsnotify.Remove})))
			})

			It("should ensure the sds-server-validation-context.yaml file is recreated when updating the config", func() {
				Expect(ioutil.WriteFile(sdsServerValidationContextFile, []byte("old-content"), 0666)).To(Succeed())
				Expect(fileWatcher.Add(sdsServerValidationContextFile)).To(Succeed())
				err := proxyConfigHandler.Update(containerstore.Credential{Cert: "cert", Key: "key"}, container)
				Expect(err).NotTo(HaveOccurred())

				Eventually(fileWatcher.Events).Should(Receive(Equal(fsnotify.Event{Name: sdsServerValidationContextFile, Op: fsnotify.Remove})))
			})
		})

		Context("with container proxy trusted certs set", func() {
			var inlinedCert string

			BeforeEach(func() {
				cert, _, _ := generateCertAndKey()
				chainedCert := fmt.Sprintf("%s%s", cert, cert)
				containerProxyTrustedCACerts = []string{cert, chainedCert}
				inlinedCert = fmt.Sprintf("%s%s", cert, chainedCert)
				containerProxyVerifySubjectAltName = []string{"valid-alt-name-1", "valid-alt-name-2"}
			})

			It("creates appropriate sds-server-validation-context.yaml configuration file", func() {
				err := proxyConfigHandler.Update(containerstore.Credential{Cert: "cert", Key: "key"}, container)
				Expect(err).NotTo(HaveOccurred())
				Eventually(sdsServerValidationContextFile).Should(BeAnExistingFile())

				var sdsDiscoveryResponse envoy_discovery.DiscoveryResponse
				Expect(yamlFileToProto(sdsServerValidationContextFile, &sdsDiscoveryResponse)).To(Succeed())

				Expect(sdsDiscoveryResponse.VersionInfo).To(Equal("0"))
				Expect(sdsDiscoveryResponse.Resources).To(HaveLen(1))

				var secret envoy_tls.Secret
				Expect(ptypes.UnmarshalAny(sdsDiscoveryResponse.Resources[0], &secret)).To(Succeed())

				Expect(secret.Name).To(Equal("server-validation-context"))
				Expect(secret.Type).To(Equal(&envoy_tls.Secret_ValidationContext{
					ValidationContext: &envoy_tls.CertificateValidationContext{
						TrustedCa: &envoy_core.DataSource{
							Specifier: &envoy_core.DataSource_InlineString{
								InlineString: inlinedCert,
							},
						},
						MatchSubjectAltNames: []*envoy_matcher.StringMatcher{
							{MatchPattern: &envoy_matcher.StringMatcher_Exact{Exact: "valid-alt-name-1"}},
							{MatchPattern: &envoy_matcher.StringMatcher_Exact{Exact: "valid-alt-name-2"}},
						},
					},
				}))
			})
		})

		It("creates the appropriate proxy config at start", func() {
			err := proxyConfigHandler.Update(containerstore.Credential{Cert: "cert", Key: "key"}, container)
			Expect(err).NotTo(HaveOccurred())

			Eventually(proxyConfigFile).Should(BeAnExistingFile())

			var proxyConfig envoy_bootstrap.Bootstrap
			Expect(yamlFileToProto(proxyConfigFile, &proxyConfig)).To(Succeed())

			admin := proxyConfig.Admin
			Expect(admin.AccessLogPath).To(Equal(os.DevNull))
			Expect(admin.Address).To(Equal(envoyAddr("127.0.0.1", 61002)))
			statsMatcher := proxyConfig.StatsConfig
			Expect(fmt.Sprintf("%+v", statsMatcher.StatsMatcher.StatsMatcher)).To(Equal("&{RejectAll:true}"))

			Expect(proxyConfig.Node.Id).To(Equal(fmt.Sprintf("sidecar~10.0.0.1~%s~x", container.Guid)))
			Expect(proxyConfig.Node.Cluster).To(Equal("proxy-cluster"))

			Expect(proxyConfig.StaticResources.Clusters).To(HaveLen(2))
			expectedCluster{
				name:           "0-service-cluster",
				hosts:          []*envoy_core.Address{envoyAddr("10.0.0.1", 8080)},
				maxConnections: math.MaxUint32,
			}.check(proxyConfig.StaticResources.Clusters[0])

			adsCluster := proxyConfig.StaticResources.Clusters[1]
			expectedCluster{
				name: "pilot-ads",
				hosts: []*envoy_core.Address{
					envoyAddr("10.255.217.2", 15010),
					envoyAddr("10.255.217.3", 15010),
				}}.check(adsCluster)
			Expect(adsCluster.Http2ProtocolOptions).To(Equal(&envoy_core.Http2ProtocolOptions{}))

			Expect(proxyConfig.StaticResources.Listeners).To(HaveLen(1))
			expectedListener{
				name:                     "listener-8080",
				listenPort:               61001,
				statPrefix:               "0-stats",
				clusterName:              "0-service-cluster",
				requireClientCertificate: true,
			}.check(proxyConfig.StaticResources.Listeners[0])

			adsConfigSource := &envoy_core.ConfigSource{
				ConfigSourceSpecifier: &envoy_core.ConfigSource_Ads{
					Ads: &envoy_core.AggregatedConfigSource{},
				},
			}

			Expect(proxyConfig.DynamicResources).To(Equal(&envoy_bootstrap.Bootstrap_DynamicResources{
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
			}))
		})

		Context("when ads server addresses is empty", func() {
			BeforeEach(func() {
				adsServers = []string{}
			})

			It("creates a proxy config without the ads config", func() {
				err := proxyConfigHandler.Update(containerstore.Credential{Cert: "cert", Key: "key"}, container)
				Expect(err).NotTo(HaveOccurred())
				Eventually(proxyConfigFile).Should(BeAnExistingFile())

				var proxyConfig envoy_bootstrap.Bootstrap
				Expect(yamlFileToProto(proxyConfigFile, &proxyConfig)).To(Succeed())

				Expect(proxyConfig.StaticResources.Clusters).To(HaveLen(1))
				cluster := proxyConfig.StaticResources.Clusters[0]
				Expect(cluster.Name).To(Equal("0-service-cluster"))

				Expect(proxyConfig.DynamicResources).To(BeNil())
			})
		})

		Context("when an ads server address is malformed", func() {
			BeforeEach(func() {
				adsServers = []string{
					"malformed",
				}
			})

			It("returns an error", func() {
				err := proxyConfigHandler.Update(containerstore.Credential{Cert: "cert", Key: "key"}, container)
				Expect(err).To(MatchError("ads server address is invalid: malformed"))
			})
		})

		Context("when an ads server port is malformed", func() {
			BeforeEach(func() {
				adsServers = []string{
					"0.0.0.0:mal",
				}
			})

			It("returns an error", func() {
				err := proxyConfigHandler.Update(containerstore.Credential{Cert: "cert", Key: "key"}, container)
				Expect(err).To(MatchError("ads server address is invalid: 0.0.0.0:mal"))
			})
		})

		Context("with multiple port mappings", func() {
			BeforeEach(func() {
				container.Ports = []executor.PortMapping{
					executor.PortMapping{
						ContainerPort:         8080,
						ContainerTLSProxyPort: 61001,
					},
					executor.PortMapping{
						ContainerPort:         2222,
						ContainerTLSProxyPort: 61002,
					},
				}
			})

			It("creates the appropriate proxy config file", func() {
				err := proxyConfigHandler.Update(containerstore.Credential{Cert: "cert", Key: "key"}, container)
				Expect(err).NotTo(HaveOccurred())
				Eventually(proxyConfigFile).Should(BeAnExistingFile())

				var proxyConfig envoy_bootstrap.Bootstrap
				Expect(yamlFileToProto(proxyConfigFile, &proxyConfig)).To(Succeed())

				admin := proxyConfig.Admin
				Expect(admin.AccessLogPath).To(Equal(os.DevNull))
				Expect(admin.Address).To(Equal(envoyAddr("127.0.0.1", 61003)))
				statsMatcher := proxyConfig.StatsConfig
				Expect(fmt.Sprintf("%+v", statsMatcher.StatsMatcher.StatsMatcher)).To(Equal("&{RejectAll:true}"))

				Expect(proxyConfig.Node.Id).To(Equal(fmt.Sprintf("sidecar~10.0.0.1~%s~x", container.Guid)))
				Expect(proxyConfig.Node.Cluster).To(Equal("proxy-cluster"))

				Expect(proxyConfig.StaticResources.Clusters).To(HaveLen(3))

				expectedCluster{
					name:           "0-service-cluster",
					hosts:          []*envoy_core.Address{envoyAddr("10.0.0.1", 8080)},
					maxConnections: math.MaxUint32,
				}.check(proxyConfig.StaticResources.Clusters[0])

				expectedCluster{
					name:           "1-service-cluster",
					hosts:          []*envoy_core.Address{envoyAddr("10.0.0.1", 2222)},
					maxConnections: math.MaxUint32,
				}.check(proxyConfig.StaticResources.Clusters[1])

				adsCluster := proxyConfig.StaticResources.Clusters[2]
				expectedCluster{
					name: "pilot-ads",
					hosts: []*envoy_core.Address{
						envoyAddr("10.255.217.2", 15010),
						envoyAddr("10.255.217.3", 15010),
					},
				}.check(adsCluster)
				Expect(adsCluster.Http2ProtocolOptions).To(Equal(&envoy_core.Http2ProtocolOptions{}))

				Expect(proxyConfig.StaticResources.Listeners).To(HaveLen(2))
				expectedListener{
					name:                     "listener-8080",
					listenPort:               61001,
					statPrefix:               "0-stats",
					clusterName:              "0-service-cluster",
					requireClientCertificate: true,
				}.check(proxyConfig.StaticResources.Listeners[0])

				expectedListener{
					name:                     "listener-2222",
					listenPort:               61002,
					statPrefix:               "1-stats",
					clusterName:              "1-service-cluster",
					requireClientCertificate: true,
				}.check(proxyConfig.StaticResources.Listeners[1])
			})

			Context("when no ports are left", func() {
				BeforeEach(func() {
					ports := []executor.PortMapping{}
					for port := uint16(containerstore.StartProxyPort); port < containerstore.EndProxyPort; port += 2 {
						ports = append(ports, executor.PortMapping{
							ContainerPort:         port,
							ContainerTLSProxyPort: port + 1,
						})
					}

					container.Ports = ports
				})

				It("returns an error", func() {
					err := proxyConfigHandler.Update(containerstore.Credential{Cert: "cert", Key: "key"}, container)
					Expect(err).To(Equal(containerstore.ErrNoPortsAvailable))
				})
			})
		})
	})

	Describe("Close", func() {
		var (
			cert, key string
		)

		BeforeEach(func() {
			container.Ports = []executor.PortMapping{
				{
					ContainerPort:         8080,
					ContainerTLSProxyPort: 61001,
				},
			}

			cert, key, _ = generateCertAndKey()
		})

		JustBeforeEach(func() {
			_, _, err := proxyConfigHandler.CreateDir(logger, container)
			Expect(err).NotTo(HaveOccurred())
		})

		It("returns after the configured reload duration", func() {
			ch := make(chan struct{})
			go func() {
				proxyConfigHandler.Close(containerstore.Credential{Cert: cert, Key: key}, container)
				close(ch)
			}()

			Consistently(ch).ShouldNot(BeClosed())
			reloadClock.WaitForWatcherAndIncrement(1000 * time.Millisecond)
			Eventually(ch).Should(BeClosed())
		})

		Context("the EnableContainerProxy is disabled on the container", func() {
			BeforeEach(func() {
				container.EnableContainerProxy = false
			})

			It("does not write a envoy config file", func() {
				err := proxyConfigHandler.Update(containerstore.Credential{Cert: "", Key: ""}, container)
				Expect(err).NotTo(HaveOccurred())

				Expect(proxyConfigFile).NotTo(BeAnExistingFile())
			})

			It("doesn't wait until the proxy is serving the new cert", func() {
				ch := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					proxyConfigHandler.Close(containerstore.Credential{Cert: cert, Key: key}, container)
					close(ch)
				}()

				Eventually(ch).Should(BeClosed())
			})
		})
	})
})

func generateCertAndKey() (string, string, *big.Int) {
	// generate a real cert
	privateKey, err := rsa.GenerateKey(rand.Reader, 512)
	Expect(err).ToNot(HaveOccurred())
	template := x509.Certificate{
		SerialNumber: new(big.Int),
		Subject:      pkix.Name{CommonName: "sample-cert"},
	}
	guid, err := uuid.NewV4()
	Expect(err).NotTo(HaveOccurred())

	guidBytes := [16]byte(*guid)
	template.SerialNumber.SetBytes(guidBytes[:])

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, privateKey.Public(), privateKey)

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	Expect(err).ToNot(HaveOccurred())
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
	key := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes}))
	return cert, key, template.SerialNumber
}

func yamlFileToStruct(path string, outputStruct interface{}) error {
	yamlBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(yamlBytes, outputStruct)
}

func yamlFileToProto(path string, outputProto proto.Message) error {
	yamlBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	jsonBytes, err := ghodss_yaml.YAMLToJSON(yamlBytes)
	if err != nil {
		return err
	}

	err = jsonpb.UnmarshalString(string(jsonBytes), outputProto)
	if err != nil {
		return err
	}

	// Check if unmarshalled proto follows validation rules
	return outputProto.(interface{ Validate() error }).Validate()
}

func envoyAddr(ip string, port int) *envoy_core.Address {
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

type expectedListener struct {
	name                     string
	listenPort               int
	statPrefix               string
	clusterName              string
	requireClientCertificate bool
}

func (l expectedListener) check(listener *envoy_listener.Listener) {
	Expect(listener.Name).To(Equal(l.name))
	Expect(listener.Address).To(Equal(envoyAddr("0.0.0.0", l.listenPort)))
	Expect(listener.FilterChains).To(HaveLen(1))
	filterChain := listener.FilterChains[0]
	Expect(filterChain.Filters).To(HaveLen(1))
	Expect(filterChain.Filters[0].Name).To(Equal("envoy.tcp_proxy"))
	filterConfig := filterChain.Filters[0].GetTypedConfig()

	var tcpProxyFilterConfig envoy_tcp_proxy.TcpProxy
	Expect(ptypes.UnmarshalAny(filterConfig, &tcpProxyFilterConfig)).To(Succeed())
	Expect(tcpProxyFilterConfig.StatPrefix).To(Equal(l.statPrefix))
	Expect(tcpProxyFilterConfig.ClusterSpecifier).To(Equal(&envoy_tcp_proxy.TcpProxy_Cluster{
		Cluster: l.clusterName,
	}))

	var downstreamTlsContext envoy_tls.DownstreamTlsContext
	Expect(ptypes.UnmarshalAny(filterChain.TransportSocket.GetTypedConfig(), &downstreamTlsContext)).To(Succeed())
	Expect(filterChain.TransportSocket.Name).To(Equal(l.name))

	Expect(downstreamTlsContext.RequireClientCertificate.Value).To(Equal(l.requireClientCertificate))
	Expect(downstreamTlsContext.CommonTlsContext.AlpnProtocols).To(Equal([]string{"h2,http/1.1"}))
	Expect(downstreamTlsContext.CommonTlsContext.TlsCertificateSdsSecretConfigs).To(ConsistOf(
		&envoy_tls.SdsSecretConfig{
			Name: "server-cert-and-key",
			SdsConfig: &envoy_core.ConfigSource{
				ConfigSourceSpecifier: &envoy_core.ConfigSource_Path{
					Path: "/etc/cf-assets/envoy_config/sds-server-cert-and-key.yaml",
				},
			},
		},
	))
	Expect(downstreamTlsContext.CommonTlsContext.TlsParams).To(Equal(&envoy_tls.TlsParameters{
		CipherSuites: []string{"ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256"},
	}))

	if l.requireClientCertificate {
		Expect(downstreamTlsContext.CommonTlsContext.ValidationContextType).To(Equal(&envoy_tls.CommonTlsContext_ValidationContextSdsSecretConfig{
			ValidationContextSdsSecretConfig: &envoy_tls.SdsSecretConfig{
				Name: "server-validation-context",
				SdsConfig: &envoy_core.ConfigSource{
					ConfigSourceSpecifier: &envoy_core.ConfigSource_Path{
						Path: "/etc/cf-assets/envoy_config/sds-server-validation-context.yaml",
					},
				},
			},
		}))
	} else {
		Expect(downstreamTlsContext.CommonTlsContext.ValidationContextType).To(BeNil())
	}
}

type expectedCluster struct {
	name           string
	hosts          []*envoy_core.Address
	maxConnections uint32
}

func (c expectedCluster) check(cluster *envoy_cluster.Cluster) {
	Expect(cluster.Name).To(Equal(c.name))
	Expect(cluster.ConnectTimeout).To(Equal(&duration.Duration{Nanos: 250000000}))
	Expect(cluster.ClusterDiscoveryType).To(Equal(&envoy_cluster.Cluster_Type{Type: envoy_cluster.Cluster_STATIC}))
	Expect(cluster.LbPolicy).To(Equal(envoy_cluster.Cluster_ROUND_ROBIN))
	var expectedLbEndpoints []*envoy_endpoint.LbEndpoint
	for _, h := range c.hosts {
		expectedLbEndpoints = append(expectedLbEndpoints, &envoy_endpoint.LbEndpoint{
			HostIdentifier: &envoy_endpoint.LbEndpoint_Endpoint{
				Endpoint: &envoy_endpoint.Endpoint{
					Address: h,
				},
			},
		})
	}
	Expect(cluster.LoadAssignment).To(Equal(&envoy_endpoint.ClusterLoadAssignment{
		ClusterName: c.name,
		Endpoints: []*envoy_endpoint.LocalityLbEndpoints{{
			LbEndpoints: expectedLbEndpoints,
		}},
	}))
	if c.maxConnections > 0 {
		Expect(cluster.CircuitBreakers.Thresholds).To(HaveLen(1))
		Expect(cluster.CircuitBreakers.Thresholds[0].MaxConnections.Value).To(BeNumerically("==", c.maxConnections))
	} else {
		Expect(cluster.CircuitBreakers).To(BeNil())
	}
}
