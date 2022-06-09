package v1alpha3

import (
	"reflect"
	"sort"
	"testing"

	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	networking "istio.io/api/networking/v1alpha3"
	xdsfilters "istio.io/istio/pilot/pkg/xds/filters"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/test/xdstest"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/schema/gvk"
)

func TestBuildSidecarOutboundListenersWithHTTPSTermination(t *testing.T) {

	sidecarProxy := model.Proxy{
		Type:        model.SidecarProxy,
		IPAddresses: []string{"1.1.1.1"},
		ID:          "v0.default",
		DNSDomain:   "default.example.org",
		Metadata: &model.NodeMetadata{
			Namespace: "not-default",
		},
		ConfigNamespace: "not-default",
	}

	type expectedFilterChain struct {
		FilterChainMatch *listener.FilterChainMatch
		IsTLS            bool
	}

	cases := []struct {
		name              string
		serviceEntries    []config.Config
		sidecar           config.Config
		expectedListeners map[string][]expectedFilterChain
	}{
		{
			"ServiceEntries with same hostnames but different exportTo",
			[]config.Config{
				{
					Meta: config.Meta{Name: "export-to-root", Namespace: "ns-config", GroupVersionKind: gvk.ServiceEntry},
					Spec: &networking.ServiceEntry{
						ExportTo: []string{"istio-system"},
						Hosts:    []string{"test.com", "foo.test.com", "bar.test.com"},
						Ports: []*networking.Port{
							{Name: "https", Number: 443, Protocol: "HTTPS"},
						},
						Resolution: networking.ServiceEntry_DNS,
					},
				},
				{
					Meta: config.Meta{Name: "export-to-non-default", Namespace: "ns-config", GroupVersionKind: gvk.ServiceEntry},
					Spec: &networking.ServiceEntry{
						ExportTo: []string{sidecarProxy.ConfigNamespace},
						Hosts:    []string{"test.com", "foo.test.com", "bar.test.com"},
						Ports: []*networking.Port{
							{Name: "http", Number: 80, Protocol: "HTTP"},
							{Name: "https", Number: 443, Protocol: "HTTPS"},
						},
						Resolution: networking.ServiceEntry_DNS,
					},
				},
			},
			config.Config{
				Meta: config.Meta{
					Name:             "sc",
					Namespace:        sidecarProxy.ConfigNamespace,
					GroupVersionKind: gvk.Sidecar,
				},
				Spec: &networking.Sidecar{
					Egress: []*networking.IstioEgressListener{
						{
							Hosts: []string{"ns-config/test.com", "ns-config/foo.test.com", "ns-config/bar.test.com"},
							Port:  &networking.Port{Name: "http", Number: 80, Protocol: "HTTP"},
						},
						{
							Hosts: []string{"ns-config/test.com", "ns-config/foo.test.com", "ns-config/bar.test.com"},
							Port:  &networking.Port{Name: "https", Number: 443, Protocol: "HTTPS"},
							Tls: &networking.ServerTLSSettings{
								CredentialName: "auto://test.com~foo.test.com~bar.test.com",
								Mode:           networking.ServerTLSSettings_SIMPLE,
							},
						},
					},
				},
			},
			map[string][]expectedFilterChain{
				"0.0.0.0_443": {
					{
						FilterChainMatch: &listener.FilterChainMatch{
							ServerNames:       []string{"test.com"},
							TransportProtocol: xdsfilters.TLSTransportProtocol,
						},
						IsTLS: true,
					},
					{
						FilterChainMatch: &listener.FilterChainMatch{
							ServerNames:       []string{"foo.test.com"},
							TransportProtocol: xdsfilters.TLSTransportProtocol,
						},
						IsTLS: true,
					},
					{
						FilterChainMatch: &listener.FilterChainMatch{
							ServerNames:       []string{"bar.test.com"},
							TransportProtocol: xdsfilters.TLSTransportProtocol,
						},
						IsTLS: true,
					},
				},
				"0.0.0.0_80": {
					{
						IsTLS: false,
					},
				},
			},
		},
		{
			"Sidecar with multiple egress listeners and same port",
			[]config.Config{
				{
					Meta: config.Meta{Name: "foo", Namespace: "ns-config", GroupVersionKind: gvk.ServiceEntry},
					Spec: &networking.ServiceEntry{
						Hosts: []string{"foo.com", "a.foo.com", "b.foo.com"},
						Ports: []*networking.Port{
							{Name: "https", Number: 443, Protocol: "HTTPS"},
						},
						Resolution: networking.ServiceEntry_DNS,
					},
				},
				{
					Meta: config.Meta{Name: "bar", Namespace: "ns-config", GroupVersionKind: gvk.ServiceEntry},
					Spec: &networking.ServiceEntry{
						Hosts: []string{"bar.com", "x.bar.com", "y.bar.com"},
						Ports: []*networking.Port{
							{Name: "https", Number: 443, Protocol: "HTTPS"},
						},
						Resolution: networking.ServiceEntry_DNS,
					},
				},
			},
			config.Config{
				Meta: config.Meta{
					Name:             "sidecar-egress",
					Namespace:        sidecarProxy.ConfigNamespace,
					GroupVersionKind: gvk.Sidecar,
				},
				Spec: &networking.Sidecar{
					Egress: []*networking.IstioEgressListener{
						{
							Hosts: []string{"ns-config/foo.com", "ns-config/a.foo.com", "ns-config/b.foo.com"},
							Port:  &networking.Port{Name: "https", Number: 443, Protocol: "HTTPS"},
							Tls: &networking.ServerTLSSettings{
								CredentialName: "auto://foo.com~a.foo.com~b.foo.com",
								Mode:           networking.ServerTLSSettings_SIMPLE,
							},
						},
						{
							Hosts: []string{"ns-config/bar.com", "ns-config/x.bar.com", "ns-config/y.bar.com"},
							Port:  &networking.Port{Name: "https", Number: 443, Protocol: "HTTPS"},
							Tls: &networking.ServerTLSSettings{
								CredentialName: "auto://bar.com~x.bar.com~y.bar.com",
								Mode:           networking.ServerTLSSettings_SIMPLE,
							},
						},
					},
				},
			},
			map[string][]expectedFilterChain{
				"0.0.0.0_443": {
					{
						FilterChainMatch: &listener.FilterChainMatch{
							ServerNames:       []string{"foo.com"},
							TransportProtocol: xdsfilters.TLSTransportProtocol,
						},
						IsTLS: true,
					},
					{
						FilterChainMatch: &listener.FilterChainMatch{
							ServerNames:       []string{"a.foo.com"},
							TransportProtocol: xdsfilters.TLSTransportProtocol,
						},
						IsTLS: true,
					},
					{
						FilterChainMatch: &listener.FilterChainMatch{
							ServerNames:       []string{"b.foo.com"},
							TransportProtocol: xdsfilters.TLSTransportProtocol,
						},
						IsTLS: true,
					},
					{
						FilterChainMatch: &listener.FilterChainMatch{
							ServerNames:       []string{"bar.com"},
							TransportProtocol: xdsfilters.TLSTransportProtocol,
						},
						IsTLS: true,
					},
					{
						FilterChainMatch: &listener.FilterChainMatch{
							ServerNames:       []string{"x.bar.com"},
							TransportProtocol: xdsfilters.TLSTransportProtocol,
						},
						IsTLS: true,
					},
					{
						FilterChainMatch: &listener.FilterChainMatch{
							ServerNames:       []string{"y.bar.com"},
							TransportProtocol: xdsfilters.TLSTransportProtocol,
						},
						IsTLS: true,
					},
				},
			},
		},
	}

	for _, tt := range cases {
		Configs := make([]config.Config, 0)
		Configs = append(Configs, tt.serviceEntries...)
		cg := NewConfigGenTest(t, TestOptions{
			Configs:        Configs,
			ConfigPointers: []*config.Config{&tt.sidecar},
		})
		proxy := cg.SetupProxy(&sidecarProxy)

		listeners := cg.ConfigGen.buildSidecarOutboundListeners(proxy, cg.env.PushContext)
		actualListeners := xdstest.ExtractListenerNames(listeners)

		expectedListeners := make([]string, 0, len(tt.expectedListeners))
		for k := range tt.expectedListeners {
			expectedListeners = append(expectedListeners, k)
		}

		sort.Strings(expectedListeners)
		sort.Strings(actualListeners)
		if !reflect.DeepEqual(expectedListeners, actualListeners) {
			t.Fatalf("Expected listeners: %v, got: %v", expectedListeners, actualListeners)
		}

		for k, v := range tt.expectedListeners {
			l := xdstest.ExtractListener(k, listeners)
			if len(l.FilterChains) != len(v) {
				t.Fatalf("Expected filter chain number: %v, got: %v", len(v), len(l.FilterChains))
			}

			for _, efc := range v {
				var fc *listener.FilterChain

				if efc.IsTLS {
					for _, afc := range l.FilterChains {
						if filterChainMatchEqual(efc.FilterChainMatch, afc.FilterChainMatch) {
							fc = afc
						}
					}
					if fc == nil {
						t.Fatalf("Missing filter chain: %v", efc.FilterChainMatch)
					}
				} else {
					fc = l.FilterChains[0]
				}

				if !isHTTPFilterChain(fc) {
					t.Fatalf("expected http filter chain, found %s", fc.Filters[0].Name)
				}

				verifyHTTPFilterChainMatch(t, fc, model.TrafficDirectionOutbound, efc.IsTLS)
			}
		}

		xdstest.ValidateListeners(t, listeners)
	}
}
