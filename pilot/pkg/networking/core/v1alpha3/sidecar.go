// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1alpha3

import (
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"

	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking/util"
	authn_model "istio.io/istio/pilot/pkg/security/model"
	"istio.io/istio/pkg/proto"
)

// IsPassThroughServer returns true if this server does TLS passthrough (auto or manual)
func IsPassThroughServer(tls *networking.ServerTLSSettings) bool {
	if tls == nil {
		return false
	}

	if tls.Mode == networking.ServerTLSSettings_PASSTHROUGH {
		return true
	}

	return false
}

func buildSidecarOutboundListenerTLSContext(tls *networking.ServerTLSSettings, proxy *model.Proxy) *tlsv3.DownstreamTlsContext {

	if tls == nil || IsPassThroughServer(tls) {
		return nil
	}

	ctx := &tlsv3.DownstreamTlsContext{
		CommonTlsContext: &tlsv3.CommonTlsContext{
			AlpnProtocols: util.ALPNHttp,
		},
	}

	ctx.RequireClientCertificate = proto.BoolFalse
	if tls.Mode == networking.ServerTLSSettings_MUTUAL ||
		tls.Mode == networking.ServerTLSSettings_ISTIO_MUTUAL {
		ctx.RequireClientCertificate = proto.BoolTrue
	}

	switch {
	case tls.CredentialName != "":
		authn_model.ApplyCredentialSDSToServerCommonTLSContext(ctx.CommonTlsContext, tls)
	case tls.Mode == networking.ServerTLSSettings_ISTIO_MUTUAL:
		authn_model.ApplyToCommonTLSContext(ctx.CommonTlsContext, proxy, tls.SubjectAltNames, []string{}, ctx.RequireClientCertificate.Value)
	default:
		certProxy := &model.Proxy{}
		certProxy.IstioVersion = proxy.IstioVersion
		// If certificate files are specified in gateway configuration, use file based SDS.
		certProxy.Metadata = &model.NodeMetadata{
			TLSServerCertChain: tls.ServerCertificate,
			TLSServerKey:       tls.PrivateKey,
			TLSServerRootCert:  tls.CaCertificates,
		}

		authn_model.ApplyToCommonTLSContext(ctx.CommonTlsContext, certProxy, tls.SubjectAltNames, []string{}, ctx.RequireClientCertificate.Value)
	}

	// Set TLS parameters if they are non-default
	if len(tls.CipherSuites) > 0 ||
		tls.MinProtocolVersion != networking.ServerTLSSettings_TLS_AUTO ||
		tls.MaxProtocolVersion != networking.ServerTLSSettings_TLS_AUTO {
		ctx.CommonTlsContext.TlsParams = &tlsv3.TlsParameters{
			TlsMinimumProtocolVersion: convertTLSProtocol(tls.MinProtocolVersion),
			TlsMaximumProtocolVersion: convertTLSProtocol(tls.MaxProtocolVersion),
			CipherSuites:              filteredCipherSuites(tls.CipherSuites),
		}
	}

	return ctx

}
