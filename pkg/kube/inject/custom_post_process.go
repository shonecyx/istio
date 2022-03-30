package inject

import (
	"fmt"

	"istio.io/api/annotation"
	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pkg/config/mesh"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	sharedCACertsVolumeName          = "istio-auto-ca-cert"
	sharedCAKeyVolumeName            = "istio-auto-ca"
	sharedAppCACertsVolumeMountPath  = "/usr/local/share/istio-auto-ca-certificates"
	sharedProxyCAVolumeMountPath     = "/usr/local/share/istio-auto-ca"
	autoRootCAPath                   = "AUTO_ROOT_CA_PATH"
	autoCACertProxyMetadataKey       = "INJECT_AUTO_CERT"
	appContainerNameProxyMetadataKey = "APP_CONTAINER_NAME"
	javaAppFW                        = "JAVA_FW"
	nodeJSAppFW                      = "NODEJS_FW"
	nodeJSExtraCACerts               = "NODE_EXTRA_CA_CERTS"
	nodeJSExtraCACertsFile           = "istio-auto-root-ca-cert.pem"
)

func getProxyConfig(mc *meshconfig.MeshConfig, metadata *metav1.ObjectMeta) (*meshconfig.MeshConfig, error) {

	var meshConfig *meshconfig.MeshConfig

	if pca, f := metadata.GetAnnotations()[annotation.ProxyConfig.Name]; f {
		var err error
		meshConfig, err = mesh.ApplyProxyConfig(pca, *mc)
		if err != nil {
			return nil, fmt.Errorf("failed unmarshal proxyConfig annotations:\n'%s'. %v", pca, err)
		}
	}

	return meshConfig, nil
}

func verifyMatchingApplicationContainerName(name string, pcm map[string]string) bool {

	if acn, ok := pcm[appContainerNameProxyMetadataKey]; ok {

		if acn == name {
			return true
		}
	}

	return false
}

func handleContainersSpecAutoCertInjection(pod *corev1.Pod, appStack string, podProxyMetadata map[string]string) bool {

	var matched bool
	// Append shared-cacerts volumeMount per each pods containers
	for i, c := range pod.Spec.Containers {

		if ok := verifyMatchingApplicationContainerName(c.Name, podProxyMetadata); ok {
			matched = true

			vm := corev1.VolumeMount{
				Name:      sharedCACertsVolumeName,
				MountPath: sharedAppCACertsVolumeMountPath,
				ReadOnly:  true,
			}
			c.VolumeMounts = append(c.VolumeMounts, vm)

			// in case of NodeJS FW, add extra CA certs environment variable
			if appStack == nodeJSAppFW {
				env := corev1.EnvVar{
					Name:  nodeJSExtraCACerts,
					Value: sharedAppCACertsVolumeMountPath + "/" + nodeJSExtraCACertsFile,
				}
				c.Env = append(c.Env, env)
			}
			pod.Spec.Containers[i] = c
			continue
		}

		if c.Name == "istio-proxy" {

			env := corev1.EnvVar{
				Name:  autoRootCAPath,
				Value: sharedProxyCAVolumeMountPath,
			}
			c.Env = append(c.Env, env)

			vm := corev1.VolumeMount{
				Name:      sharedCAKeyVolumeName,
				MountPath: sharedProxyCAVolumeMountPath,
			}

			c.VolumeMounts = append(c.VolumeMounts, vm)
			pod.Spec.Containers[i] = c
		}
	}

	return matched
}

func customPostProcess(pod *corev1.Pod, req InjectionParameters) error {

	pmc, err := getProxyConfig(req.meshConfig, &req.pod.ObjectMeta)
	if err != nil {
		return err
	}
	if pmc == nil {
		return nil
	}
	pcm := pmc.DefaultConfig.ProxyMetadata
	if cav, ok := pcm[autoCACertProxyMetadataKey]; ok {

		if cav == javaAppFW || cav == nodeJSAppFW {
			if ok := handleContainersSpecAutoCertInjection(pod, cav, pcm); !ok {
				return fmt.Errorf("could not find matching application name in proxyMetadata\n'%v'", pcm)
			}
			// Append two emptyDir{} volumes:
			// 1. istio-auto-ca-cert: istio-auto-cacert, initContainer, will store generated root CA cert
			// 2. istio-auto-ca-key: istio-auto-cacert, initContainer, will store generated root CA key
			caCertsVol := corev1.Volume{
				Name:         sharedCACertsVolumeName,
				VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
			}
			caKeyVol := corev1.Volume{
				Name:         sharedCAKeyVolumeName,
				VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
			}
			pod.Spec.Volumes = append(pod.Spec.Volumes, caCertsVol, caKeyVol)
		}
	}

	return nil
}
