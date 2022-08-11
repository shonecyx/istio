package inject

import (
	"encoding/json"
	"fmt"
	"strings"

	"istio.io/api/annotation"
	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pkg/config/mesh"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	sharedRaptorJRECACertsVolumeName  = "istio-auto-ca-openjre-cert"
	sharedNodeJSCACertsVolumeName     = "istio-auto-ca-nodejs-cert"
	sharedCAKeyVolumeName             = "istio-auto-ca"
	sharedAppCACertsVolumeMountPath   = "/usr/local/share/istio-auto-ca-certificates"
	sharedProxyCAVolumeMountPath      = "/usr/local/share/istio-auto-ca"
	sharedRaptorJRElibVolumeMountPath = "/ebay/app/jre/lib/security"
	autoRootCAPath                    = "AUTO_ROOT_CA_PATH"
	autoCACertProxyMetadataKey        = "INJECT_AUTO_CERT"
	appContainerNameProxyMetadataKey  = "APP_CONTAINER_NAME"
	javaAppFW                         = "JAVA_FW"
	nodeJSAppFW                       = "NODEJS_FW"
	nodeJSExtraCACerts                = "NODE_EXTRA_CA_CERTS"
	nodeJSExtraCACertsFile            = "istio-auto-root-ca-cert.pem"

	// framework application's stack id, its value follow below rules:
	// - node.js applications' stack id are begin with `nodejs`
	// - java application's stack id are begin with `raptor`
	appStackIdAnnotation = "application.tess.io/stackId"

	// framework application's container name is `app` by default, if it's not the case,
	// this annotation can be used to specify the application container.
	appContainerNameAnnotation = "application.tess.io/app-container-name"

	// if multiple containers need Istio auto root CA cert injection, use this annotation to
	// specify the containers and their stack. Its value is a JSON object as:
	//   { "app-raptor": "raptor.marketplace", "app-node": "nodejs.marketplace"}
	//
	sidecarsStackIdAnnotation = "application.tess.io/sidecars-stackId"
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

func handleContainersSpecAutoCertInjection(pod *corev1.Pod, appContainersStackId map[string]string, podProxyMetadata map[string]string) bool {

	var matched bool
	// Append shared-cacerts volumeMount per each pods containers
	for i, c := range pod.Spec.Containers {
		if c.Name == "istio-proxy" {
			env := corev1.EnvVar{
				Name:  autoRootCAPath,
				Value: sharedProxyCAVolumeMountPath,
			}
			c.Env = append(c.Env, env)

			vm := corev1.VolumeMount{
				Name:      sharedCAKeyVolumeName,
				MountPath: sharedProxyCAVolumeMountPath,
				ReadOnly:  true,
			}
			c.VolumeMounts = append(c.VolumeMounts, vm)
			pod.Spec.Containers[i] = c
		}

		if stackId, ok := appContainersStackId[c.Name]; ok {
			if strings.Contains(stackId, "raptor") {
				matched = true
				// For Raptor Java application, override original root CA trust store
				vm := corev1.VolumeMount{
					Name:      sharedRaptorJRECACertsVolumeName,
					MountPath: sharedRaptorJRElibVolumeMountPath,
					ReadOnly:  true,
				}
				c.VolumeMounts = append(c.VolumeMounts, vm)
			}
			if strings.Contains(stackId, "nodejs") {
				matched = true
				vm := corev1.VolumeMount{
					Name:      sharedNodeJSCACertsVolumeName,
					MountPath: sharedAppCACertsVolumeMountPath,
					ReadOnly:  true,
				}
				c.VolumeMounts = append(c.VolumeMounts, vm)

				// in case of NodeJS FW, add extra CA certs environment variable
				env := corev1.EnvVar{
					Name:  nodeJSExtraCACerts,
					Value: sharedAppCACertsVolumeMountPath + "/" + nodeJSExtraCACertsFile,
				}
				c.Env = append(c.Env, env)
			}
			pod.Spec.Containers[i] = c
		}
	}

	return matched
}

func handlePodVolumesSpecAutoCertInjection(pod *corev1.Pod, appContainersStackId map[string]string) {

	// volume for importing cert to JKS in openJRE for raptor application
	caCertsVol := corev1.Volume{
		Name:         sharedRaptorJRECACertsVolumeName,
		VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
	}
	pod.Spec.Volumes = append(pod.Spec.Volumes, caCertsVol)

	// volume for storing root cert
	caCertsVol = corev1.Volume{
		Name:         sharedNodeJSCACertsVolumeName,
		VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
	}
	pod.Spec.Volumes = append(pod.Spec.Volumes, caCertsVol)

	// volume for storing istio auto root CA cert and key, which will be used by SDS agent in istio-proxy
	// to sign cert/key for egress service
	caKeyVol := corev1.Volume{
		Name:         sharedCAKeyVolumeName,
		VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
	}
	pod.Spec.Volumes = append(pod.Spec.Volumes, caKeyVol)

	return
}

func customPostProcess(pod *corev1.Pod, req InjectionParameters) error {
	appContainerName := "app"
	pmc, err := getProxyConfig(req.meshConfig, &req.pod.ObjectMeta)
	if err != nil {
		return err
	}
	if pmc == nil {
		return nil
	}
	pcm := pmc.DefaultConfig.ProxyMetadata
	if cav, ok := pcm[autoCACertProxyMetadataKey]; ok {

		// Check INJECT_AUTO_CERT against 'JAVA_FW' and 'NODEJS_FW' for backward compatibility,
		// if an old Pod uses INJECT_AUTO_CERT , after this change rolled out, because INJECT_AUTO_CERT
		// is JAVA_FW or NODEJS_FW, istio auto cert init container will be injected to it, stack is
		// inferred by application.tess.io/stackId, default container is `app`. This can be removed
		// after old Pods change to new setting.
		if cav == "true" || cav == javaAppFW || cav == nodeJSAppFW {
			appContainersStackId := map[string]string{}

			if b, ok := req.pod.ObjectMeta.GetAnnotations()[sidecarsStackIdAnnotation]; ok {
				err := json.Unmarshal([]byte(b), &appContainersStackId)
				if err != nil {
					return err
				}
			}
			if appStack, ok := req.pod.ObjectMeta.GetAnnotations()[appStackIdAnnotation]; ok {
				//TODO: make generic
				if appCustomName, ok := req.pod.ObjectMeta.GetAnnotations()[appContainerNameAnnotation]; ok {
					appContainerName = appCustomName
				}
				appContainersStackId[appContainerName] = appStack

			}
			if ok := handleContainersSpecAutoCertInjection(pod, appContainersStackId, pcm); !ok {
				return fmt.Errorf("could not find matching application stackId '%s'", appContainersStackId[appContainerName])
			}
			// Append two emptyDir{} volumes:
			// 1. istio-auto-ca-cert: istio-auto-cacert, initContainer, will store generated root CA cert
			// 2. istio-auto-ca-key: istio-auto-cacert, initContainer, will store generated root CA key
			handlePodVolumesSpecAutoCertInjection(pod, appContainersStackId)
		}
	}

	return nil
}
