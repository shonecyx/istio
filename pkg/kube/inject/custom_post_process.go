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
	sharedCAKeyVolumeName      = "istio-auto-ca"
	sharedCARootCertVolumeName = "istio-auto-ca-root-cert"

	// include auto CA root cert and key, sds-agent uses them to sign server cert/key
	sharedProxyCAVolumeMountPath = "/usr/local/share/istio-auto-ca"
	// only include auto CA root cert, raptor loads certs from this location
	sharedRaptorCertVolumeMountPath = "/ebay/config/cacerts"
	// only include auto CA root cert
	sharedAppCACertsVolumeMountPath = "/usr/local/share/istio-auto-ca-certificates"

	autoRootCAPath             = "AUTO_ROOT_CA_PATH"
	autoCACertProxyMetadataKey = "INJECT_AUTO_CERT"

	javaAppFW              = "JAVA_FW"
	nodeJSAppFW            = "NODEJS_FW"
	nodeJSExtraCACerts     = "NODE_EXTRA_CA_CERTS"
	nodeJSExtraCACertsFile = "istio-auto-root-ca-cert.pem"

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

// append a Volume to Volume list if it's not found. This is for ensure idempotency
func appendVolume(volumes []corev1.Volume, vol corev1.Volume) []corev1.Volume {
	found := false

	for _, v := range volumes {
		if v.Name == vol.Name {
			found = true
			break
		}
	}

	if !found {
		volumes = append(volumes, vol)
	}

	return volumes
}

// append a VolumeMount to VolumeMount list if it's not found. This is for ensure idempotency
func appendVolumeMount(volumeMounts []corev1.VolumeMount, vm corev1.VolumeMount) []corev1.VolumeMount {
	found := false

	for _, v := range volumeMounts {
		if v.Name == vm.Name {
			found = true
			break
		}
	}

	if !found {
		volumeMounts = append(volumeMounts, vm)
	}

	return volumeMounts
}

// append a EnvVar to EnvVar list if it's not found. This is for ensure idempotency
func appendEnvVar(EnvVars []corev1.EnvVar, ev corev1.EnvVar) []corev1.EnvVar {
	found := false

	for _, v := range EnvVars {
		if v.Name == ev.Name {
			found = true
			break
		}
	}

	if !found {
		EnvVars = append(EnvVars, ev)
	}

	return EnvVars
}

// append volumes to containers for accessing Istio auto CA root cert/key
func handleContainersSpecAutoCertInjection(pod *corev1.Pod, appContainersStackId map[string]string, podProxyMetadata map[string]string) error {

	for i, c := range pod.Spec.Containers {
		if c.Name == "istio-proxy" {
			env := corev1.EnvVar{
				Name:  autoRootCAPath,
				Value: sharedProxyCAVolumeMountPath,
			}
			c.Env = appendEnvVar(c.Env, env)

			vm := corev1.VolumeMount{
				Name:      sharedCAKeyVolumeName,
				MountPath: sharedProxyCAVolumeMountPath,
				ReadOnly:  true,
			}
			c.VolumeMounts = appendVolumeMount(c.VolumeMounts, vm)
			pod.Spec.Containers[i] = c
		}
	}

	for name, stackId := range appContainersStackId {
		if err := mountAutoCARootCertToContainer(pod, name, stackId); err != nil {
			return err
		}
	}

	return nil
}

func mountAutoCARootCertToContainer(pod *corev1.Pod, name, stackId string) error {

	for i, c := range pod.Spec.Containers {
		if c.Name == name {
			if strings.HasPrefix(stackId, "raptor") {

				// For Raptor Java application, override original root CA trust store
				vm := corev1.VolumeMount{
					Name:      sharedCARootCertVolumeName,
					MountPath: sharedRaptorCertVolumeMountPath,
					ReadOnly:  true,
				}
				c.VolumeMounts = appendVolumeMount(c.VolumeMounts, vm)
			} else if strings.HasPrefix(stackId, "nodejs") {

				vm := corev1.VolumeMount{
					Name:      sharedCARootCertVolumeName,
					MountPath: sharedAppCACertsVolumeMountPath,
					ReadOnly:  true,
				}
				c.VolumeMounts = appendVolumeMount(c.VolumeMounts, vm)

				// in case of NodeJS FW, add extra CA certs environment variable
				env := corev1.EnvVar{
					Name:  nodeJSExtraCACerts,
					Value: sharedAppCACertsVolumeMountPath + "/" + nodeJSExtraCACertsFile,
				}
				c.Env = appendEnvVar(c.Env, env)
			} else {
				// TODO: support generic workload which using openssl
				return fmt.Errorf("Fail to inject Istio auto CA root cert to container '%s', unknown stackId '%s'",
					name, stackId)
			}

			pod.Spec.Containers[i] = c

			return nil
		}
	}

	return fmt.Errorf("Fail to inject Istio auto CA root cert, container '%s' not found", name)
}

func handlePodVolumesSpecAutoCertInjection(pod *corev1.Pod, appContainersStackId map[string]string) {

	// volume for storing root cert
	caRootCertVol := corev1.Volume{
		Name:         sharedCARootCertVolumeName,
		VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
	}
	pod.Spec.Volumes = appendVolume(pod.Spec.Volumes, caRootCertVol)

	// volume for storing istio auto root CA cert and key, which will be used by SDS agent in istio-proxy
	// to sign cert/key for egress service
	caVol := corev1.Volume{
		Name:         sharedCAKeyVolumeName,
		VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
	}
	pod.Spec.Volumes = appendVolume(pod.Spec.Volumes, caVol)

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
					return fmt.Errorf("annotation '%s' has invalid value '%s', error: %v", sidecarsStackIdAnnotation, b, err)
				}
			}

			if appStack, ok := req.pod.ObjectMeta.GetAnnotations()[appStackIdAnnotation]; ok {
				//TODO: make generic
				if appCustomName, ok := req.pod.ObjectMeta.GetAnnotations()[appContainerNameAnnotation]; ok {
					appContainerName = appCustomName
				}
				appContainersStackId[appContainerName] = appStack
			}

			if len(appContainersStackId) == 0 {
				return fmt.Errorf("Istio auto CA injection is enabled, but missing annotations: %s and/or %s",
					appStackIdAnnotation, sidecarsStackIdAnnotation)
			}

			if err := handleContainersSpecAutoCertInjection(pod, appContainersStackId, pcm); err != nil {
				return err
			}

			// Append two emptyDir{} volumes:
			// 1. istio-auto-ca-cert: istio-auto-cacert, initContainer, will store generated root CA cert
			// 2. istio-auto-ca-key: istio-auto-cacert, initContainer, will store generated root CA key
			handlePodVolumesSpecAutoCertInjection(pod, appContainersStackId)
		}
	}

	return nil
}
