package webhook

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	piishieldv1alpha1 "github.com/pii-shield/pii-shield/operator/api/v1alpha1"
)

func TestInjectFileMode(t *testing.T) {
	mutator := &PodMutator{
		LegacySidecarMode: false,
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-pod",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "main-app",
				},
			},
		},
	}
	policy := &piishieldv1alpha1.PiiPolicy{
		Spec: piishieldv1alpha1.PiiPolicySpec{
			InjectionMode: "file",
			LogPath:       "/var/log/app",
			Resources: corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					corev1.ResourceCPU: resource.MustParse("100m"),
				},
			},
		},
	}

	mutated, err := mutator.injectFileMode(pod, policy, "main-app")
	assert.NoError(t, err)

	// Verify volumes
	foundShared := false
	foundTmp := false
	for _, v := range mutated.Spec.Volumes {
		if v.Name == "pii-shared" {
			foundShared = true
		}
		if v.Name == "pii-tmp" {
			foundTmp = true
		}
	}
	assert.True(t, foundShared)
	assert.True(t, foundTmp)

	// Verify main container mount
	assert.Len(t, mutated.Spec.Containers[0].VolumeMounts, 1)
	assert.Equal(t, "/var/log", mutated.Spec.Containers[0].VolumeMounts[0].MountPath)

	// Verify Native Sidecar in InitContainers
	assert.Len(t, mutated.Spec.InitContainers, 1)
	sidecar := mutated.Spec.InitContainers[0]
	assert.Equal(t, "pii-shield-sidecar", sidecar.Name)
	assert.Equal(t, corev1.ContainerRestartPolicyAlways, *sidecar.RestartPolicy)

	// Verify Security Context
	assert.NotNil(t, sidecar.SecurityContext)
	assert.True(t, *sidecar.SecurityContext.RunAsNonRoot)
	assert.True(t, *sidecar.SecurityContext.ReadOnlyRootFilesystem)
	assert.False(t, *sidecar.SecurityContext.AllowPrivilegeEscalation)

	// Verify Resources
	cpuLimit, ok := sidecar.Resources.Limits[corev1.ResourceCPU]
	assert.True(t, ok)
	assert.Equal(t, "100m", cpuLimit.String())
}

func TestGetTargetContainerIndex(t *testing.T) {
	mutator := &PodMutator{}
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "istio-proxy"},
				{Name: "app"},
			},
		},
	}
	idx := mutator.getTargetContainerIndex(pod, "app")
	assert.Equal(t, 1, idx)
}

func TestInjectPipeMode_NoOriginalCommand(t *testing.T) {
	mutator := &PodMutator{}
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app"}, // missing command
			},
		},
	}
	policy := &piishieldv1alpha1.PiiPolicy{
		Spec: piishieldv1alpha1.PiiPolicySpec{
			InjectionMode: "pipe",
		},
	}
	_, err := mutator.injectPipeMode(pod, policy, "app")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "originalCommand is required")
}

func TestInjectPipeMode(t *testing.T) {
	mutator := &PodMutator{
		LegacySidecarMode: true,
	}
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Command: []string{"node", "app.js"}},
			},
		},
	}
	policy := &piishieldv1alpha1.PiiPolicy{
		Spec: piishieldv1alpha1.PiiPolicySpec{
			InjectionMode: "pipe",
		},
	}
	mutated, err := mutator.injectPipeMode(pod, policy, "app")
	assert.NoError(t, err)

	// Contains init container for mkfifo
	assert.Len(t, mutated.Spec.InitContainers, 1)
	assert.Equal(t, "pii-mkfifo", mutated.Spec.InitContainers[0].Name)
	joinedArgs := strings.Join(mutated.Spec.InitContainers[0].Args, " ")
	assert.Contains(t, joinedArgs, "mkfifo /shared/log.pipe")

	// Main container command wrapped
	mainApp := mutated.Spec.Containers[0]
	assert.Equal(t, []string{"/bin/sh", "-c"}, mainApp.Command)
	assert.Equal(t, []string{"exec node app.js > /shared/log.pipe"}, mainApp.Args)

	// Sidecar was injected to Containers since LegacySidecarMode = true
	assert.Len(t, mutated.Spec.Containers, 2)
	sidecar := mutated.Spec.Containers[1]
	assert.Equal(t, "pii-shield-sidecar", sidecar.Name)
}
