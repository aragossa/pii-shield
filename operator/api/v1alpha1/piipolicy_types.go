/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PiiPolicySpec defines the desired state of PiiPolicy
type PiiPolicySpec struct {
	// FailPolicy determines the behavior on failure
	FailPolicy string `json:"failPolicy,omitempty"`

	// ConfidenceThreshold is the threshold for PII scanner
	ConfidenceThreshold float32 `json:"confidenceThreshold,omitempty"`

	// InjectionMode defines the mode: "file", "pipe", or "ebpf"
	// +kubebuilder:validation:Enum=file;pipe;ebpf
	InjectionMode string `json:"injectionMode"`

	// LogPath is the path where the application writes logs (for "file" mode)
	LogPath string `json:"logPath,omitempty"`

	// OriginalCommand is the original app command (for "pipe" mode)
	OriginalCommand string `json:"originalCommand,omitempty"`

	// Resources allows configuration of compute resources for the injected sidecar
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
}

// PiiPolicyStatus defines the observed state of PiiPolicy.
type PiiPolicyStatus struct {
	// conditions represent the current state of the PiiPolicy resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// Standard condition types include:
	// - "Available": the resource is fully functional
	// - "Progressing": the resource is being created or updated
	// - "Degraded": the resource failed to reach or maintain its desired state
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// PiiPolicy is the Schema for the piipolicies API
type PiiPolicy struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of PiiPolicy
	// +required
	Spec PiiPolicySpec `json:"spec"`

	// status defines the observed state of PiiPolicy
	// +optional
	Status PiiPolicyStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// PiiPolicyList contains a list of PiiPolicy
type PiiPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []PiiPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PiiPolicy{}, &PiiPolicyList{})
}
