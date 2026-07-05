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

package controller

import (
	"context"
	"fmt"
	"reflect"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	corev1alpha1 "github.com/pii-shield/pii-shield/operator/api/v1alpha1"
)

// PiiPolicyReconciler reconciles a PiiPolicy object
type PiiPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=core.pii-shield.io,resources=piipolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core.pii-shield.io,resources=piipolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core.pii-shield.io,resources=piipolicies/finalizers,verbs=update

// Reconcile validates a PiiPolicy enough to expose an auditable status without
// mutating the user's desired spec.
func (r *PiiPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	policy := &corev1alpha1.PiiPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	effectiveMode := policy.Spec.InjectionMode
	if effectiveMode == "" {
		effectiveMode = "file"
	}

	condition := metav1.Condition{
		Type:               "Available",
		Status:             metav1.ConditionTrue,
		Reason:             "PolicyAccepted",
		Message:            fmt.Sprintf("Policy is accepted. Effective injection mode: %s", effectiveMode),
		ObservedGeneration: policy.Generation,
	}

	switch effectiveMode {
	case "file", "pipe", "ebpf":
	default:
		condition.Status = metav1.ConditionFalse
		condition.Reason = "InvalidInjectionMode"
		condition.Message = fmt.Sprintf("Unsupported injection mode: %s", effectiveMode)
	}

	oldConditions := append([]metav1.Condition(nil), policy.Status.Conditions...)
	meta.SetStatusCondition(&policy.Status.Conditions, condition)
	if reflect.DeepEqual(oldConditions, policy.Status.Conditions) {
		return ctrl.Result{}, nil
	}

	if err := r.Status().Update(ctx, policy); err != nil {
		log.Error(err, "failed to update PiiPolicy status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PiiPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha1.PiiPolicy{}).
		Named("piipolicy").
		Complete(r)
}
