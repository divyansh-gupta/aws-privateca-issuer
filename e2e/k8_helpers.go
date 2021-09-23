package main

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmclientv1 "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"

	clientV1beta1 "github.com/cert-manager/aws-privateca-issuer/pkg/clientset/v1beta1"

	"k8s.io/apimachinery/pkg/util/wait"
)

func waitForIssuerStatus(client *clientV1beta1.V1Beta1Client, ctx context.Context, name string, namespace string) error {
	return wait.PollImmediate(500*time.Millisecond, time.Minute,
		func() (bool, error) {

			issuer, err := client.AWSPCAIssuers(namespace).Get(ctx, name, metav1.GetOptions{})

			if err != nil {
				return false, fmt.Errorf("error getting Issuer %q: %v", name, err)
			}
			if issuer.Status.Conditions[0].Status != metav1.ConditionTrue {
				return true, nil
			}
			return false, nil
		})
}

func waitForClusterIssuerStatus(client *clientV1beta1.V1Beta1Client, ctx context.Context, name string) error {
	return wait.PollImmediate(500*time.Millisecond, time.Minute,
		func() (bool, error) {

			issuer, err := client.AWSPCAClusterIssuers().Get(ctx, name, metav1.GetOptions{})

			if err != nil {
				return false, fmt.Errorf("error getting Cluster Issuer %q: %v", name, err)
			}
			if issuer.Status.Conditions[0].Status != metav1.ConditionTrue {
				return true, nil
			}
			return false, nil
		})
}

func waitForCertificateStatus(client *cmclientv1.CertmanagerV1Client, ctx context.Context, name string, namespace string) error {
	return wait.PollImmediate(500*time.Millisecond, time.Minute,
		func() (bool, error) {

			certificate, err := client.Certificates(namespace).Get(ctx, name, metav1.GetOptions{})

			if err != nil {
				return false, fmt.Errorf("error getting Certificate %q: %v", name, err)
			}
			if certificate.Status.Conditions[0].Status != v1.ConditionTrue {
				return true, nil
			}
			return false, nil
		})

}
