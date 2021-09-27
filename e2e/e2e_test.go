package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	cmv1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmclientv1 "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	"github.com/stretchr/testify/assert"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/cert-manager/aws-privateca-issuer/pkg/api/v1beta1"
	clientV1beta1 "github.com/cert-manager/aws-privateca-issuer/pkg/clientset/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

var (
	iclient   *clientV1beta1.V1Beta1Client
	cmClient  *cmclientv1.CertmanagerV1Client
	clientset *kubernetes.Clientset

	rsaCaArn, ecCaArn, accessKey, secretKey, userName, policyArn string

	region = "us-east-1"
	ctx    = context.TODO()
)

func TestMain(m *testing.M) {
	//setup k8 client
	//kubeconfig files will be gathered from the home directory
	home := homedir.HomeDir()
	kubeconfig := filepath.Join(home, ".kube", "config")

	clientConfig, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	clientset, err = kubernetes.NewForConfig(clientConfig)
	if err != nil {
		panic(err.Error())
	}

	//setup pca client
	var cfg, cfgErr = config.LoadDefaultConfig(ctx, config.WithRegion(region))

	if cfgErr != nil {
		panic(cfgErr.Error())
	}

	pcaClient := acmpca.NewFromConfig(cfg)

	iclient, err = clientV1beta1.NewForConfig(clientConfig)

	if err != nil {
		panic(err.Error())
	}

	cmClient, err = cmclientv1.NewForConfig(clientConfig)

	if err != nil {
		panic(err.Error())
	}

	//Create an EC CA and a RSA CA
	rsaCaArn = createCertificateAuthority(pcaClient, ctx, true)
	log.Printf("Created RSA CA with arn %s", rsaCaArn)

	ecCaArn = createCertificateAuthority(pcaClient, ctx, false)
	log.Printf("Created EC CA with arn %s", ecCaArn)

	//Create an Access Key to be used for validiting auth via secret for an Issuer
	iamClient := iam.NewFromConfig(cfg)
	accessKey, secretKey, userName, policyArn = createAccessKey(iamClient, ctx)

	log.Printf("Created User %s with policy arn %s", userName, policyArn)
	//Run the tests
	exitVal := m.Run()

	//Delete CAs used during test
	deleteCertificateAuthority(pcaClient, ctx, rsaCaArn)
	log.Printf("Deleted the RSA CA")

	deleteCertificateAuthority(pcaClient, ctx, ecCaArn)
	log.Printf("Delete the EC CA")

	//Delete IAM User and policy
	deleteAccessKey(iamClient, ctx, userName, accessKey, policyArn)
	log.Printf("Deleted the Access Key")

	//Exit
	os.Exit(exitVal)
}

func TestClusterIssuers(t *testing.T) {

	currentTime := strconv.FormatInt(time.Now().Unix(), 10)

	secretName := "pca-cluster-issuer-secret-" + currentTime

	data := make(map[string][]byte)
	data["AWS_ACCESS_KEY_ID"] = []byte(accessKey)
	data["AWS_SECRET_ACCESS_KEY"] = []byte(secretKey)

	secret := v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName},
		Data:       data,
	}

	_, err := clientset.CoreV1().Secrets("default").Create(ctx, &secret, metav1.CreateOptions{})

	if err != nil {
		assert.FailNow(t, "Failed to create cluster issuer secret"+err.Error())
	}

	rsaClusterIssuer := v1beta1.AWSPCAClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "rsa-cluster-issuer-" + currentTime},
		Spec: v1beta1.AWSPCAIssuerSpec{
			Arn:    rsaCaArn,
			Region: region,
			SecretRef: v1beta1.AWSCredentialsSecretReference{
				SecretReference: v1.SecretReference{
					Name:      secretName,
					Namespace: "default",
				},
			},
		},
	}

	ecClusterIssuer := v1beta1.AWSPCAClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "ec-cluster-issuer-" + currentTime},
		Spec: v1beta1.AWSPCAIssuerSpec{
			Arn:    ecCaArn,
			Region: region,
			SecretRef: v1beta1.AWSCredentialsSecretReference{
				SecretReference: v1.SecretReference{
					Name:      secretName,
					Namespace: "default",
				},
			},
		},
	}

	clusterIssuers := []v1beta1.AWSPCAClusterIssuer{rsaClusterIssuer, ecClusterIssuer}

	for _, clusterIssuer := range clusterIssuers {

		issuerName := clusterIssuer.ObjectMeta.Name

		log.Printf("Testing issuer: %s", issuerName)

		_, err := iclient.AWSPCAClusterIssuers().Create(ctx, &clusterIssuer, metav1.CreateOptions{})

		if err != nil {
			assert.FailNow(t, "Could not create Cluster Issuer: "+err.Error())
		}

		err = waitForClusterIssuerReady(iclient, ctx, issuerName)

		if err != nil {
			assert.FailNow(t, "Cluster issuer did not reach a ready state: "+err.Error())
		}

		ecCertificate := cmv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: issuerName + "-ec-cert"},
			Spec: cmv1.CertificateSpec{
				Subject: &cmv1.X509Subject{
					Organizations: []string{"aws"},
				},
				DNSNames: []string{issuerName + "-ec-example.com"},
				PrivateKey: &cmv1.CertificatePrivateKey{
					Algorithm: cmv1.ECDSAKeyAlgorithm,
					Size:      256,
				},
				Duration: &metav1.Duration{
					Duration: 1000000000 * 60 * 60 * 800, //80 hours
				},
				SecretName: issuerName + "-ec-cert-tls",
				IssuerRef: cmmeta.ObjectReference{
					Kind:  "AWSPCAClusterIssuer",
					Group: "awspca.cert-manager.io",
					Name:  issuerName,
				},
			},
		}

		rsaCertificate := cmv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: issuerName + "-rsa-cert"},
			Spec: cmv1.CertificateSpec{
				Subject: &cmv1.X509Subject{
					Organizations: []string{"aws"},
				},
				DNSNames: []string{issuerName + "-rsa-example.com"},
				PrivateKey: &cmv1.CertificatePrivateKey{
					Algorithm: cmv1.RSAKeyAlgorithm,
					Size:      2048,
				},
				Duration: &metav1.Duration{
					Duration: 1000000000 * 60 * 60 * 800, //80 hours
				},
				SecretName: issuerName + "-rsa-cert-tls",
				IssuerRef: cmmeta.ObjectReference{
					Kind:  "AWSPCAClusterIssuer",
					Group: "awspca.cert-manager.io",
					Name:  issuerName,
				},
			},
		}

		certificates := []cmv1.Certificate{ecCertificate, rsaCertificate}

		for _, certificate := range certificates {

			certName := certificate.ObjectMeta.Name

			log.Printf("Testing Certificate %s", certName)

			_, err = cmClient.Certificates("default").Create(ctx, &certificate, metav1.CreateOptions{})

			if err != nil {
				assert.FailNow(t, "Could not create certificate: "+err.Error())
			}

			err = waitForCertificateReady(cmClient, ctx, certName, "default")

			if err != nil {
				assert.FailNow(t, "Certificate did not reach a ready state: "+err.Error())
			}

			err = cmClient.Certificates("default").Delete(ctx, certName, metav1.DeleteOptions{})

			if err != nil {
				assert.FailNow(t, "Certificate was not succesfully deleted: "+err.Error())
			}
		}

		err = iclient.AWSPCAClusterIssuers().Delete(ctx, issuerName, metav1.DeleteOptions{})

		if err != nil {
			assert.FailNow(t, "Issuer was not successfully deleted: "+err.Error())
		}
	}
}

func TestNamespaceIssuers(t *testing.T) {

	currentTime := strconv.FormatInt(time.Now().Unix(), 10)

	// Create namespace for issuer to live in
	namespaceName := "pca-issuer-namespace-" + currentTime

	namespace := v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespaceName},
	}

	_, err := clientset.CoreV1().Namespaces().Create(ctx, &namespace, metav1.CreateOptions{})

	secretName := "pca-namespace-issuer-secret-" + currentTime

	data := make(map[string][]byte)
	data["AWS_ACCESS_KEY_ID"] = []byte(accessKey)
	data["AWS_SECRET_ACCESS_KEY"] = []byte(secretKey)

	secret := v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName},
		Data:       data,
	}

	_, err = clientset.CoreV1().Secrets(namespaceName).Create(ctx, &secret, metav1.CreateOptions{})

	if err != nil {
		assert.FailNow(t, "Failed to create namespace issuer secret"+err.Error())
	}

	rsaClusterIssuer := v1beta1.AWSPCAIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "rsa-namespace-issuer-" + currentTime},
		Spec: v1beta1.AWSPCAIssuerSpec{
			Arn:    rsaCaArn,
			Region: region,
			SecretRef: v1beta1.AWSCredentialsSecretReference{
				SecretReference: v1.SecretReference{
					Name:      secretName,
					Namespace: namespaceName,
				},
			},
		},
	}

	ecClusterIssuer := v1beta1.AWSPCAIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "ec-namespace-issuer-" + currentTime},
		Spec: v1beta1.AWSPCAIssuerSpec{
			Arn:    ecCaArn,
			Region: region,
			SecretRef: v1beta1.AWSCredentialsSecretReference{
				SecretReference: v1.SecretReference{
					Name:      secretName,
					Namespace: namespaceName,
				},
			},
		},
	}

	clusterIssuers := []v1beta1.AWSPCAIssuer{rsaClusterIssuer, ecClusterIssuer}

	for _, clusterIssuer := range clusterIssuers {

		issuerName := clusterIssuer.ObjectMeta.Name

		log.Printf("Testing issuer: %s", issuerName)

		_, err := iclient.AWSPCAIssuers(namespaceName).Create(ctx, &clusterIssuer, metav1.CreateOptions{})

		if err != nil {
			assert.FailNow(t, "Could not create Namespace Issuer: "+err.Error())
		}

		err = waitForIssuerReady(iclient, ctx, issuerName, namespaceName)

		if err != nil {
			assert.FailNow(t, "Namespace issuer did not reach a ready state: "+err.Error())
		}

		ecCertificate := cmv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: issuerName + "-ec-cert", Namespace: namespaceName},
			Spec: cmv1.CertificateSpec{
				Subject: &cmv1.X509Subject{
					Organizations: []string{"aws"},
				},
				DNSNames: []string{issuerName + "-ec-example.com"},
				PrivateKey: &cmv1.CertificatePrivateKey{
					Algorithm: cmv1.ECDSAKeyAlgorithm,
					Size:      256,
				},
				Duration: &metav1.Duration{
					Duration: 1000000000 * 60 * 60 * 800, //80 hours
				},
				SecretName: issuerName + "-ec-cert-tls",
				IssuerRef: cmmeta.ObjectReference{
					Kind:  "AWSPCAIssuer",
					Group: "awspca.cert-manager.io",
					Name:  issuerName,
				},
			},
		}

		rsaCertificate := cmv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: issuerName + "-rsa-cert", Namespace: namespaceName},
			Spec: cmv1.CertificateSpec{
				Subject: &cmv1.X509Subject{
					Organizations: []string{"aws"},
				},
				DNSNames: []string{issuerName + "-rsa-example.com"},
				PrivateKey: &cmv1.CertificatePrivateKey{
					Algorithm: cmv1.RSAKeyAlgorithm,
					Size:      2048,
				},
				Duration: &metav1.Duration{
					Duration: 1000000000 * 60 * 60 * 800, //80 hours
				},
				SecretName: issuerName + "-rsa-cert-tls",
				IssuerRef: cmmeta.ObjectReference{
					Kind:  "AWSPCAIssuer",
					Group: "awspca.cert-manager.io",
					Name:  issuerName,
				},
			},
		}

		certificates := []cmv1.Certificate{ecCertificate, rsaCertificate}

		for _, certificate := range certificates {

			certName := certificate.ObjectMeta.Name

			log.Printf("Testing Certificate %s", certName)

			_, err = cmClient.Certificates(namespaceName).Create(ctx, &certificate, metav1.CreateOptions{})

			if err != nil {
				assert.FailNow(t, "Could not create certificate: "+err.Error())
			}

			err = waitForCertificateReady(cmClient, ctx, certName, namespaceName)

			if err != nil {
				assert.FailNow(t, "Certificate did not reach a ready state: "+err.Error())
			}

			err = cmClient.Certificates(namespaceName).Delete(ctx, certName, metav1.DeleteOptions{})

			if err != nil {
				assert.FailNow(t, "Certificate was not succesfully deleted: "+err.Error())
			}
		}

		err = iclient.AWSPCAIssuers(namespaceName).Delete(ctx, issuerName, metav1.DeleteOptions{})

		if err != nil {
			assert.FailNow(t, "Issuer was not successfully deleted: "+err.Error())
		}
	}
}
