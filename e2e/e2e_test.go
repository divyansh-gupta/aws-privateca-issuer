package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"testing"

	cmv1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmclientv1 "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"

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

var iclient *clientV1beta1.V1Beta1Client
var cmClient *cmclientv1.CertmanagerV1Client
var clientset *kubernetes.Clientset
var region = "us-east-1"
var ctx = context.TODO()

var rsaCaArn string
var accessKey string
var secretKey string

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

	//ecCaArn := createCertificateAuthority(false)
	//log.Printf("Created EC CA with arn %s", ecCaArn)

	//Create an Access Key to be used for validiting auth via secret for an Issuer
	iamClient := iam.NewFromConfig(cfg)
	accessKey, secretKey, userName, policyArn := createAccessKey(iamClient, ctx)

	log.Printf("%s %s %s %s", accessKey, secretKey, userName, policyArn)
	//Run the tests
	exitVal := m.Run()

	//Delete CAs used during test
	deleteCertificateAuthority(pcaClient, ctx, rsaCaArn)
	//deleteCertificateAuthority(ecCaArn)

	//Delete IAM User and policy
	deleteAccessKey(iamClient, ctx, userName, policyArn)

	//Exit
	os.Exit(exitVal)
}

func TestHelloWorld(t *testing.T) {

	secretName := "pca-secret-tester"
	issuerName := "pca-issuer-tester"
	certName := "pca-issuer-cert"

	data := make(map[string][]byte)
	data["AWS_ACCESS_KEY_ID"] = []byte(accessKey)
	data["AWS_SECRET_ACCESS_KEY"] = []byte(secretKey)

	secret := v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName},
		Data:       data,
	}

	clientset.CoreV1().Secrets("default").Create(ctx, &secret, metav1.CreateOptions{})

	clusterIssuer := v1beta1.AWSPCAClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: issuerName},
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

	_, err := iclient.AWSPCAClusterIssuers().Create(ctx, &clusterIssuer, metav1.CreateOptions{})

	if err != nil {
		panic(err.Error())
	}

	err = waitForClusterIssuerStatus(iclient, ctx, issuerName)

	if err != nil {
		panic(err.Error())
	}

	certificate := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: certName},
		Spec: cmv1.CertificateSpec{
			Subject: &cmv1.X509Subject{
				Organizations: []string{"aws"},
			},
			DNSNames: []string{"cluster-issuer-ec-example.com"},
			PrivateKey: &cmv1.CertificatePrivateKey{
				Algorithm: cmv1.ECDSAKeyAlgorithm,
				Size:      256,
			},
			Duration: &metav1.Duration{
				Duration: 1000000000 * 60 * 60 * 800, //80 hours
			},
			SecretName: "pca-cluster-issuer-ec-cert-tls",
			IssuerRef: cmmeta.ObjectReference{
				Kind:  "AWSPCAClusterIssuer",
				Group: "awspca.cert-manager.io",
				Name:  issuerName,
			},
		},
	}

	_, err = cmClient.Certificates("default").Create(ctx, &certificate, metav1.CreateOptions{})

	if err != nil {
		panic(err.Error())
	}

	err = waitForCertificateStatus(cmClient, ctx, certName, "default")

	if err != nil {
		panic(err.Error())
	}
}
