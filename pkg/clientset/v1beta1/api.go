package v1beta1

import (
	api "github.com/cert-manager/aws-privateca-issuer/pkg/api/v1beta1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

type V1Beta1Interface interface {
	AWSPCAIssuers(namespace string) AWSPCAIssuerInterface
	AWSPCAClusterIssuers() AWSPCAClusterIssuerInterface
}

type V1Beta1Client struct {
	restClient rest.Interface
}

func NewForConfig(c *rest.Config) (*V1Beta1Client, error) {
	AddToScheme(scheme.Scheme)

	config := *c
	config.ContentConfig.GroupVersion = &api.GroupVersion
	config.APIPath = "/apis"
	config.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
	config.UserAgent = rest.DefaultKubernetesUserAgent()

	client, err := rest.RESTClientFor(&config)
	if err != nil {
		return nil, err
	}

	return &V1Beta1Client{restClient: client}, nil
}

func (c *V1Beta1Client) AWSPCAIssuers(namespace string) AWSPCAIssuerInterface {
	return &awspcaIssuerClient{
		restClient: c.restClient,
		ns:         namespace,
	}
}

func (c *V1Beta1Client) AWSPCAClusterIssuers() AWSPCAClusterIssuerInterface {
	return &awspcaClusterIssuerClient{
		restClient: c.restClient,
	}
}
