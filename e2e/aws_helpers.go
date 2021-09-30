package main

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/aws/aws-sdk-go-v2/service/acmpca/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

type StatementEntry struct {
	Effect   string
	Action   []string
	Resource string
}

type PolicyDocument struct {
	Version   string
	Statement []StatementEntry
}

func createUser(iamClient *iam.Client, ctx context.Context) (string, string) {
	policy := PolicyDocument{
		Version: "2012-10-17",
		Statement: []StatementEntry{
			{
				Effect: "Allow",
				Action: []string{
					"acm-pca:DescribeCertificateAuthority",
					"acm-pca:GetCertificate",
					"acm-pca:IssueCertificate",
				},
				Resource: "*",
			},
		},
	}

	policyJson, err := json.Marshal(&policy)
	if err != nil {
		panic(err.Error())
	}

	policyName := "CMPolicy" + strconv.FormatInt(time.Now().Unix(), 10)

	policyParams := iam.CreatePolicyInput{
		PolicyName:     aws.String(policyName),
		PolicyDocument: aws.String(string(policyJson)),
	}

	policyOutput, policyErr := iamClient.CreatePolicy(ctx, &policyParams)

	if policyErr != nil {
		panic(policyErr.Error())
	}

	policyArn := policyOutput.Policy.Arn

	userName := "CMUser" + strconv.FormatInt(time.Now().Unix(), 10)

	userParams := iam.CreateUserInput{
		UserName:            aws.String(userName),
		PermissionsBoundary: policyArn,
	}

	_, userErr := iamClient.CreateUser(ctx, &userParams)

	if userErr != nil {
		panic(userErr.Error())
	}

	attachParams := iam.AttachUserPolicyInput{
		UserName:  aws.String(userName),
		PolicyArn: policyOutput.Policy.Arn,
	}

	_, attachErr := iamClient.AttachUserPolicy(ctx, &attachParams)

	if attachErr != nil {
		panic(attachErr.Error())
	}

	return userName, *policyArn
}

func createAccessKey(iamClient *iam.Client, ctx context.Context, userName string) (string, string) {
	createKeyParams := iam.CreateAccessKeyInput{
		UserName: aws.String(userName),
	}

	createKeyOutput, createKeyErr := iamClient.CreateAccessKey(ctx, &createKeyParams)

	if createKeyErr != nil {
		panic(createKeyErr.Error())
	}

	return *createKeyOutput.AccessKey.AccessKeyId, *createKeyOutput.AccessKey.SecretAccessKey
}

func deleteUser(iamClient *iam.Client, ctx context.Context, userName string, policyArn string) {
	detachParams := iam.DetachUserPolicyInput{
		UserName:  aws.String(userName),
		PolicyArn: aws.String(policyArn),
	}

	_, detachErr := iamClient.DetachUserPolicy(ctx, &detachParams)

	if detachErr != nil {
		panic(detachErr.Error())
	}

	deleteParams := iam.DeleteUserInput{
		UserName: aws.String(userName),
	}

	_, deleteErr := iamClient.DeleteUser(ctx, &deleteParams)

	if deleteErr != nil {
		panic(deleteErr.Error())
	}
}

func deleteAccessKey(iamClient *iam.Client, ctx context.Context, userName string, accessKey string) {
	deleteKeyParams := iam.DeleteAccessKeyInput{
		AccessKeyId: aws.String(accessKey),
		UserName:    aws.String(userName),
	}

	_, deleteKeyErr := iamClient.DeleteAccessKey(ctx, &deleteKeyParams)

	if deleteKeyErr != nil {
		panic(deleteKeyErr.Error())
	}
}

func deleteCertificateAuthority(pcaClient *acmpca.Client, ctx context.Context, caArn string) {
	updateCAParams := acmpca.UpdateCertificateAuthorityInput{
		CertificateAuthorityArn: &caArn,
		Status:                  types.CertificateAuthorityStatusDisabled,
	}

	_, updateErr := pcaClient.UpdateCertificateAuthority(ctx, &updateCAParams)

	if updateErr != nil {
		panic(updateErr.Error())
	}

	deleteCAParams := acmpca.DeleteCertificateAuthorityInput{
		CertificateAuthorityArn:     &caArn,
		PermanentDeletionTimeInDays: aws.Int32(7),
	}

	_, deleteErr := pcaClient.DeleteCertificateAuthority(ctx, &deleteCAParams)

	if deleteErr != nil {
		panic(deleteErr.Error())
	}

}

func createCertificateAuthority(pcaClient *acmpca.Client, ctx context.Context, isRSA bool) string {
	var signingAlgorithm types.SigningAlgorithm
	var keyAlgorithm types.KeyAlgorithm

	if isRSA {
		signingAlgorithm = types.SigningAlgorithmSha256withrsa
		keyAlgorithm = types.KeyAlgorithmRsa2048
	} else {
		signingAlgorithm = types.SigningAlgorithmSha256withecdsa
		keyAlgorithm = types.KeyAlgorithmEcPrime256v1
	}

	commonName := "CMTest-" + strconv.FormatInt(time.Now().Unix(), 10)

	createCertificateAuthorityParams := acmpca.CreateCertificateAuthorityInput{
		CertificateAuthorityType: types.CertificateAuthorityTypeRoot,
		CertificateAuthorityConfiguration: &types.CertificateAuthorityConfiguration{
			KeyAlgorithm:     keyAlgorithm,
			SigningAlgorithm: signingAlgorithm,
			Subject: &types.ASN1Subject{
				CommonName: aws.String(commonName),
			},
		},
	}

	createOutput, createErr := pcaClient.CreateCertificateAuthority(ctx, &createCertificateAuthorityParams)

	if createErr != nil {
		panic(createErr.Error())
	}

	caArn := createOutput.CertificateAuthorityArn

	getCsrParams := acmpca.GetCertificateAuthorityCsrInput{
		CertificateAuthorityArn: caArn,
	}

	csrWaiter := acmpca.NewCertificateAuthorityCSRCreatedWaiter(pcaClient)
	csrWaiterErr := csrWaiter.Wait(ctx, &getCsrParams, 1*time.Minute)

	if csrWaiterErr != nil {
		panic(csrWaiterErr.Error())
	}

	csrOutput, csrErr := pcaClient.GetCertificateAuthorityCsr(ctx, &getCsrParams)

	if csrErr != nil {
		panic(csrErr.Error())
	}

	caCsr := csrOutput.Csr

	issuerCertificateParms := acmpca.IssueCertificateInput{
		CertificateAuthorityArn: caArn,
		Csr:                     []byte(*caCsr),
		SigningAlgorithm:        signingAlgorithm,
		TemplateArn:             aws.String("arn:aws:acm-pca:::template/RootCACertificate/V1"),
		Validity: &types.Validity{
			Type:  types.ValidityPeriodTypeDays,
			Value: aws.Int64(365),
		},
	}

	issueOutput, issueErr := pcaClient.IssueCertificate(ctx, &issuerCertificateParms)

	if issueErr != nil {
		panic(issueErr.Error())
	}

	caCertArn := issueOutput.CertificateArn

	getCertParams := acmpca.GetCertificateInput{
		CertificateArn:          caCertArn,
		CertificateAuthorityArn: caArn,
	}

	certWaiter := acmpca.NewCertificateIssuedWaiter(pcaClient)
	certWaiterErr := certWaiter.Wait(ctx, &getCertParams, 2*time.Minute)

	if certWaiterErr != nil {
		panic(certWaiterErr.Error())
	}

	getCertOutput, getCertErr := pcaClient.GetCertificate(ctx, &getCertParams)
	if getCertErr != nil {
		panic(getCertErr.Error())
	}

	certPem := []byte(*getCertOutput.Certificate)

	importCertParms := acmpca.ImportCertificateAuthorityCertificateInput{
		Certificate:             certPem,
		CertificateAuthorityArn: caArn,
	}

	_, importCertErr := pcaClient.ImportCertificateAuthorityCertificate(ctx, &importCertParms)

	if importCertErr != nil {
		panic(importCertErr.Error())
	}

	return *caArn
}
