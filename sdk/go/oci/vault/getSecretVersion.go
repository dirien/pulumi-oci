// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package vault

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Secret Version resource in Oracle Cloud Infrastructure Vault service.
//
// Gets information about the specified version of a secret.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/vault"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := vault.GetSecretVersion(ctx, &vault.GetSecretVersionArgs{
// 			SecretId:            oci_vault_secret.Test_secret.Id,
// 			SecretVersionNumber: _var.Secret_version_secret_version_number,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetSecretVersion(ctx *pulumi.Context, args *GetSecretVersionArgs, opts ...pulumi.InvokeOption) (*GetSecretVersionResult, error) {
	var rv GetSecretVersionResult
	err := ctx.Invoke("oci:vault/getSecretVersion:getSecretVersion", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSecretVersion.
type GetSecretVersionArgs struct {
	// The OCID of the secret.
	SecretId string `pulumi:"secretId"`
	// The version number of the secret.
	SecretVersionNumber string `pulumi:"secretVersionNumber"`
}

// A collection of values returned by getSecretVersion.
type GetSecretVersionResult struct {
	// The content type of the secret version's secret contents.
	ContentType string `pulumi:"contentType"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The name of the secret version. A name is unique across versions of a secret.
	Name string `pulumi:"name"`
	// The OCID of the secret.
	SecretId            string `pulumi:"secretId"`
	SecretVersionNumber string `pulumi:"secretVersionNumber"`
	// A list of possible rotation states for the secret version. A secret version marked `CURRENT` is currently in use. A secret version marked `PENDING` is staged and available for use, but has not been applied on the target system and, therefore, has not been rotated into current, active use. The secret most recently uploaded to a vault is always marked `LATEST`. (The first version of a secret is always marked as both `CURRENT` and `LATEST`.) A secret version marked `PREVIOUS` is the secret version that was most recently marked `CURRENT`, before the last secret version rotation. A secret version marked `DEPRECATED` is neither current, pending, nor the previous one in use. Only secret versions marked `DEPRECATED` can be scheduled for deletion.
	Stages []string `pulumi:"stages"`
	// A optional property indicating when the secret version was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
	// An optional property indicating when the current secret version will expire, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeOfCurrentVersionExpiry string `pulumi:"timeOfCurrentVersionExpiry"`
	// An optional property indicating when to delete the secret version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeOfDeletion string `pulumi:"timeOfDeletion"`
	// The version number of the secret.
	VersionNumber string `pulumi:"versionNumber"`
}
