// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package kms

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Vault resource in Oracle Cloud Infrastructure Kms service.
//
// Gets the specified vault's configuration information.
//
// As a provisioning operation, this call is subject to a Key Management limit that applies to
// the total number of requests across all provisioning read operations. Key Management might
// throttle this call to reject an otherwise valid request when the total rate of provisioning
// read operations exceeds 10 requests per second for a given tenancy.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/kms"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := kms.LookupVault(ctx, &kms.LookupVaultArgs{
// 			VaultId: oci_kms_vault.Test_vault.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupVault(ctx *pulumi.Context, args *LookupVaultArgs, opts ...pulumi.InvokeOption) (*LookupVaultResult, error) {
	var rv LookupVaultResult
	err := ctx.Invoke("oci:kms/getVault:getVault", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getVault.
type LookupVaultArgs struct {
	// The OCID of the vault.
	VaultId string `pulumi:"vaultId"`
}

// A collection of values returned by getVault.
type LookupVaultResult struct {
	// The OCID of the compartment that contains a particular vault.
	CompartmentId string `pulumi:"compartmentId"`
	// The service endpoint to perform cryptographic operations against. Cryptographic operations include [Encrypt](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/EncryptedData/Encrypt), [Decrypt](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/DecryptedData/Decrypt), and [GenerateDataEncryptionKey](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/GeneratedKey/GenerateDataEncryptionKey) operations.
	CryptoEndpoint string `pulumi:"cryptoEndpoint"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// A user-friendly name for the vault. It does not have to be unique, and it is changeable. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The OCID of the vault.
	Id string `pulumi:"id"`
	// A boolean that will be true when vault is primary, and will be false when vault is a replica from a primary vault.
	IsPrimary bool `pulumi:"isPrimary"`
	// The service endpoint to perform management operations against. Management operations include "Create," "Update," "List," "Get," and "Delete" operations.
	ManagementEndpoint string `pulumi:"managementEndpoint"`
	// Vault replica details
	ReplicaDetails GetVaultReplicaDetails `pulumi:"replicaDetails"`
	// Details where vault was backed up.
	RestoreFromFile GetVaultRestoreFromFile `pulumi:"restoreFromFile"`
	// Details where vault was backed up
	RestoreFromObjectStore GetVaultRestoreFromObjectStore `pulumi:"restoreFromObjectStore"`
	// When flipped, triggers restore if restore options are provided. Values of 0 or 1 are supported
	RestoreTrigger bool `pulumi:"restoreTrigger"`
	// The OCID of the vault from which this vault was restored, if it was restored from a backup file.  If you restore a vault to the same region, the vault retains the same OCID that it had when you  backed up the vault.
	RestoredFromVaultId string `pulumi:"restoredFromVaultId"`
	// The vault's current lifecycle state.  Example: `DELETED`
	State string `pulumi:"state"`
	// The date and time this vault was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-04-03T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
	// An optional property to indicate when to delete the vault, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
	TimeOfDeletion string `pulumi:"timeOfDeletion"`
	VaultId        string `pulumi:"vaultId"`
	// The type of vault. Each type of vault stores the key with different degrees of isolation and has different options and pricing.
	VaultType string `pulumi:"vaultType"`
}
