// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func LookupAutonomousDatabaseWallet(ctx *pulumi.Context, args *LookupAutonomousDatabaseWalletArgs, opts ...pulumi.InvokeOption) (*LookupAutonomousDatabaseWalletResult, error) {
	var rv LookupAutonomousDatabaseWalletResult
	err := ctx.Invoke("oci:database/getAutonomousDatabaseWallet:getAutonomousDatabaseWallet", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAutonomousDatabaseWallet.
type LookupAutonomousDatabaseWalletArgs struct {
	// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	//
	// Deprecated: The 'data.oci_database_autonomous_database_wallet' resource has been deprecated. Please use 'oci_database_autonomous_database_wallet' instead.
	AutonomousDatabaseId string `pulumi:"autonomousDatabaseId"`
	Base64EncodeContent  *bool  `pulumi:"base64EncodeContent"`
	// The type of wallet to generate.
	GenerateType *string `pulumi:"generateType"`
	// The password to encrypt the keys inside the wallet. The password must be at least 8 characters long and must include at least 1 letter and either 1 numeric character or 1 special character.
	Password string `pulumi:"password"`
}

// A collection of values returned by getAutonomousDatabaseWallet.
type LookupAutonomousDatabaseWalletResult struct {
	// Deprecated: The 'data.oci_database_autonomous_database_wallet' resource has been deprecated. Please use 'oci_database_autonomous_database_wallet' instead.
	AutonomousDatabaseId string `pulumi:"autonomousDatabaseId"`
	Base64EncodeContent  *bool  `pulumi:"base64EncodeContent"`
	// content of the downloaded zipped wallet for the Autonomous Database. If `base64EncodeContent` is set to `true`, then this content will be base64 encoded.
	Content      string  `pulumi:"content"`
	GenerateType *string `pulumi:"generateType"`
	// The provider-assigned unique ID for this managed resource.
	Id       string `pulumi:"id"`
	Password string `pulumi:"password"`
}
