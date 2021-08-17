// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Auth Tokens in Oracle Cloud Infrastructure Identity service.
//
// Lists the auth tokens for the specified user. The returned object contains the token's OCID, but not
// the token itself. The actual token is returned only upon creation.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := oci.GetIdentityAuthTokens(ctx, &GetIdentityAuthTokensArgs{
// 			UserId: oci_identity_user.Test_user.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetIdentityAuthTokens(ctx *pulumi.Context, args *GetIdentityAuthTokensArgs, opts ...pulumi.InvokeOption) (*GetIdentityAuthTokensResult, error) {
	var rv GetIdentityAuthTokensResult
	err := ctx.Invoke("oci:index/getIdentityAuthTokens:GetIdentityAuthTokens", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetIdentityAuthTokens.
type GetIdentityAuthTokensArgs struct {
	Filters []GetIdentityAuthTokensFilter `pulumi:"filters"`
	// The OCID of the user.
	UserId string `pulumi:"userId"`
}

// A collection of values returned by GetIdentityAuthTokens.
type GetIdentityAuthTokensResult struct {
	Filters []GetIdentityAuthTokensFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of tokens.
	Tokens []GetIdentityAuthTokensToken `pulumi:"tokens"`
	// The OCID of the user the auth token belongs to.
	UserId string `pulumi:"userId"`
}