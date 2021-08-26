// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Authentication Policy resource in Oracle Cloud Infrastructure Identity service.
//
// Gets the authentication policy for the given tenancy. You must specify your tenant’s OCID as the value for
// the compartment ID (remember that the tenancy is simply the root compartment).
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/identity"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := identity.LookupAuthenticationPolicy(ctx, &identity.LookupAuthenticationPolicyArgs{
// 			CompartmentId: _var.Tenancy_ocid,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupAuthenticationPolicy(ctx *pulumi.Context, args *LookupAuthenticationPolicyArgs, opts ...pulumi.InvokeOption) (*LookupAuthenticationPolicyResult, error) {
	var rv LookupAuthenticationPolicyResult
	err := ctx.Invoke("oci:identity/getAuthenticationPolicy:getAuthenticationPolicy", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAuthenticationPolicy.
type LookupAuthenticationPolicyArgs struct {
	// The OCID of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
}

// A collection of values returned by getAuthenticationPolicy.
type LookupAuthenticationPolicyResult struct {
	// Compartment OCID.
	CompartmentId string `pulumi:"compartmentId"`
	Id            string `pulumi:"id"`
	// Network policy, Consists of a list of Network Source ids.
	NetworkPolicy GetAuthenticationPolicyNetworkPolicy `pulumi:"networkPolicy"`
	// Password policy, currently set for the given compartment.
	PasswordPolicy GetAuthenticationPolicyPasswordPolicy `pulumi:"passwordPolicy"`
}
