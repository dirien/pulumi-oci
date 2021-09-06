// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package email

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Dkims in Oracle Cloud Infrastructure Email service.
//
// Lists DKIMs for a email domain.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/email"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		opt0 := _var.Dkim_id
// 		opt1 := _var.Dkim_name
// 		opt2 := _var.Dkim_state
// 		_, err := email.GetDkims(ctx, &email.GetDkimsArgs{
// 			EmailDomainId: oci_email_email_domain.Test_email_domain.Id,
// 			Id:            &opt0,
// 			Name:          &opt1,
// 			State:         &opt2,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetDkims(ctx *pulumi.Context, args *GetDkimsArgs, opts ...pulumi.InvokeOption) (*GetDkimsResult, error) {
	var rv GetDkimsResult
	err := ctx.Invoke("oci:email/getDkims:getDkims", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDkims.
type GetDkimsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the email domain to which this DKIM belongs.
	EmailDomainId string           `pulumi:"emailDomainId"`
	Filters       []GetDkimsFilter `pulumi:"filters"`
	// A filter to only return resources that match the given id exactly.
	Id *string `pulumi:"id"`
	// A filter to only return resources that match the given name exactly.
	Name *string `pulumi:"name"`
	// Filter returned list by specified lifecycle state. This parameter is case-insensitive.
	State *string `pulumi:"state"`
}

// A collection of values returned by getDkims.
type GetDkimsResult struct {
	// The list of dkim_collection.
	DkimCollections []GetDkimsDkimCollection `pulumi:"dkimCollections"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the email domain that this DKIM belongs to.
	EmailDomainId string           `pulumi:"emailDomainId"`
	Filters       []GetDkimsFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DKIM.
	Id *string `pulumi:"id"`
	// The DKIM selector. If the same domain is managed in more than one region, each region must use different selectors.
	Name *string `pulumi:"name"`
	// The current state of the DKIM.
	State *string `pulumi:"state"`
}
