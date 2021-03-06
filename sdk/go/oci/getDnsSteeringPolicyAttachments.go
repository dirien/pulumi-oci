// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Steering Policy Attachments in Oracle Cloud Infrastructure DNS service.
//
// Lists the steering policy attachments in the specified compartment.
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
// 		opt0 := _var.Steering_policy_attachment_display_name
// 		opt1 := _var.Steering_policy_attachment_domain
// 		opt2 := _var.Steering_policy_attachment_domain_contains
// 		opt3 := _var.Steering_policy_attachment_id
// 		opt4 := _var.Steering_policy_attachment_state
// 		opt5 := oci_dns_steering_policy.Test_steering_policy.Id
// 		opt6 := _var.Steering_policy_attachment_time_created_greater_than_or_equal_to
// 		opt7 := _var.Steering_policy_attachment_time_created_less_than
// 		opt8 := oci_dns_zone.Test_zone.Id
// 		_, err := oci.GetDnsSteeringPolicyAttachments(ctx, &GetDnsSteeringPolicyAttachmentsArgs{
// 			CompartmentId:                   _var.Compartment_id,
// 			DisplayName:                     &opt0,
// 			Domain:                          &opt1,
// 			DomainContains:                  &opt2,
// 			Id:                              &opt3,
// 			State:                           &opt4,
// 			SteeringPolicyId:                &opt5,
// 			TimeCreatedGreaterThanOrEqualTo: &opt6,
// 			TimeCreatedLessThan:             &opt7,
// 			ZoneId:                          &opt8,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetDnsSteeringPolicyAttachments(ctx *pulumi.Context, args *GetDnsSteeringPolicyAttachmentsArgs, opts ...pulumi.InvokeOption) (*GetDnsSteeringPolicyAttachmentsResult, error) {
	var rv GetDnsSteeringPolicyAttachmentsResult
	err := ctx.Invoke("oci:index/getDnsSteeringPolicyAttachments:GetDnsSteeringPolicyAttachments", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetDnsSteeringPolicyAttachments.
type GetDnsSteeringPolicyAttachmentsArgs struct {
	// The OCID of the compartment the resource belongs to.
	CompartmentId string `pulumi:"compartmentId"`
	// The displayName of a resource.
	DisplayName *string `pulumi:"displayName"`
	// Search by domain. Will match any record whose domain (case-insensitive) equals the provided value.
	Domain *string `pulumi:"domain"`
	// Search by domain. Will match any record whose domain (case-insensitive) contains the provided value.
	DomainContains *string                                 `pulumi:"domainContains"`
	Filters        []GetDnsSteeringPolicyAttachmentsFilter `pulumi:"filters"`
	// The OCID of a resource.
	Id *string `pulumi:"id"`
	// The state of a resource.
	State *string `pulumi:"state"`
	// Search by steering policy OCID. Will match any resource whose steering policy ID matches the provided value.
	SteeringPolicyId *string `pulumi:"steeringPolicyId"`
	// An [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) timestamp that states all returned resources were created on or after the indicated time.
	TimeCreatedGreaterThanOrEqualTo *string `pulumi:"timeCreatedGreaterThanOrEqualTo"`
	// An [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) timestamp that states all returned resources were created before the indicated time.
	TimeCreatedLessThan *string `pulumi:"timeCreatedLessThan"`
	// Search by zone OCID. Will match any resource whose zone ID matches the provided value.
	ZoneId *string `pulumi:"zoneId"`
}

// A collection of values returned by GetDnsSteeringPolicyAttachments.
type GetDnsSteeringPolicyAttachmentsResult struct {
	// The OCID of the compartment containing the steering policy attachment.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name for the steering policy attachment. Does not have to be unique and can be changed. Avoid entering confidential information.
	DisplayName    *string                                 `pulumi:"displayName"`
	Domain         *string                                 `pulumi:"domain"`
	DomainContains *string                                 `pulumi:"domainContains"`
	Filters        []GetDnsSteeringPolicyAttachmentsFilter `pulumi:"filters"`
	// The OCID of the resource.
	Id *string `pulumi:"id"`
	// The current state of the resource.
	State *string `pulumi:"state"`
	// The list of steering_policy_attachments.
	SteeringPolicyAttachments []GetDnsSteeringPolicyAttachmentsSteeringPolicyAttachment `pulumi:"steeringPolicyAttachments"`
	// The OCID of the attached steering policy.
	SteeringPolicyId                *string `pulumi:"steeringPolicyId"`
	TimeCreatedGreaterThanOrEqualTo *string `pulumi:"timeCreatedGreaterThanOrEqualTo"`
	TimeCreatedLessThan             *string `pulumi:"timeCreatedLessThan"`
	// The OCID of the attached zone.
	ZoneId *string `pulumi:"zoneId"`
}
