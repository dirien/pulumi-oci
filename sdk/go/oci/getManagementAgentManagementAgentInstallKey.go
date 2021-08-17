// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Management Agent Install Key resource in Oracle Cloud Infrastructure Management Agent service.
//
// Gets complete details of the Agent install Key for a given key id
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
// 		_, err := oci.GetManagementAgentManagementAgentInstallKey(ctx, &GetManagementAgentManagementAgentInstallKeyArgs{
// 			ManagementAgentInstallKeyId: oci_management_agent_management_agent_install_key.Test_management_agent_install_key.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupManagementAgentManagementAgentInstallKey(ctx *pulumi.Context, args *LookupManagementAgentManagementAgentInstallKeyArgs, opts ...pulumi.InvokeOption) (*LookupManagementAgentManagementAgentInstallKeyResult, error) {
	var rv LookupManagementAgentManagementAgentInstallKeyResult
	err := ctx.Invoke("oci:index/getManagementAgentManagementAgentInstallKey:GetManagementAgentManagementAgentInstallKey", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetManagementAgentManagementAgentInstallKey.
type LookupManagementAgentManagementAgentInstallKeyArgs struct {
	// Unique Management Agent Install Key identifier
	ManagementAgentInstallKeyId string `pulumi:"managementAgentInstallKeyId"`
}

// A collection of values returned by GetManagementAgentManagementAgentInstallKey.
type LookupManagementAgentManagementAgentInstallKeyResult struct {
	// Total number of install for this keys
	AllowedKeyInstallCount int `pulumi:"allowedKeyInstallCount"`
	// Compartment Identifier
	CompartmentId string `pulumi:"compartmentId"`
	// Principal id of user who created the Agent Install key
	CreatedByPrincipalId string `pulumi:"createdByPrincipalId"`
	// Total number of install for this keys
	CurrentKeyInstallCount int `pulumi:"currentKeyInstallCount"`
	// Management Agent Install Key Name
	DisplayName string `pulumi:"displayName"`
	// Agent install Key identifier
	Id string `pulumi:"id"`
	// Management Agent Install Key
	Key string `pulumi:"key"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails            string `pulumi:"lifecycleDetails"`
	ManagementAgentInstallKeyId string `pulumi:"managementAgentInstallKeyId"`
	// Status of Key
	State string `pulumi:"state"`
	// The time when Management Agent install Key was created. An RFC3339 formatted date time string
	TimeCreated string `pulumi:"timeCreated"`
	// date after which key would expire after creation
	TimeExpires string `pulumi:"timeExpires"`
	// The time when Management Agent install Key was updated. An RFC3339 formatted date time string
	TimeUpdated string `pulumi:"timeUpdated"`
}