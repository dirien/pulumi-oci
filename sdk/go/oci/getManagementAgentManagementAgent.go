// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Management Agent resource in Oracle Cloud Infrastructure Management Agent service.
//
// Gets complete details of the inventory of a given agent id
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
// 		_, err := oci.GetManagementAgentManagementAgent(ctx, &GetManagementAgentManagementAgentArgs{
// 			ManagementAgentId: oci_management_agent_management_agent.Test_management_agent.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupManagementAgentManagementAgent(ctx *pulumi.Context, args *LookupManagementAgentManagementAgentArgs, opts ...pulumi.InvokeOption) (*LookupManagementAgentManagementAgentResult, error) {
	var rv LookupManagementAgentManagementAgentResult
	err := ctx.Invoke("oci:index/getManagementAgentManagementAgent:GetManagementAgentManagementAgent", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetManagementAgentManagementAgent.
type LookupManagementAgentManagementAgentArgs struct {
	// Unique Management Agent identifier
	ManagementAgentId string `pulumi:"managementAgentId"`
}

// A collection of values returned by GetManagementAgentManagementAgent.
type LookupManagementAgentManagementAgentResult struct {
	// The current availability status of managementAgent
	AvailabilityStatus string `pulumi:"availabilityStatus"`
	// Compartment Identifier
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags      map[string]interface{} `pulumi:"definedTags"`
	DeployPluginsIds []string               `pulumi:"deployPluginsIds"`
	// Management Agent Name
	DisplayName string `pulumi:"displayName"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Management Agent host machine name
	Host string `pulumi:"host"`
	// agent identifier
	Id string `pulumi:"id"`
	// agent install key identifier
	InstallKeyId string `pulumi:"installKeyId"`
	// Path where Management Agent is installed
	InstallPath string `pulumi:"installPath"`
	// true if the agent can be upgraded automatically; false if it must be upgraded manually. true is currently unsupported.
	IsAgentAutoUpgradable bool `pulumi:"isAgentAutoUpgradable"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails  string `pulumi:"lifecycleDetails"`
	ManagedAgentId    string `pulumi:"managedAgentId"`
	ManagementAgentId string `pulumi:"managementAgentId"`
	// Platform Name
	PlatformName string `pulumi:"platformName"`
	// Platform Type
	PlatformType string `pulumi:"platformType"`
	// Platform Version
	PlatformVersion string `pulumi:"platformVersion"`
	// list of managementAgentPlugins associated with the agent
	PluginLists []GetManagementAgentManagementAgentPluginList `pulumi:"pluginLists"`
	// The current state of managementAgent
	State string `pulumi:"state"`
	// The time the Management Agent was created. An RFC3339 formatted datetime string
	TimeCreated string `pulumi:"timeCreated"`
	// The time the Management Agent has last recorded its health status in telemetry. This value will be null if the agent has not recorded its health status in last 7 days. An RFC3339 formatted datetime string
	TimeLastHeartbeat string `pulumi:"timeLastHeartbeat"`
	// The time the Management Agent was updated. An RFC3339 formatted datetime string
	TimeUpdated string `pulumi:"timeUpdated"`
	// Management Agent Version
	Version string `pulumi:"version"`
}
