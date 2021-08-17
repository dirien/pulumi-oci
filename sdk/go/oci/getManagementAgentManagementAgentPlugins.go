// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Management Agent Plugins in Oracle Cloud Infrastructure Management Agent service.
//
// Returns a list of managementAgentPlugins.
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
// 		opt0 := _var.Management_agent_plugin_display_name
// 		opt1 := _var.Management_agent_plugin_state
// 		_, err := oci.GetManagementAgentManagementAgentPlugins(ctx, &GetManagementAgentManagementAgentPluginsArgs{
// 			CompartmentId: _var.Compartment_id,
// 			DisplayName:   &opt0,
// 			State:         &opt1,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetManagementAgentManagementAgentPlugins(ctx *pulumi.Context, args *GetManagementAgentManagementAgentPluginsArgs, opts ...pulumi.InvokeOption) (*GetManagementAgentManagementAgentPluginsResult, error) {
	var rv GetManagementAgentManagementAgentPluginsResult
	err := ctx.Invoke("oci:index/getManagementAgentManagementAgentPlugins:GetManagementAgentManagementAgentPlugins", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetManagementAgentManagementAgentPlugins.
type GetManagementAgentManagementAgentPluginsArgs struct {
	// The ID of the compartment from which the Management Agents to be listed.
	CompartmentId string `pulumi:"compartmentId"`
	// Filter to return only Management Agent Plugins having the particular display name.
	DisplayName *string                                          `pulumi:"displayName"`
	Filters     []GetManagementAgentManagementAgentPluginsFilter `pulumi:"filters"`
	// Filter to return only Management Agents in the particular lifecycle state.
	State *string `pulumi:"state"`
}

// A collection of values returned by GetManagementAgentManagementAgentPlugins.
type GetManagementAgentManagementAgentPluginsResult struct {
	CompartmentId string `pulumi:"compartmentId"`
	// Management Agent Plugin Display Name
	DisplayName *string                                          `pulumi:"displayName"`
	Filters     []GetManagementAgentManagementAgentPluginsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of management_agent_plugins.
	ManagementAgentPlugins []GetManagementAgentManagementAgentPluginsManagementAgentPlugin `pulumi:"managementAgentPlugins"`
	// The current state of Management Agent Plugin
	State *string `pulumi:"state"`
}