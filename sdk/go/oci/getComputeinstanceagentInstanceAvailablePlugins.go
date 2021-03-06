// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Instance Available Plugins in Oracle Cloud Infrastructure Compute Instance Agent service.
//
// The API to get the list of plugins that are available.
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
// 		opt0 := _var.Instance_available_plugin_name
// 		_, err := oci.GetComputeinstanceagentInstanceAvailablePlugins(ctx, &GetComputeinstanceagentInstanceAvailablePluginsArgs{
// 			OsName:    _var.Instance_available_plugin_os_name,
// 			OsVersion: _var.Instance_available_plugin_os_version,
// 			Name:      &opt0,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetComputeinstanceagentInstanceAvailablePlugins(ctx *pulumi.Context, args *GetComputeinstanceagentInstanceAvailablePluginsArgs, opts ...pulumi.InvokeOption) (*GetComputeinstanceagentInstanceAvailablePluginsResult, error) {
	var rv GetComputeinstanceagentInstanceAvailablePluginsResult
	err := ctx.Invoke("oci:index/getComputeinstanceagentInstanceAvailablePlugins:GetComputeinstanceagentInstanceAvailablePlugins", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetComputeinstanceagentInstanceAvailablePlugins.
type GetComputeinstanceagentInstanceAvailablePluginsArgs struct {
	CompartmentId string                                                  `pulumi:"compartmentId"`
	Filters       []GetComputeinstanceagentInstanceAvailablePluginsFilter `pulumi:"filters"`
	// The plugin name
	Name *string `pulumi:"name"`
	// The OS for which the plugin is supported. Examples of OperatingSystemQueryParam:OperatingSystemVersionQueryParam are as follows: 'CentOS' '6.10' , 'CentOS Linux' '7', 'CentOS Linux' '8', 'Oracle Linux Server' '6.10', 'Oracle Linux Server' '8.0', 'Red Hat Enterprise Linux Server' '7.8', 'Windows' '10', 'Windows' '2008ServerR2', 'Windows' '2012ServerR2', 'Windows' '7', 'Windows' '8.1'
	OsName string `pulumi:"osName"`
	// The OS version for which the plugin is supported.
	OsVersion string `pulumi:"osVersion"`
}

// A collection of values returned by GetComputeinstanceagentInstanceAvailablePlugins.
type GetComputeinstanceagentInstanceAvailablePluginsResult struct {
	// The list of available_plugins.
	AvailablePlugins []GetComputeinstanceagentInstanceAvailablePluginsAvailablePlugin `pulumi:"availablePlugins"`
	CompartmentId    string                                                           `pulumi:"compartmentId"`
	Filters          []GetComputeinstanceagentInstanceAvailablePluginsFilter          `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The plugin name
	Name      *string `pulumi:"name"`
	OsName    string  `pulumi:"osName"`
	OsVersion string  `pulumi:"osVersion"`
}
