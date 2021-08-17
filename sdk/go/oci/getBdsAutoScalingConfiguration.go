// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Auto Scaling Configuration resource in Oracle Cloud Infrastructure Big Data Service service.
//
// Returns details of the autoscale configuration identified by the given ID.
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
// 		_, err := oci.GetBdsAutoScalingConfiguration(ctx, &GetBdsAutoScalingConfigurationArgs{
// 			AutoScalingConfigurationId: oci_autoscaling_auto_scaling_configuration.Test_auto_scaling_configuration.Id,
// 			BdsInstanceId:              oci_bds_bds_instance.Test_bds_instance.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupBdsAutoScalingConfiguration(ctx *pulumi.Context, args *LookupBdsAutoScalingConfigurationArgs, opts ...pulumi.InvokeOption) (*LookupBdsAutoScalingConfigurationResult, error) {
	var rv LookupBdsAutoScalingConfigurationResult
	err := ctx.Invoke("oci:index/getBdsAutoScalingConfiguration:GetBdsAutoScalingConfiguration", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetBdsAutoScalingConfiguration.
type LookupBdsAutoScalingConfigurationArgs struct {
	// Unique Oracle-assigned identifier of the autoscale configuration.
	AutoScalingConfigurationId string `pulumi:"autoScalingConfigurationId"`
	// The OCID of the cluster.
	BdsInstanceId string `pulumi:"bdsInstanceId"`
}

// A collection of values returned by GetBdsAutoScalingConfiguration.
type LookupBdsAutoScalingConfigurationResult struct {
	AutoScalingConfigurationId string `pulumi:"autoScalingConfigurationId"`
	BdsInstanceId              string `pulumi:"bdsInstanceId"`
	ClusterAdminPassword       string `pulumi:"clusterAdminPassword"`
	// A user-friendly name. The name does not have to be unique, and it may be changed. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// The unique identifier for the autoscale configuration.
	Id        string `pulumi:"id"`
	IsEnabled bool   `pulumi:"isEnabled"`
	// A node type that is managed by an autoscale configuration. The only supported type is WORKER.
	NodeType string `pulumi:"nodeType"`
	// Policy definitions for the autoscale configuration.
	Policy GetBdsAutoScalingConfigurationPolicy `pulumi:"policy"`
	// The state of the autoscale configuration.
	State string `pulumi:"state"`
	// The time the cluster was created, shown as an RFC 3339 formatted datetime string.
	TimeCreated string `pulumi:"timeCreated"`
	// The time the autoscale configuration was updated, shown as an RFC 3339 formatted datetime string.
	TimeUpdated string `pulumi:"timeUpdated"`
}