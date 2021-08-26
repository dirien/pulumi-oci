// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package apmsynthetics

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Monitor resource in Oracle Cloud Infrastructure Apm Synthetics service.
//
// Gets the configuration of the monitor identified by the OCID.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/apmsynthetics"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := apmsynthetics.LookupMonitor(ctx, &apmsynthetics.LookupMonitorArgs{
// 			ApmDomainId: oci_apm_synthetics_apm_domain.Test_apm_domain.Id,
// 			MonitorId:   oci_apm_synthetics_monitor.Test_monitor.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupMonitor(ctx *pulumi.Context, args *LookupMonitorArgs, opts ...pulumi.InvokeOption) (*LookupMonitorResult, error) {
	var rv LookupMonitorResult
	err := ctx.Invoke("oci:apmsynthetics/getMonitor:getMonitor", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMonitor.
type LookupMonitorArgs struct {
	// The APM domain ID the request is intended for.
	ApmDomainId string `pulumi:"apmDomainId"`
	// The OCID of the monitor.
	MonitorId string `pulumi:"monitorId"`
}

// A collection of values returned by getMonitor.
type LookupMonitorResult struct {
	ApmDomainId string `pulumi:"apmDomainId"`
	// Details of monitor configuration.
	Configuration GetMonitorConfiguration `pulumi:"configuration"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// Unique name that can be edited. The name should not contain any confidential information.
	DisplayName string `pulumi:"displayName"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitor.
	Id        string `pulumi:"id"`
	MonitorId string `pulumi:"monitorId"`
	// Type of the monitor.
	MonitorType string `pulumi:"monitorType"`
	// Interval in seconds after the start time when the job should be repeated. Minimum repeatIntervalInSeconds should be 300 seconds.
	RepeatIntervalInSeconds int `pulumi:"repeatIntervalInSeconds"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the script. scriptId is mandatory for creation of SCRIPTED_BROWSER and SCRIPTED_REST monitor types. For other monitor types, it should be set to null.
	ScriptId string `pulumi:"scriptId"`
	// Name of the script.
	ScriptName string `pulumi:"scriptName"`
	// List of script parameters. Example: `[{"monitorScriptParameter": {"paramName": "userid", "paramValue":"testuser"}, "isSecret": false, "isOverwritten": false}]`
	ScriptParameters []GetMonitorScriptParameter `pulumi:"scriptParameters"`
	// Enables or disables the monitor.
	Status string `pulumi:"status"`
	// Specify the endpoint on which to run the monitor. For BROWSER and REST monitor types, target is mandatory. If target is specified in the SCRIPTED_BROWSER monitor type, then the monitor will run the selected script (specified by scriptId in monitor) against the specified target endpoint. If target is not specified in the SCRIPTED_BROWSER monitor type, then the monitor will run the selected script as it is.
	Target string `pulumi:"target"`
	// The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
	TimeCreated string `pulumi:"timeCreated"`
	// The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
	TimeUpdated string `pulumi:"timeUpdated"`
	// Timeout in seconds. Timeout cannot be more than 30% of repeatIntervalInSeconds time for monitors. Also, timeoutInSeconds should be a multiple of 60. Monitor will be allowed to run only for timeoutInSeconds time. It would be terminated after that.
	TimeoutInSeconds int `pulumi:"timeoutInSeconds"`
	// Number of vantage points where monitor is running.
	VantagePointCount int `pulumi:"vantagePointCount"`
	// List of vantage points from where monitor is running.
	VantagePoints []string `pulumi:"vantagePoints"`
}