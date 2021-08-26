// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package healthchecks

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Http Probe Results in Oracle Cloud Infrastructure Health Checks service.
//
// Gets the HTTP probe results for the specified probe or monitor, where
// the `probeConfigurationId` is the OCID of either a monitor or an
// on-demand probe.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/healthchecks"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		opt0 := _var.Http_probe_result_start_time_greater_than_or_equal_to
// 		opt1 := _var.Http_probe_result_start_time_less_than_or_equal_to
// 		opt2 := _var.Http_probe_result_target
// 		_, err := healthchecks.GetHttpProbeResults(ctx, &healthchecks.GetHttpProbeResultsArgs{
// 			ProbeConfigurationId:          oci_health_checks_probe_configuration.Test_probe_configuration.Id,
// 			StartTimeGreaterThanOrEqualTo: &opt0,
// 			StartTimeLessThanOrEqualTo:    &opt1,
// 			Target:                        &opt2,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetHttpProbeResults(ctx *pulumi.Context, args *GetHttpProbeResultsArgs, opts ...pulumi.InvokeOption) (*GetHttpProbeResultsResult, error) {
	var rv GetHttpProbeResultsResult
	err := ctx.Invoke("oci:healthchecks/getHttpProbeResults:getHttpProbeResults", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getHttpProbeResults.
type GetHttpProbeResultsArgs struct {
	Filters []GetHttpProbeResultsFilter `pulumi:"filters"`
	// The OCID of a monitor or on-demand probe.
	ProbeConfigurationId string `pulumi:"probeConfigurationId"`
	// Returns results with a `startTime` equal to or greater than the specified value.
	StartTimeGreaterThanOrEqualTo *float64 `pulumi:"startTimeGreaterThanOrEqualTo"`
	// Returns results with a `startTime` equal to or less than the specified value.
	StartTimeLessThanOrEqualTo *float64 `pulumi:"startTimeLessThanOrEqualTo"`
	// Filters results that match the `target`.
	Target *string `pulumi:"target"`
}

// A collection of values returned by getHttpProbeResults.
type GetHttpProbeResultsResult struct {
	Filters []GetHttpProbeResultsFilter `pulumi:"filters"`
	// The list of http_probe_results.
	HttpProbeResults []GetHttpProbeResultsHttpProbeResult `pulumi:"httpProbeResults"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The OCID of the monitor or on-demand probe responsible for creating this result.
	ProbeConfigurationId          string   `pulumi:"probeConfigurationId"`
	StartTimeGreaterThanOrEqualTo *float64 `pulumi:"startTimeGreaterThanOrEqualTo"`
	StartTimeLessThanOrEqualTo    *float64 `pulumi:"startTimeLessThanOrEqualTo"`
	// The target hostname or IP address of the probe.
	Target *string `pulumi:"target"`
}
