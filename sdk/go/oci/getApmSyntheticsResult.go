// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Result resource in Oracle Cloud Infrastructure Apm Synthetics service.
//
// Gets the results for a specific execution of a monitor identified by OCID. The results are in a HAR file, Screenshot, or Console Log.
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
// 		_, err := oci.GetApmSyntheticsResult(ctx, &GetApmSyntheticsResultArgs{
// 			ApmDomainId:       oci_apm_synthetics_apm_domain.Test_apm_domain.Id,
// 			ExecutionTime:     _var.Result_execution_time,
// 			MonitorId:         oci_apm_synthetics_monitor.Test_monitor.Id,
// 			ResultContentType: _var.Result_result_content_type,
// 			ResultType:        _var.Result_result_type,
// 			VantagePoint:      _var.Result_vantage_point,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetApmSyntheticsResult(ctx *pulumi.Context, args *GetApmSyntheticsResultArgs, opts ...pulumi.InvokeOption) (*GetApmSyntheticsResultResult, error) {
	var rv GetApmSyntheticsResultResult
	err := ctx.Invoke("oci:index/getApmSyntheticsResult:GetApmSyntheticsResult", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetApmSyntheticsResult.
type GetApmSyntheticsResultArgs struct {
	// The APM domain ID the request is intended for.
	ApmDomainId string `pulumi:"apmDomainId"`
	// The time the object was posted.
	ExecutionTime string `pulumi:"executionTime"`
	// The OCID of the monitor.
	MonitorId string `pulumi:"monitorId"`
	// The result content type zip or raw.
	ResultContentType string `pulumi:"resultContentType"`
	// The result type har or screenshot or log.
	ResultType string `pulumi:"resultType"`
	// The vantagePoint name.
	VantagePoint string `pulumi:"vantagePoint"`
}

// A collection of values returned by GetApmSyntheticsResult.
type GetApmSyntheticsResultResult struct {
	ApmDomainId string `pulumi:"apmDomainId"`
	// The specific point of time when the result of an execution is collected.
	ExecutionTime string `pulumi:"executionTime"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitor.
	MonitorId string `pulumi:"monitorId"`
	// Type of result content. Example: Zip or Raw file.
	ResultContentType string `pulumi:"resultContentType"`
	// Monitor result data set.
	ResultDataSets []GetApmSyntheticsResultResultDataSet `pulumi:"resultDataSets"`
	// Type of result. Example: HAR, Screenshot or Log.
	ResultType string `pulumi:"resultType"`
	// The name of the vantage point.
	VantagePoint string `pulumi:"vantagePoint"`
}
