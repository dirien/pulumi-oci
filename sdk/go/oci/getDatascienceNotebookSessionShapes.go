// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Notebook Session Shapes in Oracle Cloud Infrastructure Data Science service.
//
// Lists the valid notebook session shapes.
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
// 		_, err := oci.GetDatascienceNotebookSessionShapes(ctx, &GetDatascienceNotebookSessionShapesArgs{
// 			CompartmentId: _var.Compartment_id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetDatascienceNotebookSessionShapes(ctx *pulumi.Context, args *GetDatascienceNotebookSessionShapesArgs, opts ...pulumi.InvokeOption) (*GetDatascienceNotebookSessionShapesResult, error) {
	var rv GetDatascienceNotebookSessionShapesResult
	err := ctx.Invoke("oci:index/getDatascienceNotebookSessionShapes:GetDatascienceNotebookSessionShapes", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetDatascienceNotebookSessionShapes.
type GetDatascienceNotebookSessionShapesArgs struct {
	// <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string                                      `pulumi:"compartmentId"`
	Filters       []GetDatascienceNotebookSessionShapesFilter `pulumi:"filters"`
}

// A collection of values returned by GetDatascienceNotebookSessionShapes.
type GetDatascienceNotebookSessionShapesResult struct {
	CompartmentId string                                      `pulumi:"compartmentId"`
	Filters       []GetDatascienceNotebookSessionShapesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of notebook_session_shapes.
	NotebookSessionShapes []GetDatascienceNotebookSessionShapesNotebookSessionShape `pulumi:"notebookSessionShapes"`
}