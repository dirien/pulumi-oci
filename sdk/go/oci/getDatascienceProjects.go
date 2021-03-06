// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Projects in Oracle Cloud Infrastructure Data Science service.
//
// Lists projects in the specified compartment.
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
// 		opt0 := _var.Project_created_by
// 		opt1 := _var.Project_display_name
// 		opt2 := _var.Project_id
// 		opt3 := _var.Project_state
// 		_, err := oci.GetDatascienceProjects(ctx, &GetDatascienceProjectsArgs{
// 			CompartmentId: _var.Compartment_id,
// 			CreatedBy:     &opt0,
// 			DisplayName:   &opt1,
// 			Id:            &opt2,
// 			State:         &opt3,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetDatascienceProjects(ctx *pulumi.Context, args *GetDatascienceProjectsArgs, opts ...pulumi.InvokeOption) (*GetDatascienceProjectsResult, error) {
	var rv GetDatascienceProjectsResult
	err := ctx.Invoke("oci:index/getDatascienceProjects:GetDatascienceProjects", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetDatascienceProjects.
type GetDatascienceProjectsArgs struct {
	// <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
	CreatedBy *string `pulumi:"createdBy"`
	// <b>Filter</b> results by its user-friendly name.
	DisplayName *string                        `pulumi:"displayName"`
	Filters     []GetDatascienceProjectsFilter `pulumi:"filters"`
	// <b>Filter</b> results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resource type.
	Id *string `pulumi:"id"`
	// <b>Filter</b> results by the specified lifecycle state. Must be a valid state for the resource type.
	State *string `pulumi:"state"`
}

// A collection of values returned by GetDatascienceProjects.
type GetDatascienceProjectsResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project's compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created this project.
	CreatedBy *string `pulumi:"createdBy"`
	// A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information.
	DisplayName *string                        `pulumi:"displayName"`
	Filters     []GetDatascienceProjectsFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project.
	Id *string `pulumi:"id"`
	// The list of projects.
	Projects []GetDatascienceProjectsProject `pulumi:"projects"`
	// The state of the project.
	State *string `pulumi:"state"`
}
