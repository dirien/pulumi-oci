// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of User Group Memberships in Oracle Cloud Infrastructure Identity service.
//
// Lists the `UserGroupMembership` objects in your tenancy. You must specify your tenancy's OCID
// as the value for the compartment ID
// (see [Where to Get the Tenancy's OCID and User's OCID](https://docs.cloud.oracle.com/iaas/Content/API/Concepts/apisigningkey.htm#five)).
// You must also then filter the list in one of these ways:
//
// - You can limit the results to just the memberships for a given user by specifying a `userId`.
// - Similarly, you can limit the results to just the memberships for a given group by specifying a `groupId`.
// - You can set both the `userId` and `groupId` to determine if the specified user is in the specified group.
//   If the answer is no, the response is an empty list.
// - Although`userId` and `groupId` are not individually required, you must set one of them.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/identity"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		opt0 := oci_identity_group.Test_group.Id
// 		opt1 := oci_identity_user.Test_user.Id
// 		_, err := identity.GetUserGroupMemberships(ctx, &identity.GetUserGroupMembershipsArgs{
// 			CompartmentId: _var.Tenancy_ocid,
// 			GroupId:       &opt0,
// 			UserId:        &opt1,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetUserGroupMemberships(ctx *pulumi.Context, args *GetUserGroupMembershipsArgs, opts ...pulumi.InvokeOption) (*GetUserGroupMembershipsResult, error) {
	var rv GetUserGroupMembershipsResult
	err := ctx.Invoke("oci:identity/getUserGroupMemberships:getUserGroupMemberships", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getUserGroupMemberships.
type GetUserGroupMembershipsArgs struct {
	// The OCID of the compartment (remember that the tenancy is simply the root compartment).
	CompartmentId string                          `pulumi:"compartmentId"`
	Filters       []GetUserGroupMembershipsFilter `pulumi:"filters"`
	// The OCID of the group.
	GroupId *string `pulumi:"groupId"`
	// The OCID of the user.
	UserId *string `pulumi:"userId"`
}

// A collection of values returned by getUserGroupMemberships.
type GetUserGroupMembershipsResult struct {
	// The OCID of the tenancy containing the user, group, and membership object.
	CompartmentId string                          `pulumi:"compartmentId"`
	Filters       []GetUserGroupMembershipsFilter `pulumi:"filters"`
	// The OCID of the group.
	GroupId *string `pulumi:"groupId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of memberships.
	Memberships []GetUserGroupMembershipsMembership `pulumi:"memberships"`
	// The OCID of the user.
	UserId *string `pulumi:"userId"`
}