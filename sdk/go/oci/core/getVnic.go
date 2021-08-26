// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Vnic resource in Oracle Cloud Infrastructure Core service.
//
// Gets the information for the specified virtual network interface card (VNIC).
// You can get the VNIC OCID from the
// [ListVnicAttachments](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/VnicAttachment/ListVnicAttachments)
// operation.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/core"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := core.GetVnic(ctx, &core.GetVnicArgs{
// 			VnicId: oci_core_vnic.Test_vnic.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetVnic(ctx *pulumi.Context, args *GetVnicArgs, opts ...pulumi.InvokeOption) (*GetVnicResult, error) {
	var rv GetVnicResult
	err := ctx.Invoke("oci:core/getVnic:getVnic", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getVnic.
type GetVnicArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VNIC.
	VnicId string `pulumi:"vnicId"`
}

// A collection of values returned by getVnic.
type GetVnicResult struct {
	// The VNIC's availability domain.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain string `pulumi:"availabilityDomain"`
	// The OCID of the compartment containing the VNIC.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// A user-friendly name. Does not have to be unique. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The hostname for the VNIC's primary private IP. Used for DNS. The value is the hostname portion of the primary private IP's fully qualified domain name (FQDN) (for example, `bminstance-1` in FQDN `bminstance-1.subnet123.vcn1.oraclevcn.com`). Must be unique across all VNICs in the subnet and comply with [RFC 952](https://tools.ietf.org/html/rfc952) and [RFC 1123](https://tools.ietf.org/html/rfc1123).
	HostnameLabel string `pulumi:"hostnameLabel"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Whether the VNIC is the primary VNIC (the VNIC that is automatically created and attached during instance launch).
	IsPrimary bool `pulumi:"isPrimary"`
	// The MAC address of the VNIC.
	MacAddress string `pulumi:"macAddress"`
	// A list of the OCIDs of the network security groups that the VNIC belongs to.
	NsgIds []string `pulumi:"nsgIds"`
	// The private IP address of the primary `privateIp` object on the VNIC. The address is within the CIDR of the VNIC's subnet.  Example: `10.0.3.3`
	PrivateIpAddress string `pulumi:"privateIpAddress"`
	// The public IP address of the VNIC, if one is assigned.
	PublicIpAddress string `pulumi:"publicIpAddress"`
	// Whether the source/destination check is disabled on the VNIC. Defaults to `false`, which means the check is performed. For information about why you would skip the source/destination check, see [Using a Private IP as a Route Target](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingroutetables.htm#privateip).
	SkipSourceDestCheck bool `pulumi:"skipSourceDestCheck"`
	// The current state of the VNIC.
	State string `pulumi:"state"`
	// The OCID of the subnet the VNIC is in.
	SubnetId string `pulumi:"subnetId"`
	// The date and time the VNIC was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
	// If the VNIC belongs to a VLAN as part of the Oracle Cloud VMware Solution (instead of belonging to a subnet), the `vlanId` is the OCID of the VLAN the VNIC is in. See [Vlan](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Vlan). If the VNIC is instead in a subnet, `subnetId` has a value.
	VlanId string `pulumi:"vlanId"`
	VnicId string `pulumi:"vnicId"`
}