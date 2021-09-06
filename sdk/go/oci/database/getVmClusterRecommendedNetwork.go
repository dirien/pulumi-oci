// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Vm Cluster Recommended Network resource in Oracle Cloud Infrastructure Database service.
//
// Generates a recommended Cloud@Customer VM cluster network configuration.
func GetVmClusterRecommendedNetwork(ctx *pulumi.Context, args *GetVmClusterRecommendedNetworkArgs, opts ...pulumi.InvokeOption) (*GetVmClusterRecommendedNetworkResult, error) {
	var rv GetVmClusterRecommendedNetworkResult
	err := ctx.Invoke("oci:database/getVmClusterRecommendedNetwork:getVmClusterRecommendedNetwork", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getVmClusterRecommendedNetwork.
type GetVmClusterRecommendedNetworkArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The user-friendly name for the VM cluster network. The name does not need to be unique.
	DisplayName string `pulumi:"displayName"`
	// The list of DNS server IP addresses. Maximum of 3 allowed.
	Dns []string `pulumi:"dns"`
	// The Exadata infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	ExadataInfrastructureId string `pulumi:"exadataInfrastructureId"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// List of parameters for generation of the client and backup networks.
	Networks []GetVmClusterRecommendedNetworkNetwork `pulumi:"networks"`
	// The list of NTP server IP addresses. Maximum of 3 allowed.
	Ntps []string `pulumi:"ntps"`
}

// A collection of values returned by getVmClusterRecommendedNetwork.
type GetVmClusterRecommendedNetworkResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The user-friendly name for the Exadata Cloud@Customer VM cluster network. The name does not need to be unique.
	DisplayName string `pulumi:"displayName"`
	// The list of DNS server IP addresses. Maximum of 3 allowed.
	Dns                     []string `pulumi:"dns"`
	ExadataInfrastructureId string   `pulumi:"exadataInfrastructureId"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The provider-assigned unique ID for this managed resource.
	Id       string                                  `pulumi:"id"`
	Networks []GetVmClusterRecommendedNetworkNetwork `pulumi:"networks"`
	// The list of NTP server IP addresses. Maximum of 3 allowed.
	Ntps []string `pulumi:"ntps"`
	// The SCAN details.
	Scans []GetVmClusterRecommendedNetworkScan `pulumi:"scans"`
	// Details of the client and backup networks.
	VmNetworks []GetVmClusterRecommendedNetworkVmNetwork `pulumi:"vmNetworks"`
}
