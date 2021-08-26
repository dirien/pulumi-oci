// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package loadbalancer

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Load Balancer resource in Oracle Cloud Infrastructure Load Balancer service.
//
// Creates a new load balancer in the specified compartment. For general information about load balancers,
// see [Overview of the Load Balancing Service](https://docs.cloud.oracle.com/iaas/Content/Balance/Concepts/balanceoverview.htm).
//
// For the purposes of access control, you must provide the OCID of the compartment where you want
// the load balancer to reside. Notice that the load balancer doesn't have to be in the same compartment as the VCN
// or backend set. If you're not sure which compartment to use, put the load balancer in the same compartment as the VCN.
// For information about access control and compartments, see
// [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm).
//
// You must specify a display name for the load balancer. It does not have to be unique, and you can change it.
//
// For information about Availability Domains, see
// [Regions and Availability Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm).
// To get a list of Availability Domains, use the `ListAvailabilityDomains` operation
// in the Identity and Access Management Service API.
//
// All Oracle Cloud Infrastructure resources, including load balancers, get an Oracle-assigned,
// unique ID called an Oracle Cloud Identifier (OCID). When you create a resource, you can find its OCID
// in the response. You can also retrieve a resource's OCID by using a List API operation on that resource type,
// or by viewing the resource in the Console. Fore more information, see
// [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
//
// When you create a load balancer, the system assigns an IP address.
// To get the IP address, use the [GetLoadBalancer](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancer/GetLoadBalancer) operation.
//
// ## Supported Aliases
//
// * `ociLoadBalancer`
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/loadbalancer"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := loadbalancer.NewLoadBalancer(ctx, "testLoadBalancer", &loadbalancer.LoadBalancerArgs{
// 			CompartmentId: pulumi.Any(_var.Compartment_id),
// 			DisplayName:   pulumi.Any(_var.Load_balancer_display_name),
// 			Shape:         pulumi.Any(_var.Load_balancer_shape),
// 			SubnetIds:     pulumi.Any(_var.Load_balancer_subnet_ids),
// 			DefinedTags: pulumi.AnyMap{
// 				"Operations.CostCenter": pulumi.Any("42"),
// 			},
// 			FreeformTags: pulumi.AnyMap{
// 				"Department": pulumi.Any("Finance"),
// 			},
// 			IpMode:                  pulumi.Any(_var.Load_balancer_ip_mode),
// 			IsPrivate:               pulumi.Any(_var.Load_balancer_is_private),
// 			NetworkSecurityGroupIds: pulumi.Any(_var.Load_balancer_network_security_group_ids),
// 			ReservedIps: loadbalancer.LoadBalancerReservedIpArray{
// 				&loadbalancer.LoadBalancerReservedIpArgs{
// 					Id: pulumi.Any(_var.Load_balancer_reserved_ips_id),
// 				},
// 			},
// 			ShapeDetails: &loadbalancer.LoadBalancerShapeDetailsArgs{
// 				MaximumBandwidthInMbps: pulumi.Any(_var.Load_balancer_shape_details_maximum_bandwidth_in_mbps),
// 				MinimumBandwidthInMbps: pulumi.Any(_var.Load_balancer_shape_details_minimum_bandwidth_in_mbps),
// 			},
// 		})
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
//
// ## Import
//
// LoadBalancers can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:loadbalancer/loadBalancer:LoadBalancer test_load_balancer "id"
// ```
type LoadBalancer struct {
	pulumi.CustomResourceState

	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the load balancer.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `exampleLoadBalancer`
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// An array of IP addresses.
	IpAddressDetails LoadBalancerIpAddressDetailArrayOutput `pulumi:"ipAddressDetails"`
	// An array of IP addresses. Deprecated: use ipAddressDetails instead
	//
	// Deprecated: The 'ip_addresses' field has been deprecated. Please use 'ip_address_details' instead.
	IpAddresses pulumi.StringArrayOutput `pulumi:"ipAddresses"`
	// IPv6 is currently supported only in the Government Cloud. Whether the load balancer has an IPv4 or IPv6 IP address.
	IpMode pulumi.StringOutput `pulumi:"ipMode"`
	// Whether the load balancer has a VCN-local (private) IP address.
	IsPrivate pulumi.BoolOutput `pulumi:"isPrivate"`
	// (Updatable) An array of NSG [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this load balancer.
	NetworkSecurityGroupIds pulumi.StringArrayOutput `pulumi:"networkSecurityGroupIds"`
	// An array of reserved Ips. Pre-created public IP that will be used as the IP of this load balancer. This reserved IP will not be deleted when load balancer is deleted. This ip should not be already mapped to any other resource.
	ReservedIps LoadBalancerReservedIpArrayOutput `pulumi:"reservedIps"`
	// (Updatable) A template that determines the total pre-provisioned bandwidth (ingress plus egress). To get a list of available shapes, use the [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerShape/ListShapes) operation.  Example: `100Mbps` *Note: When updating shape for a load balancer, all existing connections to the load balancer will be reset during the update process. Also `10Mbps-Micro` shape cannot be updated to any other shape nor can any other shape be updated to `10Mbps-Micro`.
	Shape pulumi.StringOutput `pulumi:"shape"`
	// (Updatable) The configuration details to create load balancer using Flexible shape. This is required only if shapeName is `Flexible`.
	ShapeDetails LoadBalancerShapeDetailsOutput `pulumi:"shapeDetails"`
	// The current state of the load balancer.
	State pulumi.StringOutput `pulumi:"state"`
	// An array of subnet [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	SubnetIds pulumi.StringArrayOutput `pulumi:"subnetIds"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// The date and time the load balancer was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
}

// NewLoadBalancer registers a new resource with the given unique name, arguments, and options.
func NewLoadBalancer(ctx *pulumi.Context,
	name string, args *LoadBalancerArgs, opts ...pulumi.ResourceOption) (*LoadBalancer, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	if args.Shape == nil {
		return nil, errors.New("invalid value for required argument 'Shape'")
	}
	if args.SubnetIds == nil {
		return nil, errors.New("invalid value for required argument 'SubnetIds'")
	}
	var resource LoadBalancer
	err := ctx.RegisterResource("oci:loadbalancer/loadBalancer:LoadBalancer", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetLoadBalancer gets an existing LoadBalancer resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetLoadBalancer(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *LoadBalancerState, opts ...pulumi.ResourceOption) (*LoadBalancer, error) {
	var resource LoadBalancer
	err := ctx.ReadResource("oci:loadbalancer/loadBalancer:LoadBalancer", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering LoadBalancer resources.
type loadBalancerState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the load balancer.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `exampleLoadBalancer`
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// An array of IP addresses.
	IpAddressDetails []LoadBalancerIpAddressDetail `pulumi:"ipAddressDetails"`
	// An array of IP addresses. Deprecated: use ipAddressDetails instead
	//
	// Deprecated: The 'ip_addresses' field has been deprecated. Please use 'ip_address_details' instead.
	IpAddresses []string `pulumi:"ipAddresses"`
	// IPv6 is currently supported only in the Government Cloud. Whether the load balancer has an IPv4 or IPv6 IP address.
	IpMode *string `pulumi:"ipMode"`
	// Whether the load balancer has a VCN-local (private) IP address.
	IsPrivate *bool `pulumi:"isPrivate"`
	// (Updatable) An array of NSG [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this load balancer.
	NetworkSecurityGroupIds []string `pulumi:"networkSecurityGroupIds"`
	// An array of reserved Ips. Pre-created public IP that will be used as the IP of this load balancer. This reserved IP will not be deleted when load balancer is deleted. This ip should not be already mapped to any other resource.
	ReservedIps []LoadBalancerReservedIp `pulumi:"reservedIps"`
	// (Updatable) A template that determines the total pre-provisioned bandwidth (ingress plus egress). To get a list of available shapes, use the [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerShape/ListShapes) operation.  Example: `100Mbps` *Note: When updating shape for a load balancer, all existing connections to the load balancer will be reset during the update process. Also `10Mbps-Micro` shape cannot be updated to any other shape nor can any other shape be updated to `10Mbps-Micro`.
	Shape *string `pulumi:"shape"`
	// (Updatable) The configuration details to create load balancer using Flexible shape. This is required only if shapeName is `Flexible`.
	ShapeDetails *LoadBalancerShapeDetails `pulumi:"shapeDetails"`
	// The current state of the load balancer.
	State *string `pulumi:"state"`
	// An array of subnet [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	SubnetIds []string `pulumi:"subnetIds"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The date and time the load balancer was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
}

type LoadBalancerState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the load balancer.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `exampleLoadBalancer`
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// An array of IP addresses.
	IpAddressDetails LoadBalancerIpAddressDetailArrayInput
	// An array of IP addresses. Deprecated: use ipAddressDetails instead
	//
	// Deprecated: The 'ip_addresses' field has been deprecated. Please use 'ip_address_details' instead.
	IpAddresses pulumi.StringArrayInput
	// IPv6 is currently supported only in the Government Cloud. Whether the load balancer has an IPv4 or IPv6 IP address.
	IpMode pulumi.StringPtrInput
	// Whether the load balancer has a VCN-local (private) IP address.
	IsPrivate pulumi.BoolPtrInput
	// (Updatable) An array of NSG [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this load balancer.
	NetworkSecurityGroupIds pulumi.StringArrayInput
	// An array of reserved Ips. Pre-created public IP that will be used as the IP of this load balancer. This reserved IP will not be deleted when load balancer is deleted. This ip should not be already mapped to any other resource.
	ReservedIps LoadBalancerReservedIpArrayInput
	// (Updatable) A template that determines the total pre-provisioned bandwidth (ingress plus egress). To get a list of available shapes, use the [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerShape/ListShapes) operation.  Example: `100Mbps` *Note: When updating shape for a load balancer, all existing connections to the load balancer will be reset during the update process. Also `10Mbps-Micro` shape cannot be updated to any other shape nor can any other shape be updated to `10Mbps-Micro`.
	Shape pulumi.StringPtrInput
	// (Updatable) The configuration details to create load balancer using Flexible shape. This is required only if shapeName is `Flexible`.
	ShapeDetails LoadBalancerShapeDetailsPtrInput
	// The current state of the load balancer.
	State pulumi.StringPtrInput
	// An array of subnet [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	SubnetIds pulumi.StringArrayInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapInput
	// The date and time the load balancer was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
}

func (LoadBalancerState) ElementType() reflect.Type {
	return reflect.TypeOf((*loadBalancerState)(nil)).Elem()
}

type loadBalancerArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the load balancer.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `exampleLoadBalancer`
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// IPv6 is currently supported only in the Government Cloud. Whether the load balancer has an IPv4 or IPv6 IP address.
	IpMode *string `pulumi:"ipMode"`
	// Whether the load balancer has a VCN-local (private) IP address.
	IsPrivate *bool `pulumi:"isPrivate"`
	// (Updatable) An array of NSG [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this load balancer.
	NetworkSecurityGroupIds []string `pulumi:"networkSecurityGroupIds"`
	// An array of reserved Ips. Pre-created public IP that will be used as the IP of this load balancer. This reserved IP will not be deleted when load balancer is deleted. This ip should not be already mapped to any other resource.
	ReservedIps []LoadBalancerReservedIp `pulumi:"reservedIps"`
	// (Updatable) A template that determines the total pre-provisioned bandwidth (ingress plus egress). To get a list of available shapes, use the [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerShape/ListShapes) operation.  Example: `100Mbps` *Note: When updating shape for a load balancer, all existing connections to the load balancer will be reset during the update process. Also `10Mbps-Micro` shape cannot be updated to any other shape nor can any other shape be updated to `10Mbps-Micro`.
	Shape string `pulumi:"shape"`
	// (Updatable) The configuration details to create load balancer using Flexible shape. This is required only if shapeName is `Flexible`.
	ShapeDetails *LoadBalancerShapeDetails `pulumi:"shapeDetails"`
	// An array of subnet [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	SubnetIds []string `pulumi:"subnetIds"`
}

// The set of arguments for constructing a LoadBalancer resource.
type LoadBalancerArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the load balancer.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `exampleLoadBalancer`
	DisplayName pulumi.StringInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// IPv6 is currently supported only in the Government Cloud. Whether the load balancer has an IPv4 or IPv6 IP address.
	IpMode pulumi.StringPtrInput
	// Whether the load balancer has a VCN-local (private) IP address.
	IsPrivate pulumi.BoolPtrInput
	// (Updatable) An array of NSG [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this load balancer.
	NetworkSecurityGroupIds pulumi.StringArrayInput
	// An array of reserved Ips. Pre-created public IP that will be used as the IP of this load balancer. This reserved IP will not be deleted when load balancer is deleted. This ip should not be already mapped to any other resource.
	ReservedIps LoadBalancerReservedIpArrayInput
	// (Updatable) A template that determines the total pre-provisioned bandwidth (ingress plus egress). To get a list of available shapes, use the [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerShape/ListShapes) operation.  Example: `100Mbps` *Note: When updating shape for a load balancer, all existing connections to the load balancer will be reset during the update process. Also `10Mbps-Micro` shape cannot be updated to any other shape nor can any other shape be updated to `10Mbps-Micro`.
	Shape pulumi.StringInput
	// (Updatable) The configuration details to create load balancer using Flexible shape. This is required only if shapeName is `Flexible`.
	ShapeDetails LoadBalancerShapeDetailsPtrInput
	// An array of subnet [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	SubnetIds pulumi.StringArrayInput
}

func (LoadBalancerArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*loadBalancerArgs)(nil)).Elem()
}

type LoadBalancerInput interface {
	pulumi.Input

	ToLoadBalancerOutput() LoadBalancerOutput
	ToLoadBalancerOutputWithContext(ctx context.Context) LoadBalancerOutput
}

func (*LoadBalancer) ElementType() reflect.Type {
	return reflect.TypeOf((*LoadBalancer)(nil))
}

func (i *LoadBalancer) ToLoadBalancerOutput() LoadBalancerOutput {
	return i.ToLoadBalancerOutputWithContext(context.Background())
}

func (i *LoadBalancer) ToLoadBalancerOutputWithContext(ctx context.Context) LoadBalancerOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoadBalancerOutput)
}

func (i *LoadBalancer) ToLoadBalancerPtrOutput() LoadBalancerPtrOutput {
	return i.ToLoadBalancerPtrOutputWithContext(context.Background())
}

func (i *LoadBalancer) ToLoadBalancerPtrOutputWithContext(ctx context.Context) LoadBalancerPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoadBalancerPtrOutput)
}

type LoadBalancerPtrInput interface {
	pulumi.Input

	ToLoadBalancerPtrOutput() LoadBalancerPtrOutput
	ToLoadBalancerPtrOutputWithContext(ctx context.Context) LoadBalancerPtrOutput
}

type loadBalancerPtrType LoadBalancerArgs

func (*loadBalancerPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**LoadBalancer)(nil))
}

func (i *loadBalancerPtrType) ToLoadBalancerPtrOutput() LoadBalancerPtrOutput {
	return i.ToLoadBalancerPtrOutputWithContext(context.Background())
}

func (i *loadBalancerPtrType) ToLoadBalancerPtrOutputWithContext(ctx context.Context) LoadBalancerPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoadBalancerPtrOutput)
}

// LoadBalancerArrayInput is an input type that accepts LoadBalancerArray and LoadBalancerArrayOutput values.
// You can construct a concrete instance of `LoadBalancerArrayInput` via:
//
//          LoadBalancerArray{ LoadBalancerArgs{...} }
type LoadBalancerArrayInput interface {
	pulumi.Input

	ToLoadBalancerArrayOutput() LoadBalancerArrayOutput
	ToLoadBalancerArrayOutputWithContext(context.Context) LoadBalancerArrayOutput
}

type LoadBalancerArray []LoadBalancerInput

func (LoadBalancerArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*LoadBalancer)(nil)).Elem()
}

func (i LoadBalancerArray) ToLoadBalancerArrayOutput() LoadBalancerArrayOutput {
	return i.ToLoadBalancerArrayOutputWithContext(context.Background())
}

func (i LoadBalancerArray) ToLoadBalancerArrayOutputWithContext(ctx context.Context) LoadBalancerArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoadBalancerArrayOutput)
}

// LoadBalancerMapInput is an input type that accepts LoadBalancerMap and LoadBalancerMapOutput values.
// You can construct a concrete instance of `LoadBalancerMapInput` via:
//
//          LoadBalancerMap{ "key": LoadBalancerArgs{...} }
type LoadBalancerMapInput interface {
	pulumi.Input

	ToLoadBalancerMapOutput() LoadBalancerMapOutput
	ToLoadBalancerMapOutputWithContext(context.Context) LoadBalancerMapOutput
}

type LoadBalancerMap map[string]LoadBalancerInput

func (LoadBalancerMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*LoadBalancer)(nil)).Elem()
}

func (i LoadBalancerMap) ToLoadBalancerMapOutput() LoadBalancerMapOutput {
	return i.ToLoadBalancerMapOutputWithContext(context.Background())
}

func (i LoadBalancerMap) ToLoadBalancerMapOutputWithContext(ctx context.Context) LoadBalancerMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoadBalancerMapOutput)
}

type LoadBalancerOutput struct {
	*pulumi.OutputState
}

func (LoadBalancerOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LoadBalancer)(nil))
}

func (o LoadBalancerOutput) ToLoadBalancerOutput() LoadBalancerOutput {
	return o
}

func (o LoadBalancerOutput) ToLoadBalancerOutputWithContext(ctx context.Context) LoadBalancerOutput {
	return o
}

func (o LoadBalancerOutput) ToLoadBalancerPtrOutput() LoadBalancerPtrOutput {
	return o.ToLoadBalancerPtrOutputWithContext(context.Background())
}

func (o LoadBalancerOutput) ToLoadBalancerPtrOutputWithContext(ctx context.Context) LoadBalancerPtrOutput {
	return o.ApplyT(func(v LoadBalancer) *LoadBalancer {
		return &v
	}).(LoadBalancerPtrOutput)
}

type LoadBalancerPtrOutput struct {
	*pulumi.OutputState
}

func (LoadBalancerPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**LoadBalancer)(nil))
}

func (o LoadBalancerPtrOutput) ToLoadBalancerPtrOutput() LoadBalancerPtrOutput {
	return o
}

func (o LoadBalancerPtrOutput) ToLoadBalancerPtrOutputWithContext(ctx context.Context) LoadBalancerPtrOutput {
	return o
}

type LoadBalancerArrayOutput struct{ *pulumi.OutputState }

func (LoadBalancerArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]LoadBalancer)(nil))
}

func (o LoadBalancerArrayOutput) ToLoadBalancerArrayOutput() LoadBalancerArrayOutput {
	return o
}

func (o LoadBalancerArrayOutput) ToLoadBalancerArrayOutputWithContext(ctx context.Context) LoadBalancerArrayOutput {
	return o
}

func (o LoadBalancerArrayOutput) Index(i pulumi.IntInput) LoadBalancerOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) LoadBalancer {
		return vs[0].([]LoadBalancer)[vs[1].(int)]
	}).(LoadBalancerOutput)
}

type LoadBalancerMapOutput struct{ *pulumi.OutputState }

func (LoadBalancerMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]LoadBalancer)(nil))
}

func (o LoadBalancerMapOutput) ToLoadBalancerMapOutput() LoadBalancerMapOutput {
	return o
}

func (o LoadBalancerMapOutput) ToLoadBalancerMapOutputWithContext(ctx context.Context) LoadBalancerMapOutput {
	return o
}

func (o LoadBalancerMapOutput) MapIndex(k pulumi.StringInput) LoadBalancerOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) LoadBalancer {
		return vs[0].(map[string]LoadBalancer)[vs[1].(string)]
	}).(LoadBalancerOutput)
}

func init() {
	pulumi.RegisterOutputType(LoadBalancerOutput{})
	pulumi.RegisterOutputType(LoadBalancerPtrOutput{})
	pulumi.RegisterOutputType(LoadBalancerArrayOutput{})
	pulumi.RegisterOutputType(LoadBalancerMapOutput{})
}
