// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Drg Route Table Route Rule resource in Oracle Cloud Infrastructure Core service.
//
// Adds one static route rule to the specified DRG route table.
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
// 		_, err := oci.NewCoreDrgRouteTableRouteRule(ctx, "testDrgRouteTableRouteRule", &oci.CoreDrgRouteTableRouteRuleArgs{
// 			DrgRouteTableId:        pulumi.Any(oci_core_drg_route_table.Test_drg_route_table.Id),
// 			Destination:            pulumi.Any(_var.Drg_route_table_route_rule_route_rules_destination),
// 			DestinationType:        pulumi.Any(_var.Drg_route_table_route_rule_route_rules_destination_type),
// 			NextHopDrgAttachmentId: pulumi.Any(oci_core_drg_attachment.Test_drg_attachment.Id),
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
// DrgRouteTableRouteRule can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/coreDrgRouteTableRouteRule:CoreDrgRouteTableRouteRule test_drg_route_table_route_rule "drgRouteTables/{drgRouteTableId}/routeRules/{id}"
// ```
type CoreDrgRouteTableRouteRule struct {
	pulumi.CustomResourceState

	// (Updatable) This is the range of IP addresses used for matching when routing traffic. Only CIDR_BLOCK values are allowed.
	Destination pulumi.StringOutput `pulumi:"destination"`
	// (Updatable) Type of destination for the rule. Required if `direction` = `EGRESS`. Allowed values:
	// * `CIDR_BLOCK`: If the rule's `destination` is an IP address range in CIDR notation.
	DestinationType pulumi.StringOutput `pulumi:"destinationType"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table.
	DrgRouteTableId pulumi.StringOutput `pulumi:"drgRouteTableId"`
	// Indicates that if the next hop attachment does not exist, so traffic for this route is discarded without notification.
	IsBlackhole pulumi.BoolOutput `pulumi:"isBlackhole"`
	// Indicates that the route was not imported due to a conflict between route rules.
	IsConflict pulumi.BoolOutput `pulumi:"isConflict"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next hop DRG attachment. The next hop DRG attachment is responsible for reaching the network destination.
	NextHopDrgAttachmentId pulumi.StringOutput `pulumi:"nextHopDrgAttachmentId"`
	// The earliest origin of a route. If a route is advertised to a DRG through an IPsec tunnel attachment, and is propagated to peered DRGs via RPC attachments, the route's provenance in the peered DRGs remains `IPSEC_TUNNEL`, because that is the earliest origin.
	RouteProvenance pulumi.StringOutput `pulumi:"routeProvenance"`
	// You can specify static routes for the DRG route table using the API. The DRG learns dynamic routes from the DRG attachments using various routing protocols.
	RouteType pulumi.StringOutput `pulumi:"routeType"`
}

// NewCoreDrgRouteTableRouteRule registers a new resource with the given unique name, arguments, and options.
func NewCoreDrgRouteTableRouteRule(ctx *pulumi.Context,
	name string, args *CoreDrgRouteTableRouteRuleArgs, opts ...pulumi.ResourceOption) (*CoreDrgRouteTableRouteRule, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.Destination == nil {
		return nil, errors.New("invalid value for required argument 'Destination'")
	}
	if args.DestinationType == nil {
		return nil, errors.New("invalid value for required argument 'DestinationType'")
	}
	if args.DrgRouteTableId == nil {
		return nil, errors.New("invalid value for required argument 'DrgRouteTableId'")
	}
	if args.NextHopDrgAttachmentId == nil {
		return nil, errors.New("invalid value for required argument 'NextHopDrgAttachmentId'")
	}
	var resource CoreDrgRouteTableRouteRule
	err := ctx.RegisterResource("oci:index/coreDrgRouteTableRouteRule:CoreDrgRouteTableRouteRule", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetCoreDrgRouteTableRouteRule gets an existing CoreDrgRouteTableRouteRule resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetCoreDrgRouteTableRouteRule(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *CoreDrgRouteTableRouteRuleState, opts ...pulumi.ResourceOption) (*CoreDrgRouteTableRouteRule, error) {
	var resource CoreDrgRouteTableRouteRule
	err := ctx.ReadResource("oci:index/coreDrgRouteTableRouteRule:CoreDrgRouteTableRouteRule", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering CoreDrgRouteTableRouteRule resources.
type coreDrgRouteTableRouteRuleState struct {
	// (Updatable) This is the range of IP addresses used for matching when routing traffic. Only CIDR_BLOCK values are allowed.
	Destination *string `pulumi:"destination"`
	// (Updatable) Type of destination for the rule. Required if `direction` = `EGRESS`. Allowed values:
	// * `CIDR_BLOCK`: If the rule's `destination` is an IP address range in CIDR notation.
	DestinationType *string `pulumi:"destinationType"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table.
	DrgRouteTableId *string `pulumi:"drgRouteTableId"`
	// Indicates that if the next hop attachment does not exist, so traffic for this route is discarded without notification.
	IsBlackhole *bool `pulumi:"isBlackhole"`
	// Indicates that the route was not imported due to a conflict between route rules.
	IsConflict *bool `pulumi:"isConflict"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next hop DRG attachment. The next hop DRG attachment is responsible for reaching the network destination.
	NextHopDrgAttachmentId *string `pulumi:"nextHopDrgAttachmentId"`
	// The earliest origin of a route. If a route is advertised to a DRG through an IPsec tunnel attachment, and is propagated to peered DRGs via RPC attachments, the route's provenance in the peered DRGs remains `IPSEC_TUNNEL`, because that is the earliest origin.
	RouteProvenance *string `pulumi:"routeProvenance"`
	// You can specify static routes for the DRG route table using the API. The DRG learns dynamic routes from the DRG attachments using various routing protocols.
	RouteType *string `pulumi:"routeType"`
}

type CoreDrgRouteTableRouteRuleState struct {
	// (Updatable) This is the range of IP addresses used for matching when routing traffic. Only CIDR_BLOCK values are allowed.
	Destination pulumi.StringPtrInput
	// (Updatable) Type of destination for the rule. Required if `direction` = `EGRESS`. Allowed values:
	// * `CIDR_BLOCK`: If the rule's `destination` is an IP address range in CIDR notation.
	DestinationType pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table.
	DrgRouteTableId pulumi.StringPtrInput
	// Indicates that if the next hop attachment does not exist, so traffic for this route is discarded without notification.
	IsBlackhole pulumi.BoolPtrInput
	// Indicates that the route was not imported due to a conflict between route rules.
	IsConflict pulumi.BoolPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next hop DRG attachment. The next hop DRG attachment is responsible for reaching the network destination.
	NextHopDrgAttachmentId pulumi.StringPtrInput
	// The earliest origin of a route. If a route is advertised to a DRG through an IPsec tunnel attachment, and is propagated to peered DRGs via RPC attachments, the route's provenance in the peered DRGs remains `IPSEC_TUNNEL`, because that is the earliest origin.
	RouteProvenance pulumi.StringPtrInput
	// You can specify static routes for the DRG route table using the API. The DRG learns dynamic routes from the DRG attachments using various routing protocols.
	RouteType pulumi.StringPtrInput
}

func (CoreDrgRouteTableRouteRuleState) ElementType() reflect.Type {
	return reflect.TypeOf((*coreDrgRouteTableRouteRuleState)(nil)).Elem()
}

type coreDrgRouteTableRouteRuleArgs struct {
	// (Updatable) This is the range of IP addresses used for matching when routing traffic. Only CIDR_BLOCK values are allowed.
	Destination string `pulumi:"destination"`
	// (Updatable) Type of destination for the rule. Required if `direction` = `EGRESS`. Allowed values:
	// * `CIDR_BLOCK`: If the rule's `destination` is an IP address range in CIDR notation.
	DestinationType string `pulumi:"destinationType"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table.
	DrgRouteTableId string `pulumi:"drgRouteTableId"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next hop DRG attachment. The next hop DRG attachment is responsible for reaching the network destination.
	NextHopDrgAttachmentId string `pulumi:"nextHopDrgAttachmentId"`
}

// The set of arguments for constructing a CoreDrgRouteTableRouteRule resource.
type CoreDrgRouteTableRouteRuleArgs struct {
	// (Updatable) This is the range of IP addresses used for matching when routing traffic. Only CIDR_BLOCK values are allowed.
	Destination pulumi.StringInput
	// (Updatable) Type of destination for the rule. Required if `direction` = `EGRESS`. Allowed values:
	// * `CIDR_BLOCK`: If the rule's `destination` is an IP address range in CIDR notation.
	DestinationType pulumi.StringInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table.
	DrgRouteTableId pulumi.StringInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next hop DRG attachment. The next hop DRG attachment is responsible for reaching the network destination.
	NextHopDrgAttachmentId pulumi.StringInput
}

func (CoreDrgRouteTableRouteRuleArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*coreDrgRouteTableRouteRuleArgs)(nil)).Elem()
}

type CoreDrgRouteTableRouteRuleInput interface {
	pulumi.Input

	ToCoreDrgRouteTableRouteRuleOutput() CoreDrgRouteTableRouteRuleOutput
	ToCoreDrgRouteTableRouteRuleOutputWithContext(ctx context.Context) CoreDrgRouteTableRouteRuleOutput
}

func (*CoreDrgRouteTableRouteRule) ElementType() reflect.Type {
	return reflect.TypeOf((*CoreDrgRouteTableRouteRule)(nil))
}

func (i *CoreDrgRouteTableRouteRule) ToCoreDrgRouteTableRouteRuleOutput() CoreDrgRouteTableRouteRuleOutput {
	return i.ToCoreDrgRouteTableRouteRuleOutputWithContext(context.Background())
}

func (i *CoreDrgRouteTableRouteRule) ToCoreDrgRouteTableRouteRuleOutputWithContext(ctx context.Context) CoreDrgRouteTableRouteRuleOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreDrgRouteTableRouteRuleOutput)
}

func (i *CoreDrgRouteTableRouteRule) ToCoreDrgRouteTableRouteRulePtrOutput() CoreDrgRouteTableRouteRulePtrOutput {
	return i.ToCoreDrgRouteTableRouteRulePtrOutputWithContext(context.Background())
}

func (i *CoreDrgRouteTableRouteRule) ToCoreDrgRouteTableRouteRulePtrOutputWithContext(ctx context.Context) CoreDrgRouteTableRouteRulePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreDrgRouteTableRouteRulePtrOutput)
}

type CoreDrgRouteTableRouteRulePtrInput interface {
	pulumi.Input

	ToCoreDrgRouteTableRouteRulePtrOutput() CoreDrgRouteTableRouteRulePtrOutput
	ToCoreDrgRouteTableRouteRulePtrOutputWithContext(ctx context.Context) CoreDrgRouteTableRouteRulePtrOutput
}

type coreDrgRouteTableRouteRulePtrType CoreDrgRouteTableRouteRuleArgs

func (*coreDrgRouteTableRouteRulePtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**CoreDrgRouteTableRouteRule)(nil))
}

func (i *coreDrgRouteTableRouteRulePtrType) ToCoreDrgRouteTableRouteRulePtrOutput() CoreDrgRouteTableRouteRulePtrOutput {
	return i.ToCoreDrgRouteTableRouteRulePtrOutputWithContext(context.Background())
}

func (i *coreDrgRouteTableRouteRulePtrType) ToCoreDrgRouteTableRouteRulePtrOutputWithContext(ctx context.Context) CoreDrgRouteTableRouteRulePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreDrgRouteTableRouteRulePtrOutput)
}

// CoreDrgRouteTableRouteRuleArrayInput is an input type that accepts CoreDrgRouteTableRouteRuleArray and CoreDrgRouteTableRouteRuleArrayOutput values.
// You can construct a concrete instance of `CoreDrgRouteTableRouteRuleArrayInput` via:
//
//          CoreDrgRouteTableRouteRuleArray{ CoreDrgRouteTableRouteRuleArgs{...} }
type CoreDrgRouteTableRouteRuleArrayInput interface {
	pulumi.Input

	ToCoreDrgRouteTableRouteRuleArrayOutput() CoreDrgRouteTableRouteRuleArrayOutput
	ToCoreDrgRouteTableRouteRuleArrayOutputWithContext(context.Context) CoreDrgRouteTableRouteRuleArrayOutput
}

type CoreDrgRouteTableRouteRuleArray []CoreDrgRouteTableRouteRuleInput

func (CoreDrgRouteTableRouteRuleArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*CoreDrgRouteTableRouteRule)(nil)).Elem()
}

func (i CoreDrgRouteTableRouteRuleArray) ToCoreDrgRouteTableRouteRuleArrayOutput() CoreDrgRouteTableRouteRuleArrayOutput {
	return i.ToCoreDrgRouteTableRouteRuleArrayOutputWithContext(context.Background())
}

func (i CoreDrgRouteTableRouteRuleArray) ToCoreDrgRouteTableRouteRuleArrayOutputWithContext(ctx context.Context) CoreDrgRouteTableRouteRuleArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreDrgRouteTableRouteRuleArrayOutput)
}

// CoreDrgRouteTableRouteRuleMapInput is an input type that accepts CoreDrgRouteTableRouteRuleMap and CoreDrgRouteTableRouteRuleMapOutput values.
// You can construct a concrete instance of `CoreDrgRouteTableRouteRuleMapInput` via:
//
//          CoreDrgRouteTableRouteRuleMap{ "key": CoreDrgRouteTableRouteRuleArgs{...} }
type CoreDrgRouteTableRouteRuleMapInput interface {
	pulumi.Input

	ToCoreDrgRouteTableRouteRuleMapOutput() CoreDrgRouteTableRouteRuleMapOutput
	ToCoreDrgRouteTableRouteRuleMapOutputWithContext(context.Context) CoreDrgRouteTableRouteRuleMapOutput
}

type CoreDrgRouteTableRouteRuleMap map[string]CoreDrgRouteTableRouteRuleInput

func (CoreDrgRouteTableRouteRuleMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*CoreDrgRouteTableRouteRule)(nil)).Elem()
}

func (i CoreDrgRouteTableRouteRuleMap) ToCoreDrgRouteTableRouteRuleMapOutput() CoreDrgRouteTableRouteRuleMapOutput {
	return i.ToCoreDrgRouteTableRouteRuleMapOutputWithContext(context.Background())
}

func (i CoreDrgRouteTableRouteRuleMap) ToCoreDrgRouteTableRouteRuleMapOutputWithContext(ctx context.Context) CoreDrgRouteTableRouteRuleMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreDrgRouteTableRouteRuleMapOutput)
}

type CoreDrgRouteTableRouteRuleOutput struct {
	*pulumi.OutputState
}

func (CoreDrgRouteTableRouteRuleOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*CoreDrgRouteTableRouteRule)(nil))
}

func (o CoreDrgRouteTableRouteRuleOutput) ToCoreDrgRouteTableRouteRuleOutput() CoreDrgRouteTableRouteRuleOutput {
	return o
}

func (o CoreDrgRouteTableRouteRuleOutput) ToCoreDrgRouteTableRouteRuleOutputWithContext(ctx context.Context) CoreDrgRouteTableRouteRuleOutput {
	return o
}

func (o CoreDrgRouteTableRouteRuleOutput) ToCoreDrgRouteTableRouteRulePtrOutput() CoreDrgRouteTableRouteRulePtrOutput {
	return o.ToCoreDrgRouteTableRouteRulePtrOutputWithContext(context.Background())
}

func (o CoreDrgRouteTableRouteRuleOutput) ToCoreDrgRouteTableRouteRulePtrOutputWithContext(ctx context.Context) CoreDrgRouteTableRouteRulePtrOutput {
	return o.ApplyT(func(v CoreDrgRouteTableRouteRule) *CoreDrgRouteTableRouteRule {
		return &v
	}).(CoreDrgRouteTableRouteRulePtrOutput)
}

type CoreDrgRouteTableRouteRulePtrOutput struct {
	*pulumi.OutputState
}

func (CoreDrgRouteTableRouteRulePtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**CoreDrgRouteTableRouteRule)(nil))
}

func (o CoreDrgRouteTableRouteRulePtrOutput) ToCoreDrgRouteTableRouteRulePtrOutput() CoreDrgRouteTableRouteRulePtrOutput {
	return o
}

func (o CoreDrgRouteTableRouteRulePtrOutput) ToCoreDrgRouteTableRouteRulePtrOutputWithContext(ctx context.Context) CoreDrgRouteTableRouteRulePtrOutput {
	return o
}

type CoreDrgRouteTableRouteRuleArrayOutput struct{ *pulumi.OutputState }

func (CoreDrgRouteTableRouteRuleArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]CoreDrgRouteTableRouteRule)(nil))
}

func (o CoreDrgRouteTableRouteRuleArrayOutput) ToCoreDrgRouteTableRouteRuleArrayOutput() CoreDrgRouteTableRouteRuleArrayOutput {
	return o
}

func (o CoreDrgRouteTableRouteRuleArrayOutput) ToCoreDrgRouteTableRouteRuleArrayOutputWithContext(ctx context.Context) CoreDrgRouteTableRouteRuleArrayOutput {
	return o
}

func (o CoreDrgRouteTableRouteRuleArrayOutput) Index(i pulumi.IntInput) CoreDrgRouteTableRouteRuleOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) CoreDrgRouteTableRouteRule {
		return vs[0].([]CoreDrgRouteTableRouteRule)[vs[1].(int)]
	}).(CoreDrgRouteTableRouteRuleOutput)
}

type CoreDrgRouteTableRouteRuleMapOutput struct{ *pulumi.OutputState }

func (CoreDrgRouteTableRouteRuleMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]CoreDrgRouteTableRouteRule)(nil))
}

func (o CoreDrgRouteTableRouteRuleMapOutput) ToCoreDrgRouteTableRouteRuleMapOutput() CoreDrgRouteTableRouteRuleMapOutput {
	return o
}

func (o CoreDrgRouteTableRouteRuleMapOutput) ToCoreDrgRouteTableRouteRuleMapOutputWithContext(ctx context.Context) CoreDrgRouteTableRouteRuleMapOutput {
	return o
}

func (o CoreDrgRouteTableRouteRuleMapOutput) MapIndex(k pulumi.StringInput) CoreDrgRouteTableRouteRuleOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) CoreDrgRouteTableRouteRule {
		return vs[0].(map[string]CoreDrgRouteTableRouteRule)[vs[1].(string)]
	}).(CoreDrgRouteTableRouteRuleOutput)
}

func init() {
	pulumi.RegisterOutputType(CoreDrgRouteTableRouteRuleOutput{})
	pulumi.RegisterOutputType(CoreDrgRouteTableRouteRulePtrOutput{})
	pulumi.RegisterOutputType(CoreDrgRouteTableRouteRuleArrayOutput{})
	pulumi.RegisterOutputType(CoreDrgRouteTableRouteRuleMapOutput{})
}
