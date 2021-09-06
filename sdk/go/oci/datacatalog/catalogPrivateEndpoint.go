// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package datacatalog

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Catalog Private Endpoint resource in Oracle Cloud Infrastructure Data Catalog service.
//
// Create a new private reverse connection endpoint.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/datacatalog"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := datacatalog.NewCatalogPrivateEndpoint(ctx, "testCatalogPrivateEndpoint", &datacatalog.CatalogPrivateEndpointArgs{
// 			CompartmentId: pulumi.Any(_var.Compartment_id),
// 			DnsZones:      pulumi.Any(_var.Catalog_private_endpoint_dns_zones),
// 			SubnetId:      pulumi.Any(oci_core_subnet.Test_subnet.Id),
// 			DefinedTags: pulumi.AnyMap{
// 				"foo-namespace.bar-key": pulumi.Any("value"),
// 			},
// 			DisplayName: pulumi.Any(_var.Catalog_private_endpoint_display_name),
// 			FreeformTags: pulumi.AnyMap{
// 				"bar-key": pulumi.Any("value"),
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
// CatalogPrivateEndpoints can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:datacatalog/catalogPrivateEndpoint:CatalogPrivateEndpoint test_catalog_private_endpoint "id"
// ```
type CatalogPrivateEndpoint struct {
	pulumi.CustomResourceState

	// The list of catalogs using the private reverse connection endpoint
	AttachedCatalogs pulumi.StringArrayOutput `pulumi:"attachedCatalogs"`
	// (Updatable) Compartment identifier.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) Display name of the private endpoint resource being created.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) List of DNS zones to be used by the data assets to be harvested. Example: custpvtsubnet.oraclevcn.com for data asset: db.custpvtsubnet.oraclevcn.com
	DnsZones pulumi.StringArrayOutput `pulumi:"dnsZones"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in 'Failed' state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The current state of the private endpoint resource.
	State pulumi.StringOutput `pulumi:"state"`
	// The OCID of subnet to which the reverse connection is to be created
	SubnetId pulumi.StringOutput `pulumi:"subnetId"`
	// The time the private endpoint was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time the private endpoint was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewCatalogPrivateEndpoint registers a new resource with the given unique name, arguments, and options.
func NewCatalogPrivateEndpoint(ctx *pulumi.Context,
	name string, args *CatalogPrivateEndpointArgs, opts ...pulumi.ResourceOption) (*CatalogPrivateEndpoint, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DnsZones == nil {
		return nil, errors.New("invalid value for required argument 'DnsZones'")
	}
	if args.SubnetId == nil {
		return nil, errors.New("invalid value for required argument 'SubnetId'")
	}
	var resource CatalogPrivateEndpoint
	err := ctx.RegisterResource("oci:datacatalog/catalogPrivateEndpoint:CatalogPrivateEndpoint", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetCatalogPrivateEndpoint gets an existing CatalogPrivateEndpoint resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetCatalogPrivateEndpoint(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *CatalogPrivateEndpointState, opts ...pulumi.ResourceOption) (*CatalogPrivateEndpoint, error) {
	var resource CatalogPrivateEndpoint
	err := ctx.ReadResource("oci:datacatalog/catalogPrivateEndpoint:CatalogPrivateEndpoint", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering CatalogPrivateEndpoint resources.
type catalogPrivateEndpointState struct {
	// The list of catalogs using the private reverse connection endpoint
	AttachedCatalogs []string `pulumi:"attachedCatalogs"`
	// (Updatable) Compartment identifier.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Display name of the private endpoint resource being created.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) List of DNS zones to be used by the data assets to be harvested. Example: custpvtsubnet.oraclevcn.com for data asset: db.custpvtsubnet.oraclevcn.com
	DnsZones []string `pulumi:"dnsZones"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in 'Failed' state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The current state of the private endpoint resource.
	State *string `pulumi:"state"`
	// The OCID of subnet to which the reverse connection is to be created
	SubnetId *string `pulumi:"subnetId"`
	// The time the private endpoint was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
	TimeCreated *string `pulumi:"timeCreated"`
	// The time the private endpoint was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type CatalogPrivateEndpointState struct {
	// The list of catalogs using the private reverse connection endpoint
	AttachedCatalogs pulumi.StringArrayInput
	// (Updatable) Compartment identifier.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Display name of the private endpoint resource being created.
	DisplayName pulumi.StringPtrInput
	// (Updatable) List of DNS zones to be used by the data assets to be harvested. Example: custpvtsubnet.oraclevcn.com for data asset: db.custpvtsubnet.oraclevcn.com
	DnsZones pulumi.StringArrayInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in 'Failed' state.
	LifecycleDetails pulumi.StringPtrInput
	// The current state of the private endpoint resource.
	State pulumi.StringPtrInput
	// The OCID of subnet to which the reverse connection is to be created
	SubnetId pulumi.StringPtrInput
	// The time the private endpoint was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
	TimeCreated pulumi.StringPtrInput
	// The time the private endpoint was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
	TimeUpdated pulumi.StringPtrInput
}

func (CatalogPrivateEndpointState) ElementType() reflect.Type {
	return reflect.TypeOf((*catalogPrivateEndpointState)(nil)).Elem()
}

type catalogPrivateEndpointArgs struct {
	// (Updatable) Compartment identifier.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Display name of the private endpoint resource being created.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) List of DNS zones to be used by the data assets to be harvested. Example: custpvtsubnet.oraclevcn.com for data asset: db.custpvtsubnet.oraclevcn.com
	DnsZones []string `pulumi:"dnsZones"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The OCID of subnet to which the reverse connection is to be created
	SubnetId string `pulumi:"subnetId"`
}

// The set of arguments for constructing a CatalogPrivateEndpoint resource.
type CatalogPrivateEndpointArgs struct {
	// (Updatable) Compartment identifier.
	CompartmentId pulumi.StringInput
	// (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Display name of the private endpoint resource being created.
	DisplayName pulumi.StringPtrInput
	// (Updatable) List of DNS zones to be used by the data assets to be harvested. Example: custpvtsubnet.oraclevcn.com for data asset: db.custpvtsubnet.oraclevcn.com
	DnsZones pulumi.StringArrayInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// The OCID of subnet to which the reverse connection is to be created
	SubnetId pulumi.StringInput
}

func (CatalogPrivateEndpointArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*catalogPrivateEndpointArgs)(nil)).Elem()
}

type CatalogPrivateEndpointInput interface {
	pulumi.Input

	ToCatalogPrivateEndpointOutput() CatalogPrivateEndpointOutput
	ToCatalogPrivateEndpointOutputWithContext(ctx context.Context) CatalogPrivateEndpointOutput
}

func (*CatalogPrivateEndpoint) ElementType() reflect.Type {
	return reflect.TypeOf((*CatalogPrivateEndpoint)(nil))
}

func (i *CatalogPrivateEndpoint) ToCatalogPrivateEndpointOutput() CatalogPrivateEndpointOutput {
	return i.ToCatalogPrivateEndpointOutputWithContext(context.Background())
}

func (i *CatalogPrivateEndpoint) ToCatalogPrivateEndpointOutputWithContext(ctx context.Context) CatalogPrivateEndpointOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CatalogPrivateEndpointOutput)
}

func (i *CatalogPrivateEndpoint) ToCatalogPrivateEndpointPtrOutput() CatalogPrivateEndpointPtrOutput {
	return i.ToCatalogPrivateEndpointPtrOutputWithContext(context.Background())
}

func (i *CatalogPrivateEndpoint) ToCatalogPrivateEndpointPtrOutputWithContext(ctx context.Context) CatalogPrivateEndpointPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CatalogPrivateEndpointPtrOutput)
}

type CatalogPrivateEndpointPtrInput interface {
	pulumi.Input

	ToCatalogPrivateEndpointPtrOutput() CatalogPrivateEndpointPtrOutput
	ToCatalogPrivateEndpointPtrOutputWithContext(ctx context.Context) CatalogPrivateEndpointPtrOutput
}

type catalogPrivateEndpointPtrType CatalogPrivateEndpointArgs

func (*catalogPrivateEndpointPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**CatalogPrivateEndpoint)(nil))
}

func (i *catalogPrivateEndpointPtrType) ToCatalogPrivateEndpointPtrOutput() CatalogPrivateEndpointPtrOutput {
	return i.ToCatalogPrivateEndpointPtrOutputWithContext(context.Background())
}

func (i *catalogPrivateEndpointPtrType) ToCatalogPrivateEndpointPtrOutputWithContext(ctx context.Context) CatalogPrivateEndpointPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CatalogPrivateEndpointPtrOutput)
}

// CatalogPrivateEndpointArrayInput is an input type that accepts CatalogPrivateEndpointArray and CatalogPrivateEndpointArrayOutput values.
// You can construct a concrete instance of `CatalogPrivateEndpointArrayInput` via:
//
//          CatalogPrivateEndpointArray{ CatalogPrivateEndpointArgs{...} }
type CatalogPrivateEndpointArrayInput interface {
	pulumi.Input

	ToCatalogPrivateEndpointArrayOutput() CatalogPrivateEndpointArrayOutput
	ToCatalogPrivateEndpointArrayOutputWithContext(context.Context) CatalogPrivateEndpointArrayOutput
}

type CatalogPrivateEndpointArray []CatalogPrivateEndpointInput

func (CatalogPrivateEndpointArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*CatalogPrivateEndpoint)(nil)).Elem()
}

func (i CatalogPrivateEndpointArray) ToCatalogPrivateEndpointArrayOutput() CatalogPrivateEndpointArrayOutput {
	return i.ToCatalogPrivateEndpointArrayOutputWithContext(context.Background())
}

func (i CatalogPrivateEndpointArray) ToCatalogPrivateEndpointArrayOutputWithContext(ctx context.Context) CatalogPrivateEndpointArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CatalogPrivateEndpointArrayOutput)
}

// CatalogPrivateEndpointMapInput is an input type that accepts CatalogPrivateEndpointMap and CatalogPrivateEndpointMapOutput values.
// You can construct a concrete instance of `CatalogPrivateEndpointMapInput` via:
//
//          CatalogPrivateEndpointMap{ "key": CatalogPrivateEndpointArgs{...} }
type CatalogPrivateEndpointMapInput interface {
	pulumi.Input

	ToCatalogPrivateEndpointMapOutput() CatalogPrivateEndpointMapOutput
	ToCatalogPrivateEndpointMapOutputWithContext(context.Context) CatalogPrivateEndpointMapOutput
}

type CatalogPrivateEndpointMap map[string]CatalogPrivateEndpointInput

func (CatalogPrivateEndpointMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*CatalogPrivateEndpoint)(nil)).Elem()
}

func (i CatalogPrivateEndpointMap) ToCatalogPrivateEndpointMapOutput() CatalogPrivateEndpointMapOutput {
	return i.ToCatalogPrivateEndpointMapOutputWithContext(context.Background())
}

func (i CatalogPrivateEndpointMap) ToCatalogPrivateEndpointMapOutputWithContext(ctx context.Context) CatalogPrivateEndpointMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CatalogPrivateEndpointMapOutput)
}

type CatalogPrivateEndpointOutput struct {
	*pulumi.OutputState
}

func (CatalogPrivateEndpointOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*CatalogPrivateEndpoint)(nil))
}

func (o CatalogPrivateEndpointOutput) ToCatalogPrivateEndpointOutput() CatalogPrivateEndpointOutput {
	return o
}

func (o CatalogPrivateEndpointOutput) ToCatalogPrivateEndpointOutputWithContext(ctx context.Context) CatalogPrivateEndpointOutput {
	return o
}

func (o CatalogPrivateEndpointOutput) ToCatalogPrivateEndpointPtrOutput() CatalogPrivateEndpointPtrOutput {
	return o.ToCatalogPrivateEndpointPtrOutputWithContext(context.Background())
}

func (o CatalogPrivateEndpointOutput) ToCatalogPrivateEndpointPtrOutputWithContext(ctx context.Context) CatalogPrivateEndpointPtrOutput {
	return o.ApplyT(func(v CatalogPrivateEndpoint) *CatalogPrivateEndpoint {
		return &v
	}).(CatalogPrivateEndpointPtrOutput)
}

type CatalogPrivateEndpointPtrOutput struct {
	*pulumi.OutputState
}

func (CatalogPrivateEndpointPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**CatalogPrivateEndpoint)(nil))
}

func (o CatalogPrivateEndpointPtrOutput) ToCatalogPrivateEndpointPtrOutput() CatalogPrivateEndpointPtrOutput {
	return o
}

func (o CatalogPrivateEndpointPtrOutput) ToCatalogPrivateEndpointPtrOutputWithContext(ctx context.Context) CatalogPrivateEndpointPtrOutput {
	return o
}

type CatalogPrivateEndpointArrayOutput struct{ *pulumi.OutputState }

func (CatalogPrivateEndpointArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]CatalogPrivateEndpoint)(nil))
}

func (o CatalogPrivateEndpointArrayOutput) ToCatalogPrivateEndpointArrayOutput() CatalogPrivateEndpointArrayOutput {
	return o
}

func (o CatalogPrivateEndpointArrayOutput) ToCatalogPrivateEndpointArrayOutputWithContext(ctx context.Context) CatalogPrivateEndpointArrayOutput {
	return o
}

func (o CatalogPrivateEndpointArrayOutput) Index(i pulumi.IntInput) CatalogPrivateEndpointOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) CatalogPrivateEndpoint {
		return vs[0].([]CatalogPrivateEndpoint)[vs[1].(int)]
	}).(CatalogPrivateEndpointOutput)
}

type CatalogPrivateEndpointMapOutput struct{ *pulumi.OutputState }

func (CatalogPrivateEndpointMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]CatalogPrivateEndpoint)(nil))
}

func (o CatalogPrivateEndpointMapOutput) ToCatalogPrivateEndpointMapOutput() CatalogPrivateEndpointMapOutput {
	return o
}

func (o CatalogPrivateEndpointMapOutput) ToCatalogPrivateEndpointMapOutputWithContext(ctx context.Context) CatalogPrivateEndpointMapOutput {
	return o
}

func (o CatalogPrivateEndpointMapOutput) MapIndex(k pulumi.StringInput) CatalogPrivateEndpointOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) CatalogPrivateEndpoint {
		return vs[0].(map[string]CatalogPrivateEndpoint)[vs[1].(string)]
	}).(CatalogPrivateEndpointOutput)
}

func init() {
	pulumi.RegisterOutputType(CatalogPrivateEndpointOutput{})
	pulumi.RegisterOutputType(CatalogPrivateEndpointPtrOutput{})
	pulumi.RegisterOutputType(CatalogPrivateEndpointArrayOutput{})
	pulumi.RegisterOutputType(CatalogPrivateEndpointMapOutput{})
}
