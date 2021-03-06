// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the App Catalog Subscription resource in Oracle Cloud Infrastructure Core service.
//
// Create a subscription for listing resource version for a compartment. It will take some time to propagate to all regions.
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
// 		_, err := oci.NewCoreAppCatalogSubscription(ctx, "testAppCatalogSubscription", &oci.CoreAppCatalogSubscriptionArgs{
// 			CompartmentId:          pulumi.Any(_var.Compartment_id),
// 			ListingId:              pulumi.Any(data.Oci_core_app_catalog_listing.Test_listing.Id),
// 			ListingResourceVersion: pulumi.Any(_var.App_catalog_subscription_listing_resource_version),
// 			OracleTermsOfUseLink:   pulumi.Any(_var.App_catalog_subscription_oracle_terms_of_use_link),
// 			Signature:              pulumi.Any(_var.App_catalog_subscription_signature),
// 			TimeRetrieved:          pulumi.Any(_var.App_catalog_subscription_time_retrieved),
// 			EulaLink:               pulumi.Any(_var.App_catalog_subscription_eula_link),
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
// AppCatalogSubscriptions can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/coreAppCatalogSubscription:CoreAppCatalogSubscription test_app_catalog_subscription "compartmentId/{compartmentId}/listingId/{listingId}/listingResourceVersion/{listingResourceVersion}"
// ```
type CoreAppCatalogSubscription struct {
	pulumi.CustomResourceState

	// The compartmentID for the subscription.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// The display name of the listing.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// EULA link
	EulaLink pulumi.StringPtrOutput `pulumi:"eulaLink"`
	// The OCID of the listing.
	ListingId pulumi.StringOutput `pulumi:"listingId"`
	// Listing resource id.
	ListingResourceId pulumi.StringOutput `pulumi:"listingResourceId"`
	// Listing resource version.
	ListingResourceVersion pulumi.StringOutput `pulumi:"listingResourceVersion"`
	// Oracle TOU link
	OracleTermsOfUseLink pulumi.StringOutput `pulumi:"oracleTermsOfUseLink"`
	// Name of the publisher who published this listing.
	PublisherName pulumi.StringOutput `pulumi:"publisherName"`
	// A generated signature for this listing resource version retrieved the agreements API.
	Signature pulumi.StringOutput `pulumi:"signature"`
	// The short summary to the listing.
	Summary pulumi.StringOutput `pulumi:"summary"`
	// Date and time at which the subscription was created, in [RFC3339](https://tools.ietf.org/html/rfc3339) format. Example: `2018-03-20T12:32:53.532Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// Date and time the agreements were retrieved, in [RFC3339](https://tools.ietf.org/html/rfc3339) format. Example: `2018-03-20T12:32:53.532Z`
	TimeRetrieved pulumi.StringOutput `pulumi:"timeRetrieved"`
}

// NewCoreAppCatalogSubscription registers a new resource with the given unique name, arguments, and options.
func NewCoreAppCatalogSubscription(ctx *pulumi.Context,
	name string, args *CoreAppCatalogSubscriptionArgs, opts ...pulumi.ResourceOption) (*CoreAppCatalogSubscription, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.ListingId == nil {
		return nil, errors.New("invalid value for required argument 'ListingId'")
	}
	if args.ListingResourceVersion == nil {
		return nil, errors.New("invalid value for required argument 'ListingResourceVersion'")
	}
	if args.OracleTermsOfUseLink == nil {
		return nil, errors.New("invalid value for required argument 'OracleTermsOfUseLink'")
	}
	if args.Signature == nil {
		return nil, errors.New("invalid value for required argument 'Signature'")
	}
	if args.TimeRetrieved == nil {
		return nil, errors.New("invalid value for required argument 'TimeRetrieved'")
	}
	var resource CoreAppCatalogSubscription
	err := ctx.RegisterResource("oci:index/coreAppCatalogSubscription:CoreAppCatalogSubscription", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetCoreAppCatalogSubscription gets an existing CoreAppCatalogSubscription resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetCoreAppCatalogSubscription(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *CoreAppCatalogSubscriptionState, opts ...pulumi.ResourceOption) (*CoreAppCatalogSubscription, error) {
	var resource CoreAppCatalogSubscription
	err := ctx.ReadResource("oci:index/coreAppCatalogSubscription:CoreAppCatalogSubscription", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering CoreAppCatalogSubscription resources.
type coreAppCatalogSubscriptionState struct {
	// The compartmentID for the subscription.
	CompartmentId *string `pulumi:"compartmentId"`
	// The display name of the listing.
	DisplayName *string `pulumi:"displayName"`
	// EULA link
	EulaLink *string `pulumi:"eulaLink"`
	// The OCID of the listing.
	ListingId *string `pulumi:"listingId"`
	// Listing resource id.
	ListingResourceId *string `pulumi:"listingResourceId"`
	// Listing resource version.
	ListingResourceVersion *string `pulumi:"listingResourceVersion"`
	// Oracle TOU link
	OracleTermsOfUseLink *string `pulumi:"oracleTermsOfUseLink"`
	// Name of the publisher who published this listing.
	PublisherName *string `pulumi:"publisherName"`
	// A generated signature for this listing resource version retrieved the agreements API.
	Signature *string `pulumi:"signature"`
	// The short summary to the listing.
	Summary *string `pulumi:"summary"`
	// Date and time at which the subscription was created, in [RFC3339](https://tools.ietf.org/html/rfc3339) format. Example: `2018-03-20T12:32:53.532Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// Date and time the agreements were retrieved, in [RFC3339](https://tools.ietf.org/html/rfc3339) format. Example: `2018-03-20T12:32:53.532Z`
	TimeRetrieved *string `pulumi:"timeRetrieved"`
}

type CoreAppCatalogSubscriptionState struct {
	// The compartmentID for the subscription.
	CompartmentId pulumi.StringPtrInput
	// The display name of the listing.
	DisplayName pulumi.StringPtrInput
	// EULA link
	EulaLink pulumi.StringPtrInput
	// The OCID of the listing.
	ListingId pulumi.StringPtrInput
	// Listing resource id.
	ListingResourceId pulumi.StringPtrInput
	// Listing resource version.
	ListingResourceVersion pulumi.StringPtrInput
	// Oracle TOU link
	OracleTermsOfUseLink pulumi.StringPtrInput
	// Name of the publisher who published this listing.
	PublisherName pulumi.StringPtrInput
	// A generated signature for this listing resource version retrieved the agreements API.
	Signature pulumi.StringPtrInput
	// The short summary to the listing.
	Summary pulumi.StringPtrInput
	// Date and time at which the subscription was created, in [RFC3339](https://tools.ietf.org/html/rfc3339) format. Example: `2018-03-20T12:32:53.532Z`
	TimeCreated pulumi.StringPtrInput
	// Date and time the agreements were retrieved, in [RFC3339](https://tools.ietf.org/html/rfc3339) format. Example: `2018-03-20T12:32:53.532Z`
	TimeRetrieved pulumi.StringPtrInput
}

func (CoreAppCatalogSubscriptionState) ElementType() reflect.Type {
	return reflect.TypeOf((*coreAppCatalogSubscriptionState)(nil)).Elem()
}

type coreAppCatalogSubscriptionArgs struct {
	// The compartmentID for the subscription.
	CompartmentId string `pulumi:"compartmentId"`
	// EULA link
	EulaLink *string `pulumi:"eulaLink"`
	// The OCID of the listing.
	ListingId string `pulumi:"listingId"`
	// Listing resource version.
	ListingResourceVersion string `pulumi:"listingResourceVersion"`
	// Oracle TOU link
	OracleTermsOfUseLink string `pulumi:"oracleTermsOfUseLink"`
	// A generated signature for this listing resource version retrieved the agreements API.
	Signature string `pulumi:"signature"`
	// Date and time the agreements were retrieved, in [RFC3339](https://tools.ietf.org/html/rfc3339) format. Example: `2018-03-20T12:32:53.532Z`
	TimeRetrieved string `pulumi:"timeRetrieved"`
}

// The set of arguments for constructing a CoreAppCatalogSubscription resource.
type CoreAppCatalogSubscriptionArgs struct {
	// The compartmentID for the subscription.
	CompartmentId pulumi.StringInput
	// EULA link
	EulaLink pulumi.StringPtrInput
	// The OCID of the listing.
	ListingId pulumi.StringInput
	// Listing resource version.
	ListingResourceVersion pulumi.StringInput
	// Oracle TOU link
	OracleTermsOfUseLink pulumi.StringInput
	// A generated signature for this listing resource version retrieved the agreements API.
	Signature pulumi.StringInput
	// Date and time the agreements were retrieved, in [RFC3339](https://tools.ietf.org/html/rfc3339) format. Example: `2018-03-20T12:32:53.532Z`
	TimeRetrieved pulumi.StringInput
}

func (CoreAppCatalogSubscriptionArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*coreAppCatalogSubscriptionArgs)(nil)).Elem()
}

type CoreAppCatalogSubscriptionInput interface {
	pulumi.Input

	ToCoreAppCatalogSubscriptionOutput() CoreAppCatalogSubscriptionOutput
	ToCoreAppCatalogSubscriptionOutputWithContext(ctx context.Context) CoreAppCatalogSubscriptionOutput
}

func (*CoreAppCatalogSubscription) ElementType() reflect.Type {
	return reflect.TypeOf((*CoreAppCatalogSubscription)(nil))
}

func (i *CoreAppCatalogSubscription) ToCoreAppCatalogSubscriptionOutput() CoreAppCatalogSubscriptionOutput {
	return i.ToCoreAppCatalogSubscriptionOutputWithContext(context.Background())
}

func (i *CoreAppCatalogSubscription) ToCoreAppCatalogSubscriptionOutputWithContext(ctx context.Context) CoreAppCatalogSubscriptionOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreAppCatalogSubscriptionOutput)
}

func (i *CoreAppCatalogSubscription) ToCoreAppCatalogSubscriptionPtrOutput() CoreAppCatalogSubscriptionPtrOutput {
	return i.ToCoreAppCatalogSubscriptionPtrOutputWithContext(context.Background())
}

func (i *CoreAppCatalogSubscription) ToCoreAppCatalogSubscriptionPtrOutputWithContext(ctx context.Context) CoreAppCatalogSubscriptionPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreAppCatalogSubscriptionPtrOutput)
}

type CoreAppCatalogSubscriptionPtrInput interface {
	pulumi.Input

	ToCoreAppCatalogSubscriptionPtrOutput() CoreAppCatalogSubscriptionPtrOutput
	ToCoreAppCatalogSubscriptionPtrOutputWithContext(ctx context.Context) CoreAppCatalogSubscriptionPtrOutput
}

type coreAppCatalogSubscriptionPtrType CoreAppCatalogSubscriptionArgs

func (*coreAppCatalogSubscriptionPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**CoreAppCatalogSubscription)(nil))
}

func (i *coreAppCatalogSubscriptionPtrType) ToCoreAppCatalogSubscriptionPtrOutput() CoreAppCatalogSubscriptionPtrOutput {
	return i.ToCoreAppCatalogSubscriptionPtrOutputWithContext(context.Background())
}

func (i *coreAppCatalogSubscriptionPtrType) ToCoreAppCatalogSubscriptionPtrOutputWithContext(ctx context.Context) CoreAppCatalogSubscriptionPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreAppCatalogSubscriptionPtrOutput)
}

// CoreAppCatalogSubscriptionArrayInput is an input type that accepts CoreAppCatalogSubscriptionArray and CoreAppCatalogSubscriptionArrayOutput values.
// You can construct a concrete instance of `CoreAppCatalogSubscriptionArrayInput` via:
//
//          CoreAppCatalogSubscriptionArray{ CoreAppCatalogSubscriptionArgs{...} }
type CoreAppCatalogSubscriptionArrayInput interface {
	pulumi.Input

	ToCoreAppCatalogSubscriptionArrayOutput() CoreAppCatalogSubscriptionArrayOutput
	ToCoreAppCatalogSubscriptionArrayOutputWithContext(context.Context) CoreAppCatalogSubscriptionArrayOutput
}

type CoreAppCatalogSubscriptionArray []CoreAppCatalogSubscriptionInput

func (CoreAppCatalogSubscriptionArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*CoreAppCatalogSubscription)(nil)).Elem()
}

func (i CoreAppCatalogSubscriptionArray) ToCoreAppCatalogSubscriptionArrayOutput() CoreAppCatalogSubscriptionArrayOutput {
	return i.ToCoreAppCatalogSubscriptionArrayOutputWithContext(context.Background())
}

func (i CoreAppCatalogSubscriptionArray) ToCoreAppCatalogSubscriptionArrayOutputWithContext(ctx context.Context) CoreAppCatalogSubscriptionArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreAppCatalogSubscriptionArrayOutput)
}

// CoreAppCatalogSubscriptionMapInput is an input type that accepts CoreAppCatalogSubscriptionMap and CoreAppCatalogSubscriptionMapOutput values.
// You can construct a concrete instance of `CoreAppCatalogSubscriptionMapInput` via:
//
//          CoreAppCatalogSubscriptionMap{ "key": CoreAppCatalogSubscriptionArgs{...} }
type CoreAppCatalogSubscriptionMapInput interface {
	pulumi.Input

	ToCoreAppCatalogSubscriptionMapOutput() CoreAppCatalogSubscriptionMapOutput
	ToCoreAppCatalogSubscriptionMapOutputWithContext(context.Context) CoreAppCatalogSubscriptionMapOutput
}

type CoreAppCatalogSubscriptionMap map[string]CoreAppCatalogSubscriptionInput

func (CoreAppCatalogSubscriptionMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*CoreAppCatalogSubscription)(nil)).Elem()
}

func (i CoreAppCatalogSubscriptionMap) ToCoreAppCatalogSubscriptionMapOutput() CoreAppCatalogSubscriptionMapOutput {
	return i.ToCoreAppCatalogSubscriptionMapOutputWithContext(context.Background())
}

func (i CoreAppCatalogSubscriptionMap) ToCoreAppCatalogSubscriptionMapOutputWithContext(ctx context.Context) CoreAppCatalogSubscriptionMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CoreAppCatalogSubscriptionMapOutput)
}

type CoreAppCatalogSubscriptionOutput struct {
	*pulumi.OutputState
}

func (CoreAppCatalogSubscriptionOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*CoreAppCatalogSubscription)(nil))
}

func (o CoreAppCatalogSubscriptionOutput) ToCoreAppCatalogSubscriptionOutput() CoreAppCatalogSubscriptionOutput {
	return o
}

func (o CoreAppCatalogSubscriptionOutput) ToCoreAppCatalogSubscriptionOutputWithContext(ctx context.Context) CoreAppCatalogSubscriptionOutput {
	return o
}

func (o CoreAppCatalogSubscriptionOutput) ToCoreAppCatalogSubscriptionPtrOutput() CoreAppCatalogSubscriptionPtrOutput {
	return o.ToCoreAppCatalogSubscriptionPtrOutputWithContext(context.Background())
}

func (o CoreAppCatalogSubscriptionOutput) ToCoreAppCatalogSubscriptionPtrOutputWithContext(ctx context.Context) CoreAppCatalogSubscriptionPtrOutput {
	return o.ApplyT(func(v CoreAppCatalogSubscription) *CoreAppCatalogSubscription {
		return &v
	}).(CoreAppCatalogSubscriptionPtrOutput)
}

type CoreAppCatalogSubscriptionPtrOutput struct {
	*pulumi.OutputState
}

func (CoreAppCatalogSubscriptionPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**CoreAppCatalogSubscription)(nil))
}

func (o CoreAppCatalogSubscriptionPtrOutput) ToCoreAppCatalogSubscriptionPtrOutput() CoreAppCatalogSubscriptionPtrOutput {
	return o
}

func (o CoreAppCatalogSubscriptionPtrOutput) ToCoreAppCatalogSubscriptionPtrOutputWithContext(ctx context.Context) CoreAppCatalogSubscriptionPtrOutput {
	return o
}

type CoreAppCatalogSubscriptionArrayOutput struct{ *pulumi.OutputState }

func (CoreAppCatalogSubscriptionArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]CoreAppCatalogSubscription)(nil))
}

func (o CoreAppCatalogSubscriptionArrayOutput) ToCoreAppCatalogSubscriptionArrayOutput() CoreAppCatalogSubscriptionArrayOutput {
	return o
}

func (o CoreAppCatalogSubscriptionArrayOutput) ToCoreAppCatalogSubscriptionArrayOutputWithContext(ctx context.Context) CoreAppCatalogSubscriptionArrayOutput {
	return o
}

func (o CoreAppCatalogSubscriptionArrayOutput) Index(i pulumi.IntInput) CoreAppCatalogSubscriptionOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) CoreAppCatalogSubscription {
		return vs[0].([]CoreAppCatalogSubscription)[vs[1].(int)]
	}).(CoreAppCatalogSubscriptionOutput)
}

type CoreAppCatalogSubscriptionMapOutput struct{ *pulumi.OutputState }

func (CoreAppCatalogSubscriptionMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]CoreAppCatalogSubscription)(nil))
}

func (o CoreAppCatalogSubscriptionMapOutput) ToCoreAppCatalogSubscriptionMapOutput() CoreAppCatalogSubscriptionMapOutput {
	return o
}

func (o CoreAppCatalogSubscriptionMapOutput) ToCoreAppCatalogSubscriptionMapOutputWithContext(ctx context.Context) CoreAppCatalogSubscriptionMapOutput {
	return o
}

func (o CoreAppCatalogSubscriptionMapOutput) MapIndex(k pulumi.StringInput) CoreAppCatalogSubscriptionOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) CoreAppCatalogSubscription {
		return vs[0].(map[string]CoreAppCatalogSubscription)[vs[1].(string)]
	}).(CoreAppCatalogSubscriptionOutput)
}

func init() {
	pulumi.RegisterOutputType(CoreAppCatalogSubscriptionOutput{})
	pulumi.RegisterOutputType(CoreAppCatalogSubscriptionPtrOutput{})
	pulumi.RegisterOutputType(CoreAppCatalogSubscriptionArrayOutput{})
	pulumi.RegisterOutputType(CoreAppCatalogSubscriptionMapOutput{})
}
