// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Function resource in Oracle Cloud Infrastructure Functions service.
//
// Creates a new function.
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
// 		_, err := oci.NewFunctionsFunction(ctx, "testFunction", &oci.FunctionsFunctionArgs{
// 			ApplicationId: pulumi.Any(oci_functions_application.Test_application.Id),
// 			DisplayName:   pulumi.Any(_var.Function_display_name),
// 			Image:         pulumi.Any(_var.Function_image),
// 			MemoryInMbs:   pulumi.Any(_var.Function_memory_in_mbs),
// 			Config:        pulumi.Any(_var.Function_config),
// 			DefinedTags: pulumi.AnyMap{
// 				"Operations.CostCenter": pulumi.Any("42"),
// 			},
// 			FreeformTags: pulumi.AnyMap{
// 				"Department": pulumi.Any("Finance"),
// 			},
// 			ImageDigest:      pulumi.Any(_var.Function_image_digest),
// 			TimeoutInSeconds: pulumi.Any(_var.Function_timeout_in_seconds),
// 			TraceConfig: &FunctionsFunctionTraceConfigArgs{
// 				IsEnabled: pulumi.Any(_var.Function_trace_config_is_enabled),
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
// Functions can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/functionsFunction:FunctionsFunction test_function "id"
// ```
type FunctionsFunction struct {
	pulumi.CustomResourceState

	// The OCID of the application this function belongs to.
	ApplicationId pulumi.StringOutput `pulumi:"applicationId"`
	// The OCID of the compartment that contains the function.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Function configuration. These values are passed on to the function as environment variables, this overrides application configuration values. Keys must be ASCII strings consisting solely of letters, digits, and the '_' (underscore) character, and must not begin with a digit. Values should be limited to printable unicode characters.  Example: `{"MY_FUNCTION_CONFIG": "ConfVal"}`
	Config pulumi.MapOutput `pulumi:"config"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// The display name of the function. The display name must be unique within the application containing the function. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// (Updatable) The qualified name of the Docker image to use in the function, including the image tag. The image should be in the Oracle Cloud Infrastructure Registry that is in the same region as the function itself. This field must be updated if imageDigest is updated. Example: `phx.ocir.io/ten/functions/function:0.0.1`
	Image pulumi.StringOutput `pulumi:"image"`
	// (Updatable) The image digest for the version of the image that will be pulled when invoking this function. If no value is specified, the digest currently associated with the image in the Oracle Cloud Infrastructure Registry will be used. This field must be updated if image is updated. Example: `sha256:ca0eeb6fb05351dfc8759c20733c91def84cb8007aa89a5bf606bc8b315b9fc7`
	ImageDigest pulumi.StringOutput `pulumi:"imageDigest"`
	// The base https invoke URL to set on a client in order to invoke a function. This URL will never change over the lifetime of the function and can be cached.
	InvokeEndpoint pulumi.StringOutput `pulumi:"invokeEndpoint"`
	// (Updatable) Maximum usable memory for the function (MiB).
	MemoryInMbs pulumi.StringOutput `pulumi:"memoryInMbs"`
	// The current state of the function.
	State pulumi.StringOutput `pulumi:"state"`
	// The time the function was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time the function was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// (Updatable) Timeout for executions of the function. Value in seconds.
	TimeoutInSeconds pulumi.IntOutput `pulumi:"timeoutInSeconds"`
	// (Updatable) Define the tracing configuration for a function.
	TraceConfig FunctionsFunctionTraceConfigOutput `pulumi:"traceConfig"`
}

// NewFunctionsFunction registers a new resource with the given unique name, arguments, and options.
func NewFunctionsFunction(ctx *pulumi.Context,
	name string, args *FunctionsFunctionArgs, opts ...pulumi.ResourceOption) (*FunctionsFunction, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ApplicationId == nil {
		return nil, errors.New("invalid value for required argument 'ApplicationId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	if args.Image == nil {
		return nil, errors.New("invalid value for required argument 'Image'")
	}
	if args.MemoryInMbs == nil {
		return nil, errors.New("invalid value for required argument 'MemoryInMbs'")
	}
	var resource FunctionsFunction
	err := ctx.RegisterResource("oci:index/functionsFunction:FunctionsFunction", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetFunctionsFunction gets an existing FunctionsFunction resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetFunctionsFunction(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *FunctionsFunctionState, opts ...pulumi.ResourceOption) (*FunctionsFunction, error) {
	var resource FunctionsFunction
	err := ctx.ReadResource("oci:index/functionsFunction:FunctionsFunction", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering FunctionsFunction resources.
type functionsFunctionState struct {
	// The OCID of the application this function belongs to.
	ApplicationId *string `pulumi:"applicationId"`
	// The OCID of the compartment that contains the function.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Function configuration. These values are passed on to the function as environment variables, this overrides application configuration values. Keys must be ASCII strings consisting solely of letters, digits, and the '_' (underscore) character, and must not begin with a digit. Values should be limited to printable unicode characters.  Example: `{"MY_FUNCTION_CONFIG": "ConfVal"}`
	Config map[string]interface{} `pulumi:"config"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The display name of the function. The display name must be unique within the application containing the function. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) The qualified name of the Docker image to use in the function, including the image tag. The image should be in the Oracle Cloud Infrastructure Registry that is in the same region as the function itself. This field must be updated if imageDigest is updated. Example: `phx.ocir.io/ten/functions/function:0.0.1`
	Image *string `pulumi:"image"`
	// (Updatable) The image digest for the version of the image that will be pulled when invoking this function. If no value is specified, the digest currently associated with the image in the Oracle Cloud Infrastructure Registry will be used. This field must be updated if image is updated. Example: `sha256:ca0eeb6fb05351dfc8759c20733c91def84cb8007aa89a5bf606bc8b315b9fc7`
	ImageDigest *string `pulumi:"imageDigest"`
	// The base https invoke URL to set on a client in order to invoke a function. This URL will never change over the lifetime of the function and can be cached.
	InvokeEndpoint *string `pulumi:"invokeEndpoint"`
	// (Updatable) Maximum usable memory for the function (MiB).
	MemoryInMbs *string `pulumi:"memoryInMbs"`
	// The current state of the function.
	State *string `pulumi:"state"`
	// The time the function was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// The time the function was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
	TimeUpdated *string `pulumi:"timeUpdated"`
	// (Updatable) Timeout for executions of the function. Value in seconds.
	TimeoutInSeconds *int `pulumi:"timeoutInSeconds"`
	// (Updatable) Define the tracing configuration for a function.
	TraceConfig *FunctionsFunctionTraceConfig `pulumi:"traceConfig"`
}

type FunctionsFunctionState struct {
	// The OCID of the application this function belongs to.
	ApplicationId pulumi.StringPtrInput
	// The OCID of the compartment that contains the function.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Function configuration. These values are passed on to the function as environment variables, this overrides application configuration values. Keys must be ASCII strings consisting solely of letters, digits, and the '_' (underscore) character, and must not begin with a digit. Values should be limited to printable unicode characters.  Example: `{"MY_FUNCTION_CONFIG": "ConfVal"}`
	Config pulumi.MapInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// The display name of the function. The display name must be unique within the application containing the function. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) The qualified name of the Docker image to use in the function, including the image tag. The image should be in the Oracle Cloud Infrastructure Registry that is in the same region as the function itself. This field must be updated if imageDigest is updated. Example: `phx.ocir.io/ten/functions/function:0.0.1`
	Image pulumi.StringPtrInput
	// (Updatable) The image digest for the version of the image that will be pulled when invoking this function. If no value is specified, the digest currently associated with the image in the Oracle Cloud Infrastructure Registry will be used. This field must be updated if image is updated. Example: `sha256:ca0eeb6fb05351dfc8759c20733c91def84cb8007aa89a5bf606bc8b315b9fc7`
	ImageDigest pulumi.StringPtrInput
	// The base https invoke URL to set on a client in order to invoke a function. This URL will never change over the lifetime of the function and can be cached.
	InvokeEndpoint pulumi.StringPtrInput
	// (Updatable) Maximum usable memory for the function (MiB).
	MemoryInMbs pulumi.StringPtrInput
	// The current state of the function.
	State pulumi.StringPtrInput
	// The time the function was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
	TimeCreated pulumi.StringPtrInput
	// The time the function was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
	TimeUpdated pulumi.StringPtrInput
	// (Updatable) Timeout for executions of the function. Value in seconds.
	TimeoutInSeconds pulumi.IntPtrInput
	// (Updatable) Define the tracing configuration for a function.
	TraceConfig FunctionsFunctionTraceConfigPtrInput
}

func (FunctionsFunctionState) ElementType() reflect.Type {
	return reflect.TypeOf((*functionsFunctionState)(nil)).Elem()
}

type functionsFunctionArgs struct {
	// The OCID of the application this function belongs to.
	ApplicationId string `pulumi:"applicationId"`
	// (Updatable) Function configuration. These values are passed on to the function as environment variables, this overrides application configuration values. Keys must be ASCII strings consisting solely of letters, digits, and the '_' (underscore) character, and must not begin with a digit. Values should be limited to printable unicode characters.  Example: `{"MY_FUNCTION_CONFIG": "ConfVal"}`
	Config map[string]interface{} `pulumi:"config"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The display name of the function. The display name must be unique within the application containing the function. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) The qualified name of the Docker image to use in the function, including the image tag. The image should be in the Oracle Cloud Infrastructure Registry that is in the same region as the function itself. This field must be updated if imageDigest is updated. Example: `phx.ocir.io/ten/functions/function:0.0.1`
	Image string `pulumi:"image"`
	// (Updatable) The image digest for the version of the image that will be pulled when invoking this function. If no value is specified, the digest currently associated with the image in the Oracle Cloud Infrastructure Registry will be used. This field must be updated if image is updated. Example: `sha256:ca0eeb6fb05351dfc8759c20733c91def84cb8007aa89a5bf606bc8b315b9fc7`
	ImageDigest *string `pulumi:"imageDigest"`
	// (Updatable) Maximum usable memory for the function (MiB).
	MemoryInMbs string `pulumi:"memoryInMbs"`
	// (Updatable) Timeout for executions of the function. Value in seconds.
	TimeoutInSeconds *int `pulumi:"timeoutInSeconds"`
	// (Updatable) Define the tracing configuration for a function.
	TraceConfig *FunctionsFunctionTraceConfig `pulumi:"traceConfig"`
}

// The set of arguments for constructing a FunctionsFunction resource.
type FunctionsFunctionArgs struct {
	// The OCID of the application this function belongs to.
	ApplicationId pulumi.StringInput
	// (Updatable) Function configuration. These values are passed on to the function as environment variables, this overrides application configuration values. Keys must be ASCII strings consisting solely of letters, digits, and the '_' (underscore) character, and must not begin with a digit. Values should be limited to printable unicode characters.  Example: `{"MY_FUNCTION_CONFIG": "ConfVal"}`
	Config pulumi.MapInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// The display name of the function. The display name must be unique within the application containing the function. Avoid entering confidential information.
	DisplayName pulumi.StringInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) The qualified name of the Docker image to use in the function, including the image tag. The image should be in the Oracle Cloud Infrastructure Registry that is in the same region as the function itself. This field must be updated if imageDigest is updated. Example: `phx.ocir.io/ten/functions/function:0.0.1`
	Image pulumi.StringInput
	// (Updatable) The image digest for the version of the image that will be pulled when invoking this function. If no value is specified, the digest currently associated with the image in the Oracle Cloud Infrastructure Registry will be used. This field must be updated if image is updated. Example: `sha256:ca0eeb6fb05351dfc8759c20733c91def84cb8007aa89a5bf606bc8b315b9fc7`
	ImageDigest pulumi.StringPtrInput
	// (Updatable) Maximum usable memory for the function (MiB).
	MemoryInMbs pulumi.StringInput
	// (Updatable) Timeout for executions of the function. Value in seconds.
	TimeoutInSeconds pulumi.IntPtrInput
	// (Updatable) Define the tracing configuration for a function.
	TraceConfig FunctionsFunctionTraceConfigPtrInput
}

func (FunctionsFunctionArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*functionsFunctionArgs)(nil)).Elem()
}

type FunctionsFunctionInput interface {
	pulumi.Input

	ToFunctionsFunctionOutput() FunctionsFunctionOutput
	ToFunctionsFunctionOutputWithContext(ctx context.Context) FunctionsFunctionOutput
}

func (*FunctionsFunction) ElementType() reflect.Type {
	return reflect.TypeOf((*FunctionsFunction)(nil))
}

func (i *FunctionsFunction) ToFunctionsFunctionOutput() FunctionsFunctionOutput {
	return i.ToFunctionsFunctionOutputWithContext(context.Background())
}

func (i *FunctionsFunction) ToFunctionsFunctionOutputWithContext(ctx context.Context) FunctionsFunctionOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FunctionsFunctionOutput)
}

func (i *FunctionsFunction) ToFunctionsFunctionPtrOutput() FunctionsFunctionPtrOutput {
	return i.ToFunctionsFunctionPtrOutputWithContext(context.Background())
}

func (i *FunctionsFunction) ToFunctionsFunctionPtrOutputWithContext(ctx context.Context) FunctionsFunctionPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FunctionsFunctionPtrOutput)
}

type FunctionsFunctionPtrInput interface {
	pulumi.Input

	ToFunctionsFunctionPtrOutput() FunctionsFunctionPtrOutput
	ToFunctionsFunctionPtrOutputWithContext(ctx context.Context) FunctionsFunctionPtrOutput
}

type functionsFunctionPtrType FunctionsFunctionArgs

func (*functionsFunctionPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**FunctionsFunction)(nil))
}

func (i *functionsFunctionPtrType) ToFunctionsFunctionPtrOutput() FunctionsFunctionPtrOutput {
	return i.ToFunctionsFunctionPtrOutputWithContext(context.Background())
}

func (i *functionsFunctionPtrType) ToFunctionsFunctionPtrOutputWithContext(ctx context.Context) FunctionsFunctionPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FunctionsFunctionPtrOutput)
}

// FunctionsFunctionArrayInput is an input type that accepts FunctionsFunctionArray and FunctionsFunctionArrayOutput values.
// You can construct a concrete instance of `FunctionsFunctionArrayInput` via:
//
//          FunctionsFunctionArray{ FunctionsFunctionArgs{...} }
type FunctionsFunctionArrayInput interface {
	pulumi.Input

	ToFunctionsFunctionArrayOutput() FunctionsFunctionArrayOutput
	ToFunctionsFunctionArrayOutputWithContext(context.Context) FunctionsFunctionArrayOutput
}

type FunctionsFunctionArray []FunctionsFunctionInput

func (FunctionsFunctionArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*FunctionsFunction)(nil)).Elem()
}

func (i FunctionsFunctionArray) ToFunctionsFunctionArrayOutput() FunctionsFunctionArrayOutput {
	return i.ToFunctionsFunctionArrayOutputWithContext(context.Background())
}

func (i FunctionsFunctionArray) ToFunctionsFunctionArrayOutputWithContext(ctx context.Context) FunctionsFunctionArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FunctionsFunctionArrayOutput)
}

// FunctionsFunctionMapInput is an input type that accepts FunctionsFunctionMap and FunctionsFunctionMapOutput values.
// You can construct a concrete instance of `FunctionsFunctionMapInput` via:
//
//          FunctionsFunctionMap{ "key": FunctionsFunctionArgs{...} }
type FunctionsFunctionMapInput interface {
	pulumi.Input

	ToFunctionsFunctionMapOutput() FunctionsFunctionMapOutput
	ToFunctionsFunctionMapOutputWithContext(context.Context) FunctionsFunctionMapOutput
}

type FunctionsFunctionMap map[string]FunctionsFunctionInput

func (FunctionsFunctionMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*FunctionsFunction)(nil)).Elem()
}

func (i FunctionsFunctionMap) ToFunctionsFunctionMapOutput() FunctionsFunctionMapOutput {
	return i.ToFunctionsFunctionMapOutputWithContext(context.Background())
}

func (i FunctionsFunctionMap) ToFunctionsFunctionMapOutputWithContext(ctx context.Context) FunctionsFunctionMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FunctionsFunctionMapOutput)
}

type FunctionsFunctionOutput struct {
	*pulumi.OutputState
}

func (FunctionsFunctionOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*FunctionsFunction)(nil))
}

func (o FunctionsFunctionOutput) ToFunctionsFunctionOutput() FunctionsFunctionOutput {
	return o
}

func (o FunctionsFunctionOutput) ToFunctionsFunctionOutputWithContext(ctx context.Context) FunctionsFunctionOutput {
	return o
}

func (o FunctionsFunctionOutput) ToFunctionsFunctionPtrOutput() FunctionsFunctionPtrOutput {
	return o.ToFunctionsFunctionPtrOutputWithContext(context.Background())
}

func (o FunctionsFunctionOutput) ToFunctionsFunctionPtrOutputWithContext(ctx context.Context) FunctionsFunctionPtrOutput {
	return o.ApplyT(func(v FunctionsFunction) *FunctionsFunction {
		return &v
	}).(FunctionsFunctionPtrOutput)
}

type FunctionsFunctionPtrOutput struct {
	*pulumi.OutputState
}

func (FunctionsFunctionPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**FunctionsFunction)(nil))
}

func (o FunctionsFunctionPtrOutput) ToFunctionsFunctionPtrOutput() FunctionsFunctionPtrOutput {
	return o
}

func (o FunctionsFunctionPtrOutput) ToFunctionsFunctionPtrOutputWithContext(ctx context.Context) FunctionsFunctionPtrOutput {
	return o
}

type FunctionsFunctionArrayOutput struct{ *pulumi.OutputState }

func (FunctionsFunctionArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]FunctionsFunction)(nil))
}

func (o FunctionsFunctionArrayOutput) ToFunctionsFunctionArrayOutput() FunctionsFunctionArrayOutput {
	return o
}

func (o FunctionsFunctionArrayOutput) ToFunctionsFunctionArrayOutputWithContext(ctx context.Context) FunctionsFunctionArrayOutput {
	return o
}

func (o FunctionsFunctionArrayOutput) Index(i pulumi.IntInput) FunctionsFunctionOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) FunctionsFunction {
		return vs[0].([]FunctionsFunction)[vs[1].(int)]
	}).(FunctionsFunctionOutput)
}

type FunctionsFunctionMapOutput struct{ *pulumi.OutputState }

func (FunctionsFunctionMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]FunctionsFunction)(nil))
}

func (o FunctionsFunctionMapOutput) ToFunctionsFunctionMapOutput() FunctionsFunctionMapOutput {
	return o
}

func (o FunctionsFunctionMapOutput) ToFunctionsFunctionMapOutputWithContext(ctx context.Context) FunctionsFunctionMapOutput {
	return o
}

func (o FunctionsFunctionMapOutput) MapIndex(k pulumi.StringInput) FunctionsFunctionOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) FunctionsFunction {
		return vs[0].(map[string]FunctionsFunction)[vs[1].(string)]
	}).(FunctionsFunctionOutput)
}

func init() {
	pulumi.RegisterOutputType(FunctionsFunctionOutput{})
	pulumi.RegisterOutputType(FunctionsFunctionPtrOutput{})
	pulumi.RegisterOutputType(FunctionsFunctionArrayOutput{})
	pulumi.RegisterOutputType(FunctionsFunctionMapOutput{})
}
