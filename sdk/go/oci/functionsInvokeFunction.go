// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Invoke Function resource in Oracle Cloud Infrastructure Functions service.
//
// Invokes a function
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
// 		_, err := oci.NewFunctionsInvokeFunction(ctx, "testInvokeFunction", &oci.FunctionsInvokeFunctionArgs{
// 			FunctionId:          pulumi.Any(oci_functions_function.Test_function.Id),
// 			InvokeFunctionBody:  pulumi.Any(_var.Invoke_function_invoke_function_body),
// 			FnIntent:            pulumi.Any(_var.Invoke_function_fn_intent),
// 			FnInvokeType:        pulumi.Any(_var.Invoke_function_fn_invoke_type),
// 			Base64EncodeContent: pulumi.Bool(false),
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
// Import is not supported for this resource.
type FunctionsInvokeFunction struct {
	pulumi.CustomResourceState

	Base64EncodeContent pulumi.BoolPtrOutput `pulumi:"base64EncodeContent"`
	// Content of the response string, if any. If `base64EncodeContent` is set to `true`, then this content will be base64 encoded.
	Content pulumi.StringOutput `pulumi:"content"`
	// An optional intent header that indicates to the FDK the way the event should be interpreted. E.g. 'httprequest', 'cloudevent'.
	FnIntent pulumi.StringOutput `pulumi:"fnIntent"`
	// Indicates whether the functions platform should execute the request directly and return the result ('sync') or whether the platform should enqueue the request for later processing and acknowledge that it has been processed ('detached').
	FnInvokeType pulumi.StringOutput `pulumi:"fnInvokeType"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this function.
	FunctionId pulumi.StringOutput `pulumi:"functionId"`
	// An absolute path to a file on the local system that contains the input to be provided to the function. Cannot be defined if `invokeFunctionBody` or `invokeFunctionBodyBase64Encoded` is defined. Note: The maximum size of the request is limited. This limit is currently 6MB and the endpoint will not accept requests that are bigger than this limit.
	InputBodySourcePath pulumi.StringPtrOutput `pulumi:"inputBodySourcePath"`
	InvokeEndpoint      pulumi.StringOutput    `pulumi:"invokeEndpoint"`
	// The body of the function invocation. Note: The maximum size of the request is limited. This limit is currently 6MB and the endpoint will not accept requests that are bigger than this limit. Cannot be defined if `inputBodySourcePath` or `invokeFunctionBodyBase64Encoded` is defined.
	InvokeFunctionBody              pulumi.StringOutput `pulumi:"invokeFunctionBody"`
	InvokeFunctionBodyBase64Encoded pulumi.StringOutput `pulumi:"invokeFunctionBodyBase64Encoded"`
}

// NewFunctionsInvokeFunction registers a new resource with the given unique name, arguments, and options.
func NewFunctionsInvokeFunction(ctx *pulumi.Context,
	name string, args *FunctionsInvokeFunctionArgs, opts ...pulumi.ResourceOption) (*FunctionsInvokeFunction, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.FunctionId == nil {
		return nil, errors.New("invalid value for required argument 'FunctionId'")
	}
	var resource FunctionsInvokeFunction
	err := ctx.RegisterResource("oci:index/functionsInvokeFunction:FunctionsInvokeFunction", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetFunctionsInvokeFunction gets an existing FunctionsInvokeFunction resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetFunctionsInvokeFunction(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *FunctionsInvokeFunctionState, opts ...pulumi.ResourceOption) (*FunctionsInvokeFunction, error) {
	var resource FunctionsInvokeFunction
	err := ctx.ReadResource("oci:index/functionsInvokeFunction:FunctionsInvokeFunction", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering FunctionsInvokeFunction resources.
type functionsInvokeFunctionState struct {
	Base64EncodeContent *bool `pulumi:"base64EncodeContent"`
	// Content of the response string, if any. If `base64EncodeContent` is set to `true`, then this content will be base64 encoded.
	Content *string `pulumi:"content"`
	// An optional intent header that indicates to the FDK the way the event should be interpreted. E.g. 'httprequest', 'cloudevent'.
	FnIntent *string `pulumi:"fnIntent"`
	// Indicates whether the functions platform should execute the request directly and return the result ('sync') or whether the platform should enqueue the request for later processing and acknowledge that it has been processed ('detached').
	FnInvokeType *string `pulumi:"fnInvokeType"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this function.
	FunctionId *string `pulumi:"functionId"`
	// An absolute path to a file on the local system that contains the input to be provided to the function. Cannot be defined if `invokeFunctionBody` or `invokeFunctionBodyBase64Encoded` is defined. Note: The maximum size of the request is limited. This limit is currently 6MB and the endpoint will not accept requests that are bigger than this limit.
	InputBodySourcePath *string `pulumi:"inputBodySourcePath"`
	InvokeEndpoint      *string `pulumi:"invokeEndpoint"`
	// The body of the function invocation. Note: The maximum size of the request is limited. This limit is currently 6MB and the endpoint will not accept requests that are bigger than this limit. Cannot be defined if `inputBodySourcePath` or `invokeFunctionBodyBase64Encoded` is defined.
	InvokeFunctionBody              *string `pulumi:"invokeFunctionBody"`
	InvokeFunctionBodyBase64Encoded *string `pulumi:"invokeFunctionBodyBase64Encoded"`
}

type FunctionsInvokeFunctionState struct {
	Base64EncodeContent pulumi.BoolPtrInput
	// Content of the response string, if any. If `base64EncodeContent` is set to `true`, then this content will be base64 encoded.
	Content pulumi.StringPtrInput
	// An optional intent header that indicates to the FDK the way the event should be interpreted. E.g. 'httprequest', 'cloudevent'.
	FnIntent pulumi.StringPtrInput
	// Indicates whether the functions platform should execute the request directly and return the result ('sync') or whether the platform should enqueue the request for later processing and acknowledge that it has been processed ('detached').
	FnInvokeType pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this function.
	FunctionId pulumi.StringPtrInput
	// An absolute path to a file on the local system that contains the input to be provided to the function. Cannot be defined if `invokeFunctionBody` or `invokeFunctionBodyBase64Encoded` is defined. Note: The maximum size of the request is limited. This limit is currently 6MB and the endpoint will not accept requests that are bigger than this limit.
	InputBodySourcePath pulumi.StringPtrInput
	InvokeEndpoint      pulumi.StringPtrInput
	// The body of the function invocation. Note: The maximum size of the request is limited. This limit is currently 6MB and the endpoint will not accept requests that are bigger than this limit. Cannot be defined if `inputBodySourcePath` or `invokeFunctionBodyBase64Encoded` is defined.
	InvokeFunctionBody              pulumi.StringPtrInput
	InvokeFunctionBodyBase64Encoded pulumi.StringPtrInput
}

func (FunctionsInvokeFunctionState) ElementType() reflect.Type {
	return reflect.TypeOf((*functionsInvokeFunctionState)(nil)).Elem()
}

type functionsInvokeFunctionArgs struct {
	Base64EncodeContent *bool `pulumi:"base64EncodeContent"`
	// An optional intent header that indicates to the FDK the way the event should be interpreted. E.g. 'httprequest', 'cloudevent'.
	FnIntent *string `pulumi:"fnIntent"`
	// Indicates whether the functions platform should execute the request directly and return the result ('sync') or whether the platform should enqueue the request for later processing and acknowledge that it has been processed ('detached').
	FnInvokeType *string `pulumi:"fnInvokeType"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this function.
	FunctionId string `pulumi:"functionId"`
	// An absolute path to a file on the local system that contains the input to be provided to the function. Cannot be defined if `invokeFunctionBody` or `invokeFunctionBodyBase64Encoded` is defined. Note: The maximum size of the request is limited. This limit is currently 6MB and the endpoint will not accept requests that are bigger than this limit.
	InputBodySourcePath *string `pulumi:"inputBodySourcePath"`
	// The body of the function invocation. Note: The maximum size of the request is limited. This limit is currently 6MB and the endpoint will not accept requests that are bigger than this limit. Cannot be defined if `inputBodySourcePath` or `invokeFunctionBodyBase64Encoded` is defined.
	InvokeFunctionBody              *string `pulumi:"invokeFunctionBody"`
	InvokeFunctionBodyBase64Encoded *string `pulumi:"invokeFunctionBodyBase64Encoded"`
}

// The set of arguments for constructing a FunctionsInvokeFunction resource.
type FunctionsInvokeFunctionArgs struct {
	Base64EncodeContent pulumi.BoolPtrInput
	// An optional intent header that indicates to the FDK the way the event should be interpreted. E.g. 'httprequest', 'cloudevent'.
	FnIntent pulumi.StringPtrInput
	// Indicates whether the functions platform should execute the request directly and return the result ('sync') or whether the platform should enqueue the request for later processing and acknowledge that it has been processed ('detached').
	FnInvokeType pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this function.
	FunctionId pulumi.StringInput
	// An absolute path to a file on the local system that contains the input to be provided to the function. Cannot be defined if `invokeFunctionBody` or `invokeFunctionBodyBase64Encoded` is defined. Note: The maximum size of the request is limited. This limit is currently 6MB and the endpoint will not accept requests that are bigger than this limit.
	InputBodySourcePath pulumi.StringPtrInput
	// The body of the function invocation. Note: The maximum size of the request is limited. This limit is currently 6MB and the endpoint will not accept requests that are bigger than this limit. Cannot be defined if `inputBodySourcePath` or `invokeFunctionBodyBase64Encoded` is defined.
	InvokeFunctionBody              pulumi.StringPtrInput
	InvokeFunctionBodyBase64Encoded pulumi.StringPtrInput
}

func (FunctionsInvokeFunctionArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*functionsInvokeFunctionArgs)(nil)).Elem()
}

type FunctionsInvokeFunctionInput interface {
	pulumi.Input

	ToFunctionsInvokeFunctionOutput() FunctionsInvokeFunctionOutput
	ToFunctionsInvokeFunctionOutputWithContext(ctx context.Context) FunctionsInvokeFunctionOutput
}

func (*FunctionsInvokeFunction) ElementType() reflect.Type {
	return reflect.TypeOf((*FunctionsInvokeFunction)(nil))
}

func (i *FunctionsInvokeFunction) ToFunctionsInvokeFunctionOutput() FunctionsInvokeFunctionOutput {
	return i.ToFunctionsInvokeFunctionOutputWithContext(context.Background())
}

func (i *FunctionsInvokeFunction) ToFunctionsInvokeFunctionOutputWithContext(ctx context.Context) FunctionsInvokeFunctionOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FunctionsInvokeFunctionOutput)
}

func (i *FunctionsInvokeFunction) ToFunctionsInvokeFunctionPtrOutput() FunctionsInvokeFunctionPtrOutput {
	return i.ToFunctionsInvokeFunctionPtrOutputWithContext(context.Background())
}

func (i *FunctionsInvokeFunction) ToFunctionsInvokeFunctionPtrOutputWithContext(ctx context.Context) FunctionsInvokeFunctionPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FunctionsInvokeFunctionPtrOutput)
}

type FunctionsInvokeFunctionPtrInput interface {
	pulumi.Input

	ToFunctionsInvokeFunctionPtrOutput() FunctionsInvokeFunctionPtrOutput
	ToFunctionsInvokeFunctionPtrOutputWithContext(ctx context.Context) FunctionsInvokeFunctionPtrOutput
}

type functionsInvokeFunctionPtrType FunctionsInvokeFunctionArgs

func (*functionsInvokeFunctionPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**FunctionsInvokeFunction)(nil))
}

func (i *functionsInvokeFunctionPtrType) ToFunctionsInvokeFunctionPtrOutput() FunctionsInvokeFunctionPtrOutput {
	return i.ToFunctionsInvokeFunctionPtrOutputWithContext(context.Background())
}

func (i *functionsInvokeFunctionPtrType) ToFunctionsInvokeFunctionPtrOutputWithContext(ctx context.Context) FunctionsInvokeFunctionPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FunctionsInvokeFunctionPtrOutput)
}

// FunctionsInvokeFunctionArrayInput is an input type that accepts FunctionsInvokeFunctionArray and FunctionsInvokeFunctionArrayOutput values.
// You can construct a concrete instance of `FunctionsInvokeFunctionArrayInput` via:
//
//          FunctionsInvokeFunctionArray{ FunctionsInvokeFunctionArgs{...} }
type FunctionsInvokeFunctionArrayInput interface {
	pulumi.Input

	ToFunctionsInvokeFunctionArrayOutput() FunctionsInvokeFunctionArrayOutput
	ToFunctionsInvokeFunctionArrayOutputWithContext(context.Context) FunctionsInvokeFunctionArrayOutput
}

type FunctionsInvokeFunctionArray []FunctionsInvokeFunctionInput

func (FunctionsInvokeFunctionArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*FunctionsInvokeFunction)(nil)).Elem()
}

func (i FunctionsInvokeFunctionArray) ToFunctionsInvokeFunctionArrayOutput() FunctionsInvokeFunctionArrayOutput {
	return i.ToFunctionsInvokeFunctionArrayOutputWithContext(context.Background())
}

func (i FunctionsInvokeFunctionArray) ToFunctionsInvokeFunctionArrayOutputWithContext(ctx context.Context) FunctionsInvokeFunctionArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FunctionsInvokeFunctionArrayOutput)
}

// FunctionsInvokeFunctionMapInput is an input type that accepts FunctionsInvokeFunctionMap and FunctionsInvokeFunctionMapOutput values.
// You can construct a concrete instance of `FunctionsInvokeFunctionMapInput` via:
//
//          FunctionsInvokeFunctionMap{ "key": FunctionsInvokeFunctionArgs{...} }
type FunctionsInvokeFunctionMapInput interface {
	pulumi.Input

	ToFunctionsInvokeFunctionMapOutput() FunctionsInvokeFunctionMapOutput
	ToFunctionsInvokeFunctionMapOutputWithContext(context.Context) FunctionsInvokeFunctionMapOutput
}

type FunctionsInvokeFunctionMap map[string]FunctionsInvokeFunctionInput

func (FunctionsInvokeFunctionMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*FunctionsInvokeFunction)(nil)).Elem()
}

func (i FunctionsInvokeFunctionMap) ToFunctionsInvokeFunctionMapOutput() FunctionsInvokeFunctionMapOutput {
	return i.ToFunctionsInvokeFunctionMapOutputWithContext(context.Background())
}

func (i FunctionsInvokeFunctionMap) ToFunctionsInvokeFunctionMapOutputWithContext(ctx context.Context) FunctionsInvokeFunctionMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FunctionsInvokeFunctionMapOutput)
}

type FunctionsInvokeFunctionOutput struct {
	*pulumi.OutputState
}

func (FunctionsInvokeFunctionOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*FunctionsInvokeFunction)(nil))
}

func (o FunctionsInvokeFunctionOutput) ToFunctionsInvokeFunctionOutput() FunctionsInvokeFunctionOutput {
	return o
}

func (o FunctionsInvokeFunctionOutput) ToFunctionsInvokeFunctionOutputWithContext(ctx context.Context) FunctionsInvokeFunctionOutput {
	return o
}

func (o FunctionsInvokeFunctionOutput) ToFunctionsInvokeFunctionPtrOutput() FunctionsInvokeFunctionPtrOutput {
	return o.ToFunctionsInvokeFunctionPtrOutputWithContext(context.Background())
}

func (o FunctionsInvokeFunctionOutput) ToFunctionsInvokeFunctionPtrOutputWithContext(ctx context.Context) FunctionsInvokeFunctionPtrOutput {
	return o.ApplyT(func(v FunctionsInvokeFunction) *FunctionsInvokeFunction {
		return &v
	}).(FunctionsInvokeFunctionPtrOutput)
}

type FunctionsInvokeFunctionPtrOutput struct {
	*pulumi.OutputState
}

func (FunctionsInvokeFunctionPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**FunctionsInvokeFunction)(nil))
}

func (o FunctionsInvokeFunctionPtrOutput) ToFunctionsInvokeFunctionPtrOutput() FunctionsInvokeFunctionPtrOutput {
	return o
}

func (o FunctionsInvokeFunctionPtrOutput) ToFunctionsInvokeFunctionPtrOutputWithContext(ctx context.Context) FunctionsInvokeFunctionPtrOutput {
	return o
}

type FunctionsInvokeFunctionArrayOutput struct{ *pulumi.OutputState }

func (FunctionsInvokeFunctionArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]FunctionsInvokeFunction)(nil))
}

func (o FunctionsInvokeFunctionArrayOutput) ToFunctionsInvokeFunctionArrayOutput() FunctionsInvokeFunctionArrayOutput {
	return o
}

func (o FunctionsInvokeFunctionArrayOutput) ToFunctionsInvokeFunctionArrayOutputWithContext(ctx context.Context) FunctionsInvokeFunctionArrayOutput {
	return o
}

func (o FunctionsInvokeFunctionArrayOutput) Index(i pulumi.IntInput) FunctionsInvokeFunctionOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) FunctionsInvokeFunction {
		return vs[0].([]FunctionsInvokeFunction)[vs[1].(int)]
	}).(FunctionsInvokeFunctionOutput)
}

type FunctionsInvokeFunctionMapOutput struct{ *pulumi.OutputState }

func (FunctionsInvokeFunctionMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]FunctionsInvokeFunction)(nil))
}

func (o FunctionsInvokeFunctionMapOutput) ToFunctionsInvokeFunctionMapOutput() FunctionsInvokeFunctionMapOutput {
	return o
}

func (o FunctionsInvokeFunctionMapOutput) ToFunctionsInvokeFunctionMapOutputWithContext(ctx context.Context) FunctionsInvokeFunctionMapOutput {
	return o
}

func (o FunctionsInvokeFunctionMapOutput) MapIndex(k pulumi.StringInput) FunctionsInvokeFunctionOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) FunctionsInvokeFunction {
		return vs[0].(map[string]FunctionsInvokeFunction)[vs[1].(string)]
	}).(FunctionsInvokeFunctionOutput)
}

func init() {
	pulumi.RegisterOutputType(FunctionsInvokeFunctionOutput{})
	pulumi.RegisterOutputType(FunctionsInvokeFunctionPtrOutput{})
	pulumi.RegisterOutputType(FunctionsInvokeFunctionArrayOutput{})
	pulumi.RegisterOutputType(FunctionsInvokeFunctionMapOutput{})
}
