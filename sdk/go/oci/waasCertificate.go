// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Certificate resource in Oracle Cloud Infrastructure Web Application Acceleration and Security service.
//
// Allows an SSL certificate to be added to a WAAS policy. The Web Application Firewall terminates SSL connections to inspect requests in runtime, and then re-encrypts requests before sending them to the origin for fulfillment.
//
// For more information, see [WAF Settings](https://docs.cloud.oracle.com/iaas/Content/WAF/Tasks/wafsettings.htm).
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
// 		_, err := oci.NewWaasCertificate(ctx, "testCertificate", &oci.WaasCertificateArgs{
// 			CertificateData: pulumi.Any(_var.Certificate_certificate_data),
// 			CompartmentId:   pulumi.Any(_var.Compartment_id),
// 			PrivateKeyData:  pulumi.Any(_var.Certificate_private_key_data),
// 			DefinedTags: pulumi.AnyMap{
// 				"Operations.CostCenter": pulumi.Any("42"),
// 			},
// 			DisplayName: pulumi.Any(_var.Certificate_display_name),
// 			FreeformTags: pulumi.AnyMap{
// 				"Department": pulumi.Any("Finance"),
// 			},
// 			IsTrustVerificationDisabled: pulumi.Any(_var.Certificate_is_trust_verification_disabled),
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
type WaasCertificate struct {
	pulumi.CustomResourceState

	// The data of the SSL certificate.
	CertificateData pulumi.StringOutput `pulumi:"certificateData"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the SSL certificate.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name for the SSL certificate. The name can be changed and does not need to be unique.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// Additional attributes associated with users or public keys for managing relationships between Certificate Authorities.
	Extensions WaasCertificateExtensionArrayOutput `pulumi:"extensions"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// Set to `true` if the SSL certificate is self-signed.
	IsTrustVerificationDisabled pulumi.BoolOutput   `pulumi:"isTrustVerificationDisabled"`
	IssuedBy                    pulumi.StringOutput `pulumi:"issuedBy"`
	// The issuer of the certificate.
	IssuerName WaasCertificateIssuerNameOutput `pulumi:"issuerName"`
	// The private key of the SSL certificate.
	PrivateKeyData pulumi.StringOutput `pulumi:"privateKeyData"`
	// Information about the public key and the algorithm used by the public key.
	PublicKeyInfo WaasCertificatePublicKeyInfoOutput `pulumi:"publicKeyInfo"`
	// A unique, positive integer assigned by the Certificate Authority (CA). The issuer name and serial number identify a unique certificate.
	SerialNumber pulumi.StringOutput `pulumi:"serialNumber"`
	// The identifier for the cryptographic algorithm used by the Certificate Authority (CA) to sign this certificate.
	SignatureAlgorithm pulumi.StringOutput `pulumi:"signatureAlgorithm"`
	// The current lifecycle state of the SSL certificate.
	State pulumi.StringOutput `pulumi:"state"`
	// The entity to be secured by the certificate.
	SubjectName WaasCertificateSubjectNameOutput `pulumi:"subjectName"`
	// The date and time the certificate was created, expressed in RFC 3339 timestamp format.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the certificate will expire, expressed in RFC 3339 timestamp format.
	TimeNotValidAfter pulumi.StringOutput `pulumi:"timeNotValidAfter"`
	// The date and time the certificate will become valid, expressed in RFC 3339 timestamp format.
	TimeNotValidBefore pulumi.StringOutput `pulumi:"timeNotValidBefore"`
	// The version of the encoded certificate.
	Version pulumi.IntOutput `pulumi:"version"`
}

// NewWaasCertificate registers a new resource with the given unique name, arguments, and options.
func NewWaasCertificate(ctx *pulumi.Context,
	name string, args *WaasCertificateArgs, opts ...pulumi.ResourceOption) (*WaasCertificate, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CertificateData == nil {
		return nil, errors.New("invalid value for required argument 'CertificateData'")
	}
	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.PrivateKeyData == nil {
		return nil, errors.New("invalid value for required argument 'PrivateKeyData'")
	}
	var resource WaasCertificate
	err := ctx.RegisterResource("oci:index/waasCertificate:WaasCertificate", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetWaasCertificate gets an existing WaasCertificate resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetWaasCertificate(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *WaasCertificateState, opts ...pulumi.ResourceOption) (*WaasCertificate, error) {
	var resource WaasCertificate
	err := ctx.ReadResource("oci:index/waasCertificate:WaasCertificate", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering WaasCertificate resources.
type waasCertificateState struct {
	// The data of the SSL certificate.
	CertificateData *string `pulumi:"certificateData"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the SSL certificate.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name for the SSL certificate. The name can be changed and does not need to be unique.
	DisplayName *string `pulumi:"displayName"`
	// Additional attributes associated with users or public keys for managing relationships between Certificate Authorities.
	Extensions []WaasCertificateExtension `pulumi:"extensions"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Set to `true` if the SSL certificate is self-signed.
	IsTrustVerificationDisabled *bool   `pulumi:"isTrustVerificationDisabled"`
	IssuedBy                    *string `pulumi:"issuedBy"`
	// The issuer of the certificate.
	IssuerName *WaasCertificateIssuerName `pulumi:"issuerName"`
	// The private key of the SSL certificate.
	PrivateKeyData *string `pulumi:"privateKeyData"`
	// Information about the public key and the algorithm used by the public key.
	PublicKeyInfo *WaasCertificatePublicKeyInfo `pulumi:"publicKeyInfo"`
	// A unique, positive integer assigned by the Certificate Authority (CA). The issuer name and serial number identify a unique certificate.
	SerialNumber *string `pulumi:"serialNumber"`
	// The identifier for the cryptographic algorithm used by the Certificate Authority (CA) to sign this certificate.
	SignatureAlgorithm *string `pulumi:"signatureAlgorithm"`
	// The current lifecycle state of the SSL certificate.
	State *string `pulumi:"state"`
	// The entity to be secured by the certificate.
	SubjectName *WaasCertificateSubjectName `pulumi:"subjectName"`
	// The date and time the certificate was created, expressed in RFC 3339 timestamp format.
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the certificate will expire, expressed in RFC 3339 timestamp format.
	TimeNotValidAfter *string `pulumi:"timeNotValidAfter"`
	// The date and time the certificate will become valid, expressed in RFC 3339 timestamp format.
	TimeNotValidBefore *string `pulumi:"timeNotValidBefore"`
	// The version of the encoded certificate.
	Version *int `pulumi:"version"`
}

type WaasCertificateState struct {
	// The data of the SSL certificate.
	CertificateData pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the SSL certificate.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name for the SSL certificate. The name can be changed and does not need to be unique.
	DisplayName pulumi.StringPtrInput
	// Additional attributes associated with users or public keys for managing relationships between Certificate Authorities.
	Extensions WaasCertificateExtensionArrayInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// Set to `true` if the SSL certificate is self-signed.
	IsTrustVerificationDisabled pulumi.BoolPtrInput
	IssuedBy                    pulumi.StringPtrInput
	// The issuer of the certificate.
	IssuerName WaasCertificateIssuerNamePtrInput
	// The private key of the SSL certificate.
	PrivateKeyData pulumi.StringPtrInput
	// Information about the public key and the algorithm used by the public key.
	PublicKeyInfo WaasCertificatePublicKeyInfoPtrInput
	// A unique, positive integer assigned by the Certificate Authority (CA). The issuer name and serial number identify a unique certificate.
	SerialNumber pulumi.StringPtrInput
	// The identifier for the cryptographic algorithm used by the Certificate Authority (CA) to sign this certificate.
	SignatureAlgorithm pulumi.StringPtrInput
	// The current lifecycle state of the SSL certificate.
	State pulumi.StringPtrInput
	// The entity to be secured by the certificate.
	SubjectName WaasCertificateSubjectNamePtrInput
	// The date and time the certificate was created, expressed in RFC 3339 timestamp format.
	TimeCreated pulumi.StringPtrInput
	// The date and time the certificate will expire, expressed in RFC 3339 timestamp format.
	TimeNotValidAfter pulumi.StringPtrInput
	// The date and time the certificate will become valid, expressed in RFC 3339 timestamp format.
	TimeNotValidBefore pulumi.StringPtrInput
	// The version of the encoded certificate.
	Version pulumi.IntPtrInput
}

func (WaasCertificateState) ElementType() reflect.Type {
	return reflect.TypeOf((*waasCertificateState)(nil)).Elem()
}

type waasCertificateArgs struct {
	// The data of the SSL certificate.
	CertificateData string `pulumi:"certificateData"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the SSL certificate.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name for the SSL certificate. The name can be changed and does not need to be unique.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Set to `true` if the SSL certificate is self-signed.
	IsTrustVerificationDisabled *bool `pulumi:"isTrustVerificationDisabled"`
	// The private key of the SSL certificate.
	PrivateKeyData string `pulumi:"privateKeyData"`
}

// The set of arguments for constructing a WaasCertificate resource.
type WaasCertificateArgs struct {
	// The data of the SSL certificate.
	CertificateData pulumi.StringInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the SSL certificate.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name for the SSL certificate. The name can be changed and does not need to be unique.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// Set to `true` if the SSL certificate is self-signed.
	IsTrustVerificationDisabled pulumi.BoolPtrInput
	// The private key of the SSL certificate.
	PrivateKeyData pulumi.StringInput
}

func (WaasCertificateArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*waasCertificateArgs)(nil)).Elem()
}

type WaasCertificateInput interface {
	pulumi.Input

	ToWaasCertificateOutput() WaasCertificateOutput
	ToWaasCertificateOutputWithContext(ctx context.Context) WaasCertificateOutput
}

func (*WaasCertificate) ElementType() reflect.Type {
	return reflect.TypeOf((*WaasCertificate)(nil))
}

func (i *WaasCertificate) ToWaasCertificateOutput() WaasCertificateOutput {
	return i.ToWaasCertificateOutputWithContext(context.Background())
}

func (i *WaasCertificate) ToWaasCertificateOutputWithContext(ctx context.Context) WaasCertificateOutput {
	return pulumi.ToOutputWithContext(ctx, i).(WaasCertificateOutput)
}

func (i *WaasCertificate) ToWaasCertificatePtrOutput() WaasCertificatePtrOutput {
	return i.ToWaasCertificatePtrOutputWithContext(context.Background())
}

func (i *WaasCertificate) ToWaasCertificatePtrOutputWithContext(ctx context.Context) WaasCertificatePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(WaasCertificatePtrOutput)
}

type WaasCertificatePtrInput interface {
	pulumi.Input

	ToWaasCertificatePtrOutput() WaasCertificatePtrOutput
	ToWaasCertificatePtrOutputWithContext(ctx context.Context) WaasCertificatePtrOutput
}

type waasCertificatePtrType WaasCertificateArgs

func (*waasCertificatePtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**WaasCertificate)(nil))
}

func (i *waasCertificatePtrType) ToWaasCertificatePtrOutput() WaasCertificatePtrOutput {
	return i.ToWaasCertificatePtrOutputWithContext(context.Background())
}

func (i *waasCertificatePtrType) ToWaasCertificatePtrOutputWithContext(ctx context.Context) WaasCertificatePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(WaasCertificatePtrOutput)
}

// WaasCertificateArrayInput is an input type that accepts WaasCertificateArray and WaasCertificateArrayOutput values.
// You can construct a concrete instance of `WaasCertificateArrayInput` via:
//
//          WaasCertificateArray{ WaasCertificateArgs{...} }
type WaasCertificateArrayInput interface {
	pulumi.Input

	ToWaasCertificateArrayOutput() WaasCertificateArrayOutput
	ToWaasCertificateArrayOutputWithContext(context.Context) WaasCertificateArrayOutput
}

type WaasCertificateArray []WaasCertificateInput

func (WaasCertificateArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*WaasCertificate)(nil)).Elem()
}

func (i WaasCertificateArray) ToWaasCertificateArrayOutput() WaasCertificateArrayOutput {
	return i.ToWaasCertificateArrayOutputWithContext(context.Background())
}

func (i WaasCertificateArray) ToWaasCertificateArrayOutputWithContext(ctx context.Context) WaasCertificateArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(WaasCertificateArrayOutput)
}

// WaasCertificateMapInput is an input type that accepts WaasCertificateMap and WaasCertificateMapOutput values.
// You can construct a concrete instance of `WaasCertificateMapInput` via:
//
//          WaasCertificateMap{ "key": WaasCertificateArgs{...} }
type WaasCertificateMapInput interface {
	pulumi.Input

	ToWaasCertificateMapOutput() WaasCertificateMapOutput
	ToWaasCertificateMapOutputWithContext(context.Context) WaasCertificateMapOutput
}

type WaasCertificateMap map[string]WaasCertificateInput

func (WaasCertificateMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*WaasCertificate)(nil)).Elem()
}

func (i WaasCertificateMap) ToWaasCertificateMapOutput() WaasCertificateMapOutput {
	return i.ToWaasCertificateMapOutputWithContext(context.Background())
}

func (i WaasCertificateMap) ToWaasCertificateMapOutputWithContext(ctx context.Context) WaasCertificateMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(WaasCertificateMapOutput)
}

type WaasCertificateOutput struct {
	*pulumi.OutputState
}

func (WaasCertificateOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*WaasCertificate)(nil))
}

func (o WaasCertificateOutput) ToWaasCertificateOutput() WaasCertificateOutput {
	return o
}

func (o WaasCertificateOutput) ToWaasCertificateOutputWithContext(ctx context.Context) WaasCertificateOutput {
	return o
}

func (o WaasCertificateOutput) ToWaasCertificatePtrOutput() WaasCertificatePtrOutput {
	return o.ToWaasCertificatePtrOutputWithContext(context.Background())
}

func (o WaasCertificateOutput) ToWaasCertificatePtrOutputWithContext(ctx context.Context) WaasCertificatePtrOutput {
	return o.ApplyT(func(v WaasCertificate) *WaasCertificate {
		return &v
	}).(WaasCertificatePtrOutput)
}

type WaasCertificatePtrOutput struct {
	*pulumi.OutputState
}

func (WaasCertificatePtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**WaasCertificate)(nil))
}

func (o WaasCertificatePtrOutput) ToWaasCertificatePtrOutput() WaasCertificatePtrOutput {
	return o
}

func (o WaasCertificatePtrOutput) ToWaasCertificatePtrOutputWithContext(ctx context.Context) WaasCertificatePtrOutput {
	return o
}

type WaasCertificateArrayOutput struct{ *pulumi.OutputState }

func (WaasCertificateArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]WaasCertificate)(nil))
}

func (o WaasCertificateArrayOutput) ToWaasCertificateArrayOutput() WaasCertificateArrayOutput {
	return o
}

func (o WaasCertificateArrayOutput) ToWaasCertificateArrayOutputWithContext(ctx context.Context) WaasCertificateArrayOutput {
	return o
}

func (o WaasCertificateArrayOutput) Index(i pulumi.IntInput) WaasCertificateOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) WaasCertificate {
		return vs[0].([]WaasCertificate)[vs[1].(int)]
	}).(WaasCertificateOutput)
}

type WaasCertificateMapOutput struct{ *pulumi.OutputState }

func (WaasCertificateMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]WaasCertificate)(nil))
}

func (o WaasCertificateMapOutput) ToWaasCertificateMapOutput() WaasCertificateMapOutput {
	return o
}

func (o WaasCertificateMapOutput) ToWaasCertificateMapOutputWithContext(ctx context.Context) WaasCertificateMapOutput {
	return o
}

func (o WaasCertificateMapOutput) MapIndex(k pulumi.StringInput) WaasCertificateOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) WaasCertificate {
		return vs[0].(map[string]WaasCertificate)[vs[1].(string)]
	}).(WaasCertificateOutput)
}

func init() {
	pulumi.RegisterOutputType(WaasCertificateOutput{})
	pulumi.RegisterOutputType(WaasCertificatePtrOutput{})
	pulumi.RegisterOutputType(WaasCertificateArrayOutput{})
	pulumi.RegisterOutputType(WaasCertificateMapOutput{})
}