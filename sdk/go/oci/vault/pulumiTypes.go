// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package vault

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type GetSecretSecretRule struct {
	// A property indicating whether the rule is applied even if the secret version with the content you are trying to reuse was deleted.
	IsEnforcedOnDeletedSecretVersions bool `pulumi:"isEnforcedOnDeletedSecretVersions"`
	// A property indicating whether to block retrieval of the secret content, on expiry. The default is false. If the secret has already expired and you would like to retrieve the secret contents, you need to edit the secret rule to disable this property, to allow reading the secret content.
	IsSecretContentRetrievalBlockedOnExpiry bool `pulumi:"isSecretContentRetrievalBlockedOnExpiry"`
	// The type of rule, which either controls when the secret contents expire or whether they can be reused.
	RuleType string `pulumi:"ruleType"`
	// A property indicating how long the secret contents will be considered valid, expressed in [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601#Time_intervals) format. The secret needs to be updated when the secret content expires. No enforcement mechanism exists at this time, but audit logs record the expiration on the appropriate date, according to the time interval specified in the rule. The timer resets after you update the secret contents. The minimum value is 1 day and the maximum value is 90 days for this property. Currently, only intervals expressed in days are supported. For example, pass `P3D` to have the secret version expire every 3 days.
	SecretVersionExpiryInterval string `pulumi:"secretVersionExpiryInterval"`
	// An optional property indicating the absolute time when this secret will expire, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. The minimum number of days from current time is 1 day and the maximum number of days from current time is 365 days. Example: `2019-04-03T21:10:29.600Z`
	TimeOfAbsoluteExpiry string `pulumi:"timeOfAbsoluteExpiry"`
}

// GetSecretSecretRuleInput is an input type that accepts GetSecretSecretRuleArgs and GetSecretSecretRuleOutput values.
// You can construct a concrete instance of `GetSecretSecretRuleInput` via:
//
//          GetSecretSecretRuleArgs{...}
type GetSecretSecretRuleInput interface {
	pulumi.Input

	ToGetSecretSecretRuleOutput() GetSecretSecretRuleOutput
	ToGetSecretSecretRuleOutputWithContext(context.Context) GetSecretSecretRuleOutput
}

type GetSecretSecretRuleArgs struct {
	// A property indicating whether the rule is applied even if the secret version with the content you are trying to reuse was deleted.
	IsEnforcedOnDeletedSecretVersions pulumi.BoolInput `pulumi:"isEnforcedOnDeletedSecretVersions"`
	// A property indicating whether to block retrieval of the secret content, on expiry. The default is false. If the secret has already expired and you would like to retrieve the secret contents, you need to edit the secret rule to disable this property, to allow reading the secret content.
	IsSecretContentRetrievalBlockedOnExpiry pulumi.BoolInput `pulumi:"isSecretContentRetrievalBlockedOnExpiry"`
	// The type of rule, which either controls when the secret contents expire or whether they can be reused.
	RuleType pulumi.StringInput `pulumi:"ruleType"`
	// A property indicating how long the secret contents will be considered valid, expressed in [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601#Time_intervals) format. The secret needs to be updated when the secret content expires. No enforcement mechanism exists at this time, but audit logs record the expiration on the appropriate date, according to the time interval specified in the rule. The timer resets after you update the secret contents. The minimum value is 1 day and the maximum value is 90 days for this property. Currently, only intervals expressed in days are supported. For example, pass `P3D` to have the secret version expire every 3 days.
	SecretVersionExpiryInterval pulumi.StringInput `pulumi:"secretVersionExpiryInterval"`
	// An optional property indicating the absolute time when this secret will expire, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. The minimum number of days from current time is 1 day and the maximum number of days from current time is 365 days. Example: `2019-04-03T21:10:29.600Z`
	TimeOfAbsoluteExpiry pulumi.StringInput `pulumi:"timeOfAbsoluteExpiry"`
}

func (GetSecretSecretRuleArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSecretSecretRule)(nil)).Elem()
}

func (i GetSecretSecretRuleArgs) ToGetSecretSecretRuleOutput() GetSecretSecretRuleOutput {
	return i.ToGetSecretSecretRuleOutputWithContext(context.Background())
}

func (i GetSecretSecretRuleArgs) ToGetSecretSecretRuleOutputWithContext(ctx context.Context) GetSecretSecretRuleOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GetSecretSecretRuleOutput)
}

// GetSecretSecretRuleArrayInput is an input type that accepts GetSecretSecretRuleArray and GetSecretSecretRuleArrayOutput values.
// You can construct a concrete instance of `GetSecretSecretRuleArrayInput` via:
//
//          GetSecretSecretRuleArray{ GetSecretSecretRuleArgs{...} }
type GetSecretSecretRuleArrayInput interface {
	pulumi.Input

	ToGetSecretSecretRuleArrayOutput() GetSecretSecretRuleArrayOutput
	ToGetSecretSecretRuleArrayOutputWithContext(context.Context) GetSecretSecretRuleArrayOutput
}

type GetSecretSecretRuleArray []GetSecretSecretRuleInput

func (GetSecretSecretRuleArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]GetSecretSecretRule)(nil)).Elem()
}

func (i GetSecretSecretRuleArray) ToGetSecretSecretRuleArrayOutput() GetSecretSecretRuleArrayOutput {
	return i.ToGetSecretSecretRuleArrayOutputWithContext(context.Background())
}

func (i GetSecretSecretRuleArray) ToGetSecretSecretRuleArrayOutputWithContext(ctx context.Context) GetSecretSecretRuleArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GetSecretSecretRuleArrayOutput)
}

type GetSecretSecretRuleOutput struct{ *pulumi.OutputState }

func (GetSecretSecretRuleOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSecretSecretRule)(nil)).Elem()
}

func (o GetSecretSecretRuleOutput) ToGetSecretSecretRuleOutput() GetSecretSecretRuleOutput {
	return o
}

func (o GetSecretSecretRuleOutput) ToGetSecretSecretRuleOutputWithContext(ctx context.Context) GetSecretSecretRuleOutput {
	return o
}

// A property indicating whether the rule is applied even if the secret version with the content you are trying to reuse was deleted.
func (o GetSecretSecretRuleOutput) IsEnforcedOnDeletedSecretVersions() pulumi.BoolOutput {
	return o.ApplyT(func(v GetSecretSecretRule) bool { return v.IsEnforcedOnDeletedSecretVersions }).(pulumi.BoolOutput)
}

// A property indicating whether to block retrieval of the secret content, on expiry. The default is false. If the secret has already expired and you would like to retrieve the secret contents, you need to edit the secret rule to disable this property, to allow reading the secret content.
func (o GetSecretSecretRuleOutput) IsSecretContentRetrievalBlockedOnExpiry() pulumi.BoolOutput {
	return o.ApplyT(func(v GetSecretSecretRule) bool { return v.IsSecretContentRetrievalBlockedOnExpiry }).(pulumi.BoolOutput)
}

// The type of rule, which either controls when the secret contents expire or whether they can be reused.
func (o GetSecretSecretRuleOutput) RuleType() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretSecretRule) string { return v.RuleType }).(pulumi.StringOutput)
}

// A property indicating how long the secret contents will be considered valid, expressed in [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601#Time_intervals) format. The secret needs to be updated when the secret content expires. No enforcement mechanism exists at this time, but audit logs record the expiration on the appropriate date, according to the time interval specified in the rule. The timer resets after you update the secret contents. The minimum value is 1 day and the maximum value is 90 days for this property. Currently, only intervals expressed in days are supported. For example, pass `P3D` to have the secret version expire every 3 days.
func (o GetSecretSecretRuleOutput) SecretVersionExpiryInterval() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretSecretRule) string { return v.SecretVersionExpiryInterval }).(pulumi.StringOutput)
}

// An optional property indicating the absolute time when this secret will expire, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. The minimum number of days from current time is 1 day and the maximum number of days from current time is 365 days. Example: `2019-04-03T21:10:29.600Z`
func (o GetSecretSecretRuleOutput) TimeOfAbsoluteExpiry() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretSecretRule) string { return v.TimeOfAbsoluteExpiry }).(pulumi.StringOutput)
}

type GetSecretSecretRuleArrayOutput struct{ *pulumi.OutputState }

func (GetSecretSecretRuleArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]GetSecretSecretRule)(nil)).Elem()
}

func (o GetSecretSecretRuleArrayOutput) ToGetSecretSecretRuleArrayOutput() GetSecretSecretRuleArrayOutput {
	return o
}

func (o GetSecretSecretRuleArrayOutput) ToGetSecretSecretRuleArrayOutputWithContext(ctx context.Context) GetSecretSecretRuleArrayOutput {
	return o
}

func (o GetSecretSecretRuleArrayOutput) Index(i pulumi.IntInput) GetSecretSecretRuleOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) GetSecretSecretRule {
		return vs[0].([]GetSecretSecretRule)[vs[1].(int)]
	}).(GetSecretSecretRuleOutput)
}

type GetSecretsFilter struct {
	// The secret name.
	Name   string   `pulumi:"name"`
	Regex  *bool    `pulumi:"regex"`
	Values []string `pulumi:"values"`
}

// GetSecretsFilterInput is an input type that accepts GetSecretsFilterArgs and GetSecretsFilterOutput values.
// You can construct a concrete instance of `GetSecretsFilterInput` via:
//
//          GetSecretsFilterArgs{...}
type GetSecretsFilterInput interface {
	pulumi.Input

	ToGetSecretsFilterOutput() GetSecretsFilterOutput
	ToGetSecretsFilterOutputWithContext(context.Context) GetSecretsFilterOutput
}

type GetSecretsFilterArgs struct {
	// The secret name.
	Name   pulumi.StringInput      `pulumi:"name"`
	Regex  pulumi.BoolPtrInput     `pulumi:"regex"`
	Values pulumi.StringArrayInput `pulumi:"values"`
}

func (GetSecretsFilterArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSecretsFilter)(nil)).Elem()
}

func (i GetSecretsFilterArgs) ToGetSecretsFilterOutput() GetSecretsFilterOutput {
	return i.ToGetSecretsFilterOutputWithContext(context.Background())
}

func (i GetSecretsFilterArgs) ToGetSecretsFilterOutputWithContext(ctx context.Context) GetSecretsFilterOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GetSecretsFilterOutput)
}

// GetSecretsFilterArrayInput is an input type that accepts GetSecretsFilterArray and GetSecretsFilterArrayOutput values.
// You can construct a concrete instance of `GetSecretsFilterArrayInput` via:
//
//          GetSecretsFilterArray{ GetSecretsFilterArgs{...} }
type GetSecretsFilterArrayInput interface {
	pulumi.Input

	ToGetSecretsFilterArrayOutput() GetSecretsFilterArrayOutput
	ToGetSecretsFilterArrayOutputWithContext(context.Context) GetSecretsFilterArrayOutput
}

type GetSecretsFilterArray []GetSecretsFilterInput

func (GetSecretsFilterArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]GetSecretsFilter)(nil)).Elem()
}

func (i GetSecretsFilterArray) ToGetSecretsFilterArrayOutput() GetSecretsFilterArrayOutput {
	return i.ToGetSecretsFilterArrayOutputWithContext(context.Background())
}

func (i GetSecretsFilterArray) ToGetSecretsFilterArrayOutputWithContext(ctx context.Context) GetSecretsFilterArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GetSecretsFilterArrayOutput)
}

type GetSecretsFilterOutput struct{ *pulumi.OutputState }

func (GetSecretsFilterOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSecretsFilter)(nil)).Elem()
}

func (o GetSecretsFilterOutput) ToGetSecretsFilterOutput() GetSecretsFilterOutput {
	return o
}

func (o GetSecretsFilterOutput) ToGetSecretsFilterOutputWithContext(ctx context.Context) GetSecretsFilterOutput {
	return o
}

// The secret name.
func (o GetSecretsFilterOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretsFilter) string { return v.Name }).(pulumi.StringOutput)
}

func (o GetSecretsFilterOutput) Regex() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetSecretsFilter) *bool { return v.Regex }).(pulumi.BoolPtrOutput)
}

func (o GetSecretsFilterOutput) Values() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetSecretsFilter) []string { return v.Values }).(pulumi.StringArrayOutput)
}

type GetSecretsFilterArrayOutput struct{ *pulumi.OutputState }

func (GetSecretsFilterArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]GetSecretsFilter)(nil)).Elem()
}

func (o GetSecretsFilterArrayOutput) ToGetSecretsFilterArrayOutput() GetSecretsFilterArrayOutput {
	return o
}

func (o GetSecretsFilterArrayOutput) ToGetSecretsFilterArrayOutputWithContext(ctx context.Context) GetSecretsFilterArrayOutput {
	return o
}

func (o GetSecretsFilterArrayOutput) Index(i pulumi.IntInput) GetSecretsFilterOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) GetSecretsFilter {
		return vs[0].([]GetSecretsFilter)[vs[1].(int)]
	}).(GetSecretsFilterOutput)
}

type GetSecretsSecret struct {
	// The OCID of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// A brief description of the secret. Avoid entering confidential information.
	Description string `pulumi:"description"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The OCID of the secret.
	Id string `pulumi:"id"`
	// The OCID of the master encryption key that is used to encrypt the secret.
	KeyId string `pulumi:"keyId"`
	// Additional information about the current lifecycle state of the secret.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// The user-friendly name of the secret. Avoid entering confidential information.
	SecretName string `pulumi:"secretName"`
	// A filter that returns only resources that match the specified lifecycle state. The state value is case-insensitive.
	State string `pulumi:"state"`
	// A property indicating when the secret was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
	// An optional property indicating when the current secret version will expire, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeOfCurrentVersionExpiry string `pulumi:"timeOfCurrentVersionExpiry"`
	// An optional property indicating when to delete the secret, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeOfDeletion string `pulumi:"timeOfDeletion"`
	// The OCID of the vault.
	VaultId string `pulumi:"vaultId"`
}

// GetSecretsSecretInput is an input type that accepts GetSecretsSecretArgs and GetSecretsSecretOutput values.
// You can construct a concrete instance of `GetSecretsSecretInput` via:
//
//          GetSecretsSecretArgs{...}
type GetSecretsSecretInput interface {
	pulumi.Input

	ToGetSecretsSecretOutput() GetSecretsSecretOutput
	ToGetSecretsSecretOutputWithContext(context.Context) GetSecretsSecretOutput
}

type GetSecretsSecretArgs struct {
	// The OCID of the compartment.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput `pulumi:"definedTags"`
	// A brief description of the secret. Avoid entering confidential information.
	Description pulumi.StringInput `pulumi:"description"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput `pulumi:"freeformTags"`
	// The OCID of the secret.
	Id pulumi.StringInput `pulumi:"id"`
	// The OCID of the master encryption key that is used to encrypt the secret.
	KeyId pulumi.StringInput `pulumi:"keyId"`
	// Additional information about the current lifecycle state of the secret.
	LifecycleDetails pulumi.StringInput `pulumi:"lifecycleDetails"`
	// The user-friendly name of the secret. Avoid entering confidential information.
	SecretName pulumi.StringInput `pulumi:"secretName"`
	// A filter that returns only resources that match the specified lifecycle state. The state value is case-insensitive.
	State pulumi.StringInput `pulumi:"state"`
	// A property indicating when the secret was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeCreated pulumi.StringInput `pulumi:"timeCreated"`
	// An optional property indicating when the current secret version will expire, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeOfCurrentVersionExpiry pulumi.StringInput `pulumi:"timeOfCurrentVersionExpiry"`
	// An optional property indicating when to delete the secret, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeOfDeletion pulumi.StringInput `pulumi:"timeOfDeletion"`
	// The OCID of the vault.
	VaultId pulumi.StringInput `pulumi:"vaultId"`
}

func (GetSecretsSecretArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSecretsSecret)(nil)).Elem()
}

func (i GetSecretsSecretArgs) ToGetSecretsSecretOutput() GetSecretsSecretOutput {
	return i.ToGetSecretsSecretOutputWithContext(context.Background())
}

func (i GetSecretsSecretArgs) ToGetSecretsSecretOutputWithContext(ctx context.Context) GetSecretsSecretOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GetSecretsSecretOutput)
}

// GetSecretsSecretArrayInput is an input type that accepts GetSecretsSecretArray and GetSecretsSecretArrayOutput values.
// You can construct a concrete instance of `GetSecretsSecretArrayInput` via:
//
//          GetSecretsSecretArray{ GetSecretsSecretArgs{...} }
type GetSecretsSecretArrayInput interface {
	pulumi.Input

	ToGetSecretsSecretArrayOutput() GetSecretsSecretArrayOutput
	ToGetSecretsSecretArrayOutputWithContext(context.Context) GetSecretsSecretArrayOutput
}

type GetSecretsSecretArray []GetSecretsSecretInput

func (GetSecretsSecretArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]GetSecretsSecret)(nil)).Elem()
}

func (i GetSecretsSecretArray) ToGetSecretsSecretArrayOutput() GetSecretsSecretArrayOutput {
	return i.ToGetSecretsSecretArrayOutputWithContext(context.Background())
}

func (i GetSecretsSecretArray) ToGetSecretsSecretArrayOutputWithContext(ctx context.Context) GetSecretsSecretArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GetSecretsSecretArrayOutput)
}

type GetSecretsSecretOutput struct{ *pulumi.OutputState }

func (GetSecretsSecretOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSecretsSecret)(nil)).Elem()
}

func (o GetSecretsSecretOutput) ToGetSecretsSecretOutput() GetSecretsSecretOutput {
	return o
}

func (o GetSecretsSecretOutput) ToGetSecretsSecretOutputWithContext(ctx context.Context) GetSecretsSecretOutput {
	return o
}

// The OCID of the compartment.
func (o GetSecretsSecretOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretsSecret) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o GetSecretsSecretOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v GetSecretsSecret) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// A brief description of the secret. Avoid entering confidential information.
func (o GetSecretsSecretOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretsSecret) string { return v.Description }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o GetSecretsSecretOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v GetSecretsSecret) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// The OCID of the secret.
func (o GetSecretsSecretOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretsSecret) string { return v.Id }).(pulumi.StringOutput)
}

// The OCID of the master encryption key that is used to encrypt the secret.
func (o GetSecretsSecretOutput) KeyId() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretsSecret) string { return v.KeyId }).(pulumi.StringOutput)
}

// Additional information about the current lifecycle state of the secret.
func (o GetSecretsSecretOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretsSecret) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The user-friendly name of the secret. Avoid entering confidential information.
func (o GetSecretsSecretOutput) SecretName() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretsSecret) string { return v.SecretName }).(pulumi.StringOutput)
}

// A filter that returns only resources that match the specified lifecycle state. The state value is case-insensitive.
func (o GetSecretsSecretOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretsSecret) string { return v.State }).(pulumi.StringOutput)
}

// A property indicating when the secret was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
func (o GetSecretsSecretOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretsSecret) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// An optional property indicating when the current secret version will expire, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
func (o GetSecretsSecretOutput) TimeOfCurrentVersionExpiry() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretsSecret) string { return v.TimeOfCurrentVersionExpiry }).(pulumi.StringOutput)
}

// An optional property indicating when to delete the secret, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
func (o GetSecretsSecretOutput) TimeOfDeletion() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretsSecret) string { return v.TimeOfDeletion }).(pulumi.StringOutput)
}

// The OCID of the vault.
func (o GetSecretsSecretOutput) VaultId() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretsSecret) string { return v.VaultId }).(pulumi.StringOutput)
}

type GetSecretsSecretArrayOutput struct{ *pulumi.OutputState }

func (GetSecretsSecretArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]GetSecretsSecret)(nil)).Elem()
}

func (o GetSecretsSecretArrayOutput) ToGetSecretsSecretArrayOutput() GetSecretsSecretArrayOutput {
	return o
}

func (o GetSecretsSecretArrayOutput) ToGetSecretsSecretArrayOutputWithContext(ctx context.Context) GetSecretsSecretArrayOutput {
	return o
}

func (o GetSecretsSecretArrayOutput) Index(i pulumi.IntInput) GetSecretsSecretOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) GetSecretsSecret {
		return vs[0].([]GetSecretsSecret)[vs[1].(int)]
	}).(GetSecretsSecretOutput)
}

func init() {
	pulumi.RegisterOutputType(GetSecretSecretRuleOutput{})
	pulumi.RegisterOutputType(GetSecretSecretRuleArrayOutput{})
	pulumi.RegisterOutputType(GetSecretsFilterOutput{})
	pulumi.RegisterOutputType(GetSecretsFilterArrayOutput{})
	pulumi.RegisterOutputType(GetSecretsSecretOutput{})
	pulumi.RegisterOutputType(GetSecretsSecretArrayOutput{})
}
