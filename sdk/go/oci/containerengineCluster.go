// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Cluster resource in Oracle Cloud Infrastructure Container Engine service.
//
// Create a new cluster.
//
// ## Import
//
// Clusters can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/containerengineCluster:ContainerengineCluster test_cluster "id"
// ```
type ContainerengineCluster struct {
	pulumi.CustomResourceState

	// Available Kubernetes versions to which the clusters masters may be upgraded.
	AvailableKubernetesUpgrades pulumi.StringArrayOutput `pulumi:"availableKubernetesUpgrades"`
	// The OCID of the compartment in which to create the cluster.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// The network configuration for access to the Cluster control plane.
	EndpointConfig ContainerengineClusterEndpointConfigPtrOutput `pulumi:"endpointConfig"`
	// Endpoints served up by the cluster masters.
	Endpoints ContainerengineClusterEndpointsOutput `pulumi:"endpoints"`
	// (Updatable) The image verification policy for signature validation. Once a policy is created and enabled with one or more kms keys, the policy will ensure all images deployed has been signed with the key(s) attached to the policy.
	ImagePolicyConfig ContainerengineClusterImagePolicyConfigOutput `pulumi:"imagePolicyConfig"`
	// The OCID of the KMS key to be used as the master encryption key for Kubernetes secret encryption. When used, `kubernetesVersion` must be at least `v1.13.0`.
	KmsKeyId pulumi.StringOutput `pulumi:"kmsKeyId"`
	// (Updatable) The version of Kubernetes to install into the cluster masters.
	KubernetesVersion pulumi.StringOutput `pulumi:"kubernetesVersion"`
	// Details about the state of the cluster masters.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// Metadata about the cluster.
	Metadata ContainerengineClusterMetadataOutput `pulumi:"metadata"`
	// (Updatable) The name of the cluster. Avoid entering confidential information.
	Name pulumi.StringOutput `pulumi:"name"`
	// (Updatable) Optional attributes for the cluster.
	Options ContainerengineClusterOptionsOutput `pulumi:"options"`
	// The state of the cluster masters.
	State pulumi.StringOutput `pulumi:"state"`
	// The OCID of the virtual cloud network (VCN) in which to create the cluster.
	VcnId pulumi.StringOutput `pulumi:"vcnId"`
}

// NewContainerengineCluster registers a new resource with the given unique name, arguments, and options.
func NewContainerengineCluster(ctx *pulumi.Context,
	name string, args *ContainerengineClusterArgs, opts ...pulumi.ResourceOption) (*ContainerengineCluster, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.KubernetesVersion == nil {
		return nil, errors.New("invalid value for required argument 'KubernetesVersion'")
	}
	if args.VcnId == nil {
		return nil, errors.New("invalid value for required argument 'VcnId'")
	}
	var resource ContainerengineCluster
	err := ctx.RegisterResource("oci:index/containerengineCluster:ContainerengineCluster", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetContainerengineCluster gets an existing ContainerengineCluster resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetContainerengineCluster(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ContainerengineClusterState, opts ...pulumi.ResourceOption) (*ContainerengineCluster, error) {
	var resource ContainerengineCluster
	err := ctx.ReadResource("oci:index/containerengineCluster:ContainerengineCluster", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ContainerengineCluster resources.
type containerengineClusterState struct {
	// Available Kubernetes versions to which the clusters masters may be upgraded.
	AvailableKubernetesUpgrades []string `pulumi:"availableKubernetesUpgrades"`
	// The OCID of the compartment in which to create the cluster.
	CompartmentId *string `pulumi:"compartmentId"`
	// The network configuration for access to the Cluster control plane.
	EndpointConfig *ContainerengineClusterEndpointConfig `pulumi:"endpointConfig"`
	// Endpoints served up by the cluster masters.
	Endpoints *ContainerengineClusterEndpoints `pulumi:"endpoints"`
	// (Updatable) The image verification policy for signature validation. Once a policy is created and enabled with one or more kms keys, the policy will ensure all images deployed has been signed with the key(s) attached to the policy.
	ImagePolicyConfig *ContainerengineClusterImagePolicyConfig `pulumi:"imagePolicyConfig"`
	// The OCID of the KMS key to be used as the master encryption key for Kubernetes secret encryption. When used, `kubernetesVersion` must be at least `v1.13.0`.
	KmsKeyId *string `pulumi:"kmsKeyId"`
	// (Updatable) The version of Kubernetes to install into the cluster masters.
	KubernetesVersion *string `pulumi:"kubernetesVersion"`
	// Details about the state of the cluster masters.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// Metadata about the cluster.
	Metadata *ContainerengineClusterMetadata `pulumi:"metadata"`
	// (Updatable) The name of the cluster. Avoid entering confidential information.
	Name *string `pulumi:"name"`
	// (Updatable) Optional attributes for the cluster.
	Options *ContainerengineClusterOptions `pulumi:"options"`
	// The state of the cluster masters.
	State *string `pulumi:"state"`
	// The OCID of the virtual cloud network (VCN) in which to create the cluster.
	VcnId *string `pulumi:"vcnId"`
}

type ContainerengineClusterState struct {
	// Available Kubernetes versions to which the clusters masters may be upgraded.
	AvailableKubernetesUpgrades pulumi.StringArrayInput
	// The OCID of the compartment in which to create the cluster.
	CompartmentId pulumi.StringPtrInput
	// The network configuration for access to the Cluster control plane.
	EndpointConfig ContainerengineClusterEndpointConfigPtrInput
	// Endpoints served up by the cluster masters.
	Endpoints ContainerengineClusterEndpointsPtrInput
	// (Updatable) The image verification policy for signature validation. Once a policy is created and enabled with one or more kms keys, the policy will ensure all images deployed has been signed with the key(s) attached to the policy.
	ImagePolicyConfig ContainerengineClusterImagePolicyConfigPtrInput
	// The OCID of the KMS key to be used as the master encryption key for Kubernetes secret encryption. When used, `kubernetesVersion` must be at least `v1.13.0`.
	KmsKeyId pulumi.StringPtrInput
	// (Updatable) The version of Kubernetes to install into the cluster masters.
	KubernetesVersion pulumi.StringPtrInput
	// Details about the state of the cluster masters.
	LifecycleDetails pulumi.StringPtrInput
	// Metadata about the cluster.
	Metadata ContainerengineClusterMetadataPtrInput
	// (Updatable) The name of the cluster. Avoid entering confidential information.
	Name pulumi.StringPtrInput
	// (Updatable) Optional attributes for the cluster.
	Options ContainerengineClusterOptionsPtrInput
	// The state of the cluster masters.
	State pulumi.StringPtrInput
	// The OCID of the virtual cloud network (VCN) in which to create the cluster.
	VcnId pulumi.StringPtrInput
}

func (ContainerengineClusterState) ElementType() reflect.Type {
	return reflect.TypeOf((*containerengineClusterState)(nil)).Elem()
}

type containerengineClusterArgs struct {
	// The OCID of the compartment in which to create the cluster.
	CompartmentId string `pulumi:"compartmentId"`
	// The network configuration for access to the Cluster control plane.
	EndpointConfig *ContainerengineClusterEndpointConfig `pulumi:"endpointConfig"`
	// (Updatable) The image verification policy for signature validation. Once a policy is created and enabled with one or more kms keys, the policy will ensure all images deployed has been signed with the key(s) attached to the policy.
	ImagePolicyConfig *ContainerengineClusterImagePolicyConfig `pulumi:"imagePolicyConfig"`
	// The OCID of the KMS key to be used as the master encryption key for Kubernetes secret encryption. When used, `kubernetesVersion` must be at least `v1.13.0`.
	KmsKeyId *string `pulumi:"kmsKeyId"`
	// (Updatable) The version of Kubernetes to install into the cluster masters.
	KubernetesVersion string `pulumi:"kubernetesVersion"`
	// (Updatable) The name of the cluster. Avoid entering confidential information.
	Name *string `pulumi:"name"`
	// (Updatable) Optional attributes for the cluster.
	Options *ContainerengineClusterOptions `pulumi:"options"`
	// The OCID of the virtual cloud network (VCN) in which to create the cluster.
	VcnId string `pulumi:"vcnId"`
}

// The set of arguments for constructing a ContainerengineCluster resource.
type ContainerengineClusterArgs struct {
	// The OCID of the compartment in which to create the cluster.
	CompartmentId pulumi.StringInput
	// The network configuration for access to the Cluster control plane.
	EndpointConfig ContainerengineClusterEndpointConfigPtrInput
	// (Updatable) The image verification policy for signature validation. Once a policy is created and enabled with one or more kms keys, the policy will ensure all images deployed has been signed with the key(s) attached to the policy.
	ImagePolicyConfig ContainerengineClusterImagePolicyConfigPtrInput
	// The OCID of the KMS key to be used as the master encryption key for Kubernetes secret encryption. When used, `kubernetesVersion` must be at least `v1.13.0`.
	KmsKeyId pulumi.StringPtrInput
	// (Updatable) The version of Kubernetes to install into the cluster masters.
	KubernetesVersion pulumi.StringInput
	// (Updatable) The name of the cluster. Avoid entering confidential information.
	Name pulumi.StringPtrInput
	// (Updatable) Optional attributes for the cluster.
	Options ContainerengineClusterOptionsPtrInput
	// The OCID of the virtual cloud network (VCN) in which to create the cluster.
	VcnId pulumi.StringInput
}

func (ContainerengineClusterArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*containerengineClusterArgs)(nil)).Elem()
}

type ContainerengineClusterInput interface {
	pulumi.Input

	ToContainerengineClusterOutput() ContainerengineClusterOutput
	ToContainerengineClusterOutputWithContext(ctx context.Context) ContainerengineClusterOutput
}

func (*ContainerengineCluster) ElementType() reflect.Type {
	return reflect.TypeOf((*ContainerengineCluster)(nil))
}

func (i *ContainerengineCluster) ToContainerengineClusterOutput() ContainerengineClusterOutput {
	return i.ToContainerengineClusterOutputWithContext(context.Background())
}

func (i *ContainerengineCluster) ToContainerengineClusterOutputWithContext(ctx context.Context) ContainerengineClusterOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ContainerengineClusterOutput)
}

func (i *ContainerengineCluster) ToContainerengineClusterPtrOutput() ContainerengineClusterPtrOutput {
	return i.ToContainerengineClusterPtrOutputWithContext(context.Background())
}

func (i *ContainerengineCluster) ToContainerengineClusterPtrOutputWithContext(ctx context.Context) ContainerengineClusterPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ContainerengineClusterPtrOutput)
}

type ContainerengineClusterPtrInput interface {
	pulumi.Input

	ToContainerengineClusterPtrOutput() ContainerengineClusterPtrOutput
	ToContainerengineClusterPtrOutputWithContext(ctx context.Context) ContainerengineClusterPtrOutput
}

type containerengineClusterPtrType ContainerengineClusterArgs

func (*containerengineClusterPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**ContainerengineCluster)(nil))
}

func (i *containerengineClusterPtrType) ToContainerengineClusterPtrOutput() ContainerengineClusterPtrOutput {
	return i.ToContainerengineClusterPtrOutputWithContext(context.Background())
}

func (i *containerengineClusterPtrType) ToContainerengineClusterPtrOutputWithContext(ctx context.Context) ContainerengineClusterPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ContainerengineClusterPtrOutput)
}

// ContainerengineClusterArrayInput is an input type that accepts ContainerengineClusterArray and ContainerengineClusterArrayOutput values.
// You can construct a concrete instance of `ContainerengineClusterArrayInput` via:
//
//          ContainerengineClusterArray{ ContainerengineClusterArgs{...} }
type ContainerengineClusterArrayInput interface {
	pulumi.Input

	ToContainerengineClusterArrayOutput() ContainerengineClusterArrayOutput
	ToContainerengineClusterArrayOutputWithContext(context.Context) ContainerengineClusterArrayOutput
}

type ContainerengineClusterArray []ContainerengineClusterInput

func (ContainerengineClusterArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ContainerengineCluster)(nil)).Elem()
}

func (i ContainerengineClusterArray) ToContainerengineClusterArrayOutput() ContainerengineClusterArrayOutput {
	return i.ToContainerengineClusterArrayOutputWithContext(context.Background())
}

func (i ContainerengineClusterArray) ToContainerengineClusterArrayOutputWithContext(ctx context.Context) ContainerengineClusterArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ContainerengineClusterArrayOutput)
}

// ContainerengineClusterMapInput is an input type that accepts ContainerengineClusterMap and ContainerengineClusterMapOutput values.
// You can construct a concrete instance of `ContainerengineClusterMapInput` via:
//
//          ContainerengineClusterMap{ "key": ContainerengineClusterArgs{...} }
type ContainerengineClusterMapInput interface {
	pulumi.Input

	ToContainerengineClusterMapOutput() ContainerengineClusterMapOutput
	ToContainerengineClusterMapOutputWithContext(context.Context) ContainerengineClusterMapOutput
}

type ContainerengineClusterMap map[string]ContainerengineClusterInput

func (ContainerengineClusterMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ContainerengineCluster)(nil)).Elem()
}

func (i ContainerengineClusterMap) ToContainerengineClusterMapOutput() ContainerengineClusterMapOutput {
	return i.ToContainerengineClusterMapOutputWithContext(context.Background())
}

func (i ContainerengineClusterMap) ToContainerengineClusterMapOutputWithContext(ctx context.Context) ContainerengineClusterMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ContainerengineClusterMapOutput)
}

type ContainerengineClusterOutput struct {
	*pulumi.OutputState
}

func (ContainerengineClusterOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*ContainerengineCluster)(nil))
}

func (o ContainerengineClusterOutput) ToContainerengineClusterOutput() ContainerengineClusterOutput {
	return o
}

func (o ContainerengineClusterOutput) ToContainerengineClusterOutputWithContext(ctx context.Context) ContainerengineClusterOutput {
	return o
}

func (o ContainerengineClusterOutput) ToContainerengineClusterPtrOutput() ContainerengineClusterPtrOutput {
	return o.ToContainerengineClusterPtrOutputWithContext(context.Background())
}

func (o ContainerengineClusterOutput) ToContainerengineClusterPtrOutputWithContext(ctx context.Context) ContainerengineClusterPtrOutput {
	return o.ApplyT(func(v ContainerengineCluster) *ContainerengineCluster {
		return &v
	}).(ContainerengineClusterPtrOutput)
}

type ContainerengineClusterPtrOutput struct {
	*pulumi.OutputState
}

func (ContainerengineClusterPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ContainerengineCluster)(nil))
}

func (o ContainerengineClusterPtrOutput) ToContainerengineClusterPtrOutput() ContainerengineClusterPtrOutput {
	return o
}

func (o ContainerengineClusterPtrOutput) ToContainerengineClusterPtrOutputWithContext(ctx context.Context) ContainerengineClusterPtrOutput {
	return o
}

type ContainerengineClusterArrayOutput struct{ *pulumi.OutputState }

func (ContainerengineClusterArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]ContainerengineCluster)(nil))
}

func (o ContainerengineClusterArrayOutput) ToContainerengineClusterArrayOutput() ContainerengineClusterArrayOutput {
	return o
}

func (o ContainerengineClusterArrayOutput) ToContainerengineClusterArrayOutputWithContext(ctx context.Context) ContainerengineClusterArrayOutput {
	return o
}

func (o ContainerengineClusterArrayOutput) Index(i pulumi.IntInput) ContainerengineClusterOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) ContainerengineCluster {
		return vs[0].([]ContainerengineCluster)[vs[1].(int)]
	}).(ContainerengineClusterOutput)
}

type ContainerengineClusterMapOutput struct{ *pulumi.OutputState }

func (ContainerengineClusterMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]ContainerengineCluster)(nil))
}

func (o ContainerengineClusterMapOutput) ToContainerengineClusterMapOutput() ContainerengineClusterMapOutput {
	return o
}

func (o ContainerengineClusterMapOutput) ToContainerengineClusterMapOutputWithContext(ctx context.Context) ContainerengineClusterMapOutput {
	return o
}

func (o ContainerengineClusterMapOutput) MapIndex(k pulumi.StringInput) ContainerengineClusterOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) ContainerengineCluster {
		return vs[0].(map[string]ContainerengineCluster)[vs[1].(string)]
	}).(ContainerengineClusterOutput)
}

func init() {
	pulumi.RegisterOutputType(ContainerengineClusterOutput{})
	pulumi.RegisterOutputType(ContainerengineClusterPtrOutput{})
	pulumi.RegisterOutputType(ContainerengineClusterArrayOutput{})
	pulumi.RegisterOutputType(ContainerengineClusterMapOutput{})
}