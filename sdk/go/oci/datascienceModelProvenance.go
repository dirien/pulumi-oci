// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Model Provenance resource in Oracle Cloud Infrastructure Data Science service.
//
// Creates provenance information for the specified model.
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
// 		_, err := oci.NewDatascienceModelProvenance(ctx, "testModelProvenance", &oci.DatascienceModelProvenanceArgs{
// 			ModelId:        pulumi.Any(oci_datascience_model.Test_model.Id),
// 			GitBranch:      pulumi.Any(_var.Model_provenance_git_branch),
// 			GitCommit:      pulumi.Any(_var.Model_provenance_git_commit),
// 			RepositoryUrl:  pulumi.Any(_var.Model_provenance_repository_url),
// 			ScriptDir:      pulumi.Any(_var.Model_provenance_script_dir),
// 			TrainingId:     pulumi.Any(oci_datascience_training.Test_training.Id),
// 			TrainingScript: pulumi.Any(_var.Model_provenance_training_script),
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
// ModelProvenances can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/datascienceModelProvenance:DatascienceModelProvenance test_model_provenance "models/{modelId}/provenance"
// ```
type DatascienceModelProvenance struct {
	pulumi.CustomResourceState

	// (Updatable) For model reproducibility purposes. Branch of the git repository associated with model training.
	GitBranch pulumi.StringOutput `pulumi:"gitBranch"`
	// (Updatable) For model reproducibility purposes. Commit ID of the git repository associated with model training.
	GitCommit pulumi.StringOutput `pulumi:"gitCommit"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
	ModelId pulumi.StringOutput `pulumi:"modelId"`
	// (Updatable) For model reproducibility purposes. URL of the git repository associated with model training.
	RepositoryUrl pulumi.StringOutput `pulumi:"repositoryUrl"`
	// (Updatable) For model reproducibility purposes. Path to model artifacts.
	ScriptDir pulumi.StringOutput `pulumi:"scriptDir"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a training session(Job or NotebookSession) in which the model was trained. It is used for model reproducibility purposes.
	TrainingId pulumi.StringOutput `pulumi:"trainingId"`
	// (Updatable) For model reproducibility purposes. Path to the python script or notebook in which the model was trained."
	TrainingScript pulumi.StringOutput `pulumi:"trainingScript"`
}

// NewDatascienceModelProvenance registers a new resource with the given unique name, arguments, and options.
func NewDatascienceModelProvenance(ctx *pulumi.Context,
	name string, args *DatascienceModelProvenanceArgs, opts ...pulumi.ResourceOption) (*DatascienceModelProvenance, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ModelId == nil {
		return nil, errors.New("invalid value for required argument 'ModelId'")
	}
	var resource DatascienceModelProvenance
	err := ctx.RegisterResource("oci:index/datascienceModelProvenance:DatascienceModelProvenance", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetDatascienceModelProvenance gets an existing DatascienceModelProvenance resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetDatascienceModelProvenance(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *DatascienceModelProvenanceState, opts ...pulumi.ResourceOption) (*DatascienceModelProvenance, error) {
	var resource DatascienceModelProvenance
	err := ctx.ReadResource("oci:index/datascienceModelProvenance:DatascienceModelProvenance", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering DatascienceModelProvenance resources.
type datascienceModelProvenanceState struct {
	// (Updatable) For model reproducibility purposes. Branch of the git repository associated with model training.
	GitBranch *string `pulumi:"gitBranch"`
	// (Updatable) For model reproducibility purposes. Commit ID of the git repository associated with model training.
	GitCommit *string `pulumi:"gitCommit"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
	ModelId *string `pulumi:"modelId"`
	// (Updatable) For model reproducibility purposes. URL of the git repository associated with model training.
	RepositoryUrl *string `pulumi:"repositoryUrl"`
	// (Updatable) For model reproducibility purposes. Path to model artifacts.
	ScriptDir *string `pulumi:"scriptDir"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a training session(Job or NotebookSession) in which the model was trained. It is used for model reproducibility purposes.
	TrainingId *string `pulumi:"trainingId"`
	// (Updatable) For model reproducibility purposes. Path to the python script or notebook in which the model was trained."
	TrainingScript *string `pulumi:"trainingScript"`
}

type DatascienceModelProvenanceState struct {
	// (Updatable) For model reproducibility purposes. Branch of the git repository associated with model training.
	GitBranch pulumi.StringPtrInput
	// (Updatable) For model reproducibility purposes. Commit ID of the git repository associated with model training.
	GitCommit pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
	ModelId pulumi.StringPtrInput
	// (Updatable) For model reproducibility purposes. URL of the git repository associated with model training.
	RepositoryUrl pulumi.StringPtrInput
	// (Updatable) For model reproducibility purposes. Path to model artifacts.
	ScriptDir pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a training session(Job or NotebookSession) in which the model was trained. It is used for model reproducibility purposes.
	TrainingId pulumi.StringPtrInput
	// (Updatable) For model reproducibility purposes. Path to the python script or notebook in which the model was trained."
	TrainingScript pulumi.StringPtrInput
}

func (DatascienceModelProvenanceState) ElementType() reflect.Type {
	return reflect.TypeOf((*datascienceModelProvenanceState)(nil)).Elem()
}

type datascienceModelProvenanceArgs struct {
	// (Updatable) For model reproducibility purposes. Branch of the git repository associated with model training.
	GitBranch *string `pulumi:"gitBranch"`
	// (Updatable) For model reproducibility purposes. Commit ID of the git repository associated with model training.
	GitCommit *string `pulumi:"gitCommit"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
	ModelId string `pulumi:"modelId"`
	// (Updatable) For model reproducibility purposes. URL of the git repository associated with model training.
	RepositoryUrl *string `pulumi:"repositoryUrl"`
	// (Updatable) For model reproducibility purposes. Path to model artifacts.
	ScriptDir *string `pulumi:"scriptDir"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a training session(Job or NotebookSession) in which the model was trained. It is used for model reproducibility purposes.
	TrainingId *string `pulumi:"trainingId"`
	// (Updatable) For model reproducibility purposes. Path to the python script or notebook in which the model was trained."
	TrainingScript *string `pulumi:"trainingScript"`
}

// The set of arguments for constructing a DatascienceModelProvenance resource.
type DatascienceModelProvenanceArgs struct {
	// (Updatable) For model reproducibility purposes. Branch of the git repository associated with model training.
	GitBranch pulumi.StringPtrInput
	// (Updatable) For model reproducibility purposes. Commit ID of the git repository associated with model training.
	GitCommit pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
	ModelId pulumi.StringInput
	// (Updatable) For model reproducibility purposes. URL of the git repository associated with model training.
	RepositoryUrl pulumi.StringPtrInput
	// (Updatable) For model reproducibility purposes. Path to model artifacts.
	ScriptDir pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a training session(Job or NotebookSession) in which the model was trained. It is used for model reproducibility purposes.
	TrainingId pulumi.StringPtrInput
	// (Updatable) For model reproducibility purposes. Path to the python script or notebook in which the model was trained."
	TrainingScript pulumi.StringPtrInput
}

func (DatascienceModelProvenanceArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*datascienceModelProvenanceArgs)(nil)).Elem()
}

type DatascienceModelProvenanceInput interface {
	pulumi.Input

	ToDatascienceModelProvenanceOutput() DatascienceModelProvenanceOutput
	ToDatascienceModelProvenanceOutputWithContext(ctx context.Context) DatascienceModelProvenanceOutput
}

func (*DatascienceModelProvenance) ElementType() reflect.Type {
	return reflect.TypeOf((*DatascienceModelProvenance)(nil))
}

func (i *DatascienceModelProvenance) ToDatascienceModelProvenanceOutput() DatascienceModelProvenanceOutput {
	return i.ToDatascienceModelProvenanceOutputWithContext(context.Background())
}

func (i *DatascienceModelProvenance) ToDatascienceModelProvenanceOutputWithContext(ctx context.Context) DatascienceModelProvenanceOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatascienceModelProvenanceOutput)
}

func (i *DatascienceModelProvenance) ToDatascienceModelProvenancePtrOutput() DatascienceModelProvenancePtrOutput {
	return i.ToDatascienceModelProvenancePtrOutputWithContext(context.Background())
}

func (i *DatascienceModelProvenance) ToDatascienceModelProvenancePtrOutputWithContext(ctx context.Context) DatascienceModelProvenancePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatascienceModelProvenancePtrOutput)
}

type DatascienceModelProvenancePtrInput interface {
	pulumi.Input

	ToDatascienceModelProvenancePtrOutput() DatascienceModelProvenancePtrOutput
	ToDatascienceModelProvenancePtrOutputWithContext(ctx context.Context) DatascienceModelProvenancePtrOutput
}

type datascienceModelProvenancePtrType DatascienceModelProvenanceArgs

func (*datascienceModelProvenancePtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**DatascienceModelProvenance)(nil))
}

func (i *datascienceModelProvenancePtrType) ToDatascienceModelProvenancePtrOutput() DatascienceModelProvenancePtrOutput {
	return i.ToDatascienceModelProvenancePtrOutputWithContext(context.Background())
}

func (i *datascienceModelProvenancePtrType) ToDatascienceModelProvenancePtrOutputWithContext(ctx context.Context) DatascienceModelProvenancePtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatascienceModelProvenancePtrOutput)
}

// DatascienceModelProvenanceArrayInput is an input type that accepts DatascienceModelProvenanceArray and DatascienceModelProvenanceArrayOutput values.
// You can construct a concrete instance of `DatascienceModelProvenanceArrayInput` via:
//
//          DatascienceModelProvenanceArray{ DatascienceModelProvenanceArgs{...} }
type DatascienceModelProvenanceArrayInput interface {
	pulumi.Input

	ToDatascienceModelProvenanceArrayOutput() DatascienceModelProvenanceArrayOutput
	ToDatascienceModelProvenanceArrayOutputWithContext(context.Context) DatascienceModelProvenanceArrayOutput
}

type DatascienceModelProvenanceArray []DatascienceModelProvenanceInput

func (DatascienceModelProvenanceArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DatascienceModelProvenance)(nil)).Elem()
}

func (i DatascienceModelProvenanceArray) ToDatascienceModelProvenanceArrayOutput() DatascienceModelProvenanceArrayOutput {
	return i.ToDatascienceModelProvenanceArrayOutputWithContext(context.Background())
}

func (i DatascienceModelProvenanceArray) ToDatascienceModelProvenanceArrayOutputWithContext(ctx context.Context) DatascienceModelProvenanceArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatascienceModelProvenanceArrayOutput)
}

// DatascienceModelProvenanceMapInput is an input type that accepts DatascienceModelProvenanceMap and DatascienceModelProvenanceMapOutput values.
// You can construct a concrete instance of `DatascienceModelProvenanceMapInput` via:
//
//          DatascienceModelProvenanceMap{ "key": DatascienceModelProvenanceArgs{...} }
type DatascienceModelProvenanceMapInput interface {
	pulumi.Input

	ToDatascienceModelProvenanceMapOutput() DatascienceModelProvenanceMapOutput
	ToDatascienceModelProvenanceMapOutputWithContext(context.Context) DatascienceModelProvenanceMapOutput
}

type DatascienceModelProvenanceMap map[string]DatascienceModelProvenanceInput

func (DatascienceModelProvenanceMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DatascienceModelProvenance)(nil)).Elem()
}

func (i DatascienceModelProvenanceMap) ToDatascienceModelProvenanceMapOutput() DatascienceModelProvenanceMapOutput {
	return i.ToDatascienceModelProvenanceMapOutputWithContext(context.Background())
}

func (i DatascienceModelProvenanceMap) ToDatascienceModelProvenanceMapOutputWithContext(ctx context.Context) DatascienceModelProvenanceMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatascienceModelProvenanceMapOutput)
}

type DatascienceModelProvenanceOutput struct {
	*pulumi.OutputState
}

func (DatascienceModelProvenanceOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*DatascienceModelProvenance)(nil))
}

func (o DatascienceModelProvenanceOutput) ToDatascienceModelProvenanceOutput() DatascienceModelProvenanceOutput {
	return o
}

func (o DatascienceModelProvenanceOutput) ToDatascienceModelProvenanceOutputWithContext(ctx context.Context) DatascienceModelProvenanceOutput {
	return o
}

func (o DatascienceModelProvenanceOutput) ToDatascienceModelProvenancePtrOutput() DatascienceModelProvenancePtrOutput {
	return o.ToDatascienceModelProvenancePtrOutputWithContext(context.Background())
}

func (o DatascienceModelProvenanceOutput) ToDatascienceModelProvenancePtrOutputWithContext(ctx context.Context) DatascienceModelProvenancePtrOutput {
	return o.ApplyT(func(v DatascienceModelProvenance) *DatascienceModelProvenance {
		return &v
	}).(DatascienceModelProvenancePtrOutput)
}

type DatascienceModelProvenancePtrOutput struct {
	*pulumi.OutputState
}

func (DatascienceModelProvenancePtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**DatascienceModelProvenance)(nil))
}

func (o DatascienceModelProvenancePtrOutput) ToDatascienceModelProvenancePtrOutput() DatascienceModelProvenancePtrOutput {
	return o
}

func (o DatascienceModelProvenancePtrOutput) ToDatascienceModelProvenancePtrOutputWithContext(ctx context.Context) DatascienceModelProvenancePtrOutput {
	return o
}

type DatascienceModelProvenanceArrayOutput struct{ *pulumi.OutputState }

func (DatascienceModelProvenanceArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]DatascienceModelProvenance)(nil))
}

func (o DatascienceModelProvenanceArrayOutput) ToDatascienceModelProvenanceArrayOutput() DatascienceModelProvenanceArrayOutput {
	return o
}

func (o DatascienceModelProvenanceArrayOutput) ToDatascienceModelProvenanceArrayOutputWithContext(ctx context.Context) DatascienceModelProvenanceArrayOutput {
	return o
}

func (o DatascienceModelProvenanceArrayOutput) Index(i pulumi.IntInput) DatascienceModelProvenanceOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) DatascienceModelProvenance {
		return vs[0].([]DatascienceModelProvenance)[vs[1].(int)]
	}).(DatascienceModelProvenanceOutput)
}

type DatascienceModelProvenanceMapOutput struct{ *pulumi.OutputState }

func (DatascienceModelProvenanceMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]DatascienceModelProvenance)(nil))
}

func (o DatascienceModelProvenanceMapOutput) ToDatascienceModelProvenanceMapOutput() DatascienceModelProvenanceMapOutput {
	return o
}

func (o DatascienceModelProvenanceMapOutput) ToDatascienceModelProvenanceMapOutputWithContext(ctx context.Context) DatascienceModelProvenanceMapOutput {
	return o
}

func (o DatascienceModelProvenanceMapOutput) MapIndex(k pulumi.StringInput) DatascienceModelProvenanceOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) DatascienceModelProvenance {
		return vs[0].(map[string]DatascienceModelProvenance)[vs[1].(string)]
	}).(DatascienceModelProvenanceOutput)
}

func init() {
	pulumi.RegisterOutputType(DatascienceModelProvenanceOutput{})
	pulumi.RegisterOutputType(DatascienceModelProvenancePtrOutput{})
	pulumi.RegisterOutputType(DatascienceModelProvenanceArrayOutput{})
	pulumi.RegisterOutputType(DatascienceModelProvenanceMapOutput{})
}
