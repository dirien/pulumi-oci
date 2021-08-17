// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci
{
    /// <summary>
    /// This resource provides the Model Deployment resource in Oracle Cloud Infrastructure Datascience service.
    /// 
    /// Creates a new model deployment.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// class MyStack : Stack
    /// {
    ///     public MyStack()
    ///     {
    ///         var testModelDeployment = new Oci.DatascienceModelDeployment("testModelDeployment", new Oci.DatascienceModelDeploymentArgs
    ///         {
    ///             CompartmentId = @var.Compartment_id,
    ///             ModelDeploymentConfigurationDetails = new Oci.Inputs.DatascienceModelDeploymentModelDeploymentConfigurationDetailsArgs
    ///             {
    ///                 DeploymentType = @var.Model_deployment_model_deployment_configuration_details_deployment_type,
    ///                 ModelConfigurationDetails = new Oci.Inputs.DatascienceModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsArgs
    ///                 {
    ///                     InstanceConfiguration = new Oci.Inputs.DatascienceModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsInstanceConfigurationArgs
    ///                     {
    ///                         InstanceShapeName = oci_core_shape.Test_shape.Name,
    ///                     },
    ///                     ModelId = oci_datascience_model.Test_model.Id,
    ///                     BandwidthMbps = @var.Model_deployment_model_deployment_configuration_details_model_configuration_details_bandwidth_mbps,
    ///                     ScalingPolicy = new Oci.Inputs.DatascienceModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyArgs
    ///                     {
    ///                         InstanceCount = @var.Model_deployment_model_deployment_configuration_details_model_configuration_details_scaling_policy_instance_count,
    ///                         PolicyType = @var.Model_deployment_model_deployment_configuration_details_model_configuration_details_scaling_policy_policy_type,
    ///                     },
    ///                 },
    ///             },
    ///             ProjectId = oci_datascience_project.Test_project.Id,
    ///             CategoryLogDetails = new Oci.Inputs.DatascienceModelDeploymentCategoryLogDetailsArgs
    ///             {
    ///                 Access = new Oci.Inputs.DatascienceModelDeploymentCategoryLogDetailsAccessArgs
    ///                 {
    ///                     LogGroupId = oci_logging_log_group.Test_log_group.Id,
    ///                     LogId = oci_logging_log.Test_log.Id,
    ///                 },
    ///                 Predict = new Oci.Inputs.DatascienceModelDeploymentCategoryLogDetailsPredictArgs
    ///                 {
    ///                     LogGroupId = oci_logging_log_group.Test_log_group.Id,
    ///                     LogId = oci_logging_log.Test_log.Id,
    ///                 },
    ///             },
    ///             DefinedTags = 
    ///             {
    ///                 { "Operations.CostCenter", "42" },
    ///             },
    ///             Description = @var.Model_deployment_description,
    ///             DisplayName = @var.Model_deployment_display_name,
    ///             FreeformTags = 
    ///             {
    ///                 { "Department", "Finance" },
    ///             },
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// ModelDeployments can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:index/datascienceModelDeployment:DatascienceModelDeployment test_model_deployment "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:index/datascienceModelDeployment:DatascienceModelDeployment")]
    public partial class DatascienceModelDeployment : Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The log details for each category.
        /// </summary>
        [Output("categoryLogDetails")]
        public Output<Outputs.DatascienceModelDeploymentCategoryLogDetails> CategoryLogDetails { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the model deployment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the model deployment.
        /// </summary>
        [Output("createdBy")]
        public Output<string> CreatedBy { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A short description of the model deployment.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-friendly display name for the resource. Does not have to be unique, and can be modified. Avoid entering confidential information. Example: `My ModelDeployment`
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// Details about the state of the model deployment.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The model deployment configuration details.
        /// </summary>
        [Output("modelDeploymentConfigurationDetails")]
        public Output<Outputs.DatascienceModelDeploymentModelDeploymentConfigurationDetails> ModelDeploymentConfigurationDetails { get; private set; } = null!;

        /// <summary>
        /// The URL to interact with the model deployment.
        /// </summary>
        [Output("modelDeploymentUrl")]
        public Output<string> ModelDeploymentUrl { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model deployment.
        /// </summary>
        [Output("projectId")]
        public Output<string> ProjectId { get; private set; } = null!;

        /// <summary>
        /// The state of the model deployment.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The date and time the resource was created, in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2019-08-25T21:10:29.41Z
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;


        /// <summary>
        /// Create a DatascienceModelDeployment resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public DatascienceModelDeployment(string name, DatascienceModelDeploymentArgs args, CustomResourceOptions? options = null)
            : base("oci:index/datascienceModelDeployment:DatascienceModelDeployment", name, args ?? new DatascienceModelDeploymentArgs(), MakeResourceOptions(options, ""))
        {
        }

        private DatascienceModelDeployment(string name, Input<string> id, DatascienceModelDeploymentState? state = null, CustomResourceOptions? options = null)
            : base("oci:index/datascienceModelDeployment:DatascienceModelDeployment", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing DatascienceModelDeployment resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static DatascienceModelDeployment Get(string name, Input<string> id, DatascienceModelDeploymentState? state = null, CustomResourceOptions? options = null)
        {
            return new DatascienceModelDeployment(name, id, state, options);
        }
    }

    public sealed class DatascienceModelDeploymentArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The log details for each category.
        /// </summary>
        [Input("categoryLogDetails")]
        public Input<Inputs.DatascienceModelDeploymentCategoryLogDetailsArgs>? CategoryLogDetails { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the model deployment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A short description of the model deployment.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) A user-friendly display name for the resource. Does not have to be unique, and can be modified. Avoid entering confidential information. Example: `My ModelDeployment`
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) The model deployment configuration details.
        /// </summary>
        [Input("modelDeploymentConfigurationDetails", required: true)]
        public Input<Inputs.DatascienceModelDeploymentModelDeploymentConfigurationDetailsArgs> ModelDeploymentConfigurationDetails { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model deployment.
        /// </summary>
        [Input("projectId", required: true)]
        public Input<string> ProjectId { get; set; } = null!;

        public DatascienceModelDeploymentArgs()
        {
        }
    }

    public sealed class DatascienceModelDeploymentState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The log details for each category.
        /// </summary>
        [Input("categoryLogDetails")]
        public Input<Inputs.DatascienceModelDeploymentCategoryLogDetailsGetArgs>? CategoryLogDetails { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the model deployment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the model deployment.
        /// </summary>
        [Input("createdBy")]
        public Input<string>? CreatedBy { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A short description of the model deployment.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) A user-friendly display name for the resource. Does not have to be unique, and can be modified. Avoid entering confidential information. Example: `My ModelDeployment`
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// Details about the state of the model deployment.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// (Updatable) The model deployment configuration details.
        /// </summary>
        [Input("modelDeploymentConfigurationDetails")]
        public Input<Inputs.DatascienceModelDeploymentModelDeploymentConfigurationDetailsGetArgs>? ModelDeploymentConfigurationDetails { get; set; }

        /// <summary>
        /// The URL to interact with the model deployment.
        /// </summary>
        [Input("modelDeploymentUrl")]
        public Input<string>? ModelDeploymentUrl { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model deployment.
        /// </summary>
        [Input("projectId")]
        public Input<string>? ProjectId { get; set; }

        /// <summary>
        /// The state of the model deployment.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The date and time the resource was created, in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2019-08-25T21:10:29.41Z
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        public DatascienceModelDeploymentState()
        {
        }
    }
}