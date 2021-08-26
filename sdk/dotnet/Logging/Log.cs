// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Logging
{
    /// <summary>
    /// This resource provides the Log resource in Oracle Cloud Infrastructure Logging service.
    /// 
    /// Creates a log within the specified log group. This call fails if a log group has already been created
    /// with the same displayName or (service, resource, category) triplet.
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
    ///         var testLog = new Oci.Logging.Log("testLog", new Oci.Logging.LogArgs
    ///         {
    ///             DisplayName = @var.Log_display_name,
    ///             LogGroupId = oci_logging_log_group.Test_log_group.Id,
    ///             LogType = @var.Log_log_type,
    ///             Configuration = new Oci.Logging.Inputs.LogConfigurationArgs
    ///             {
    ///                 Source = new Oci.Logging.Inputs.LogConfigurationSourceArgs
    ///                 {
    ///                     Category = @var.Log_configuration_source_category,
    ///                     Resource = @var.Log_configuration_source_resource,
    ///                     Service = @var.Log_configuration_source_service,
    ///                     SourceType = @var.Log_configuration_source_source_type,
    ///                 },
    ///                 CompartmentId = @var.Compartment_id,
    ///             },
    ///             DefinedTags = 
    ///             {
    ///                 { "Operations.CostCenter", "42" },
    ///             },
    ///             FreeformTags = 
    ///             {
    ///                 { "Department", "Finance" },
    ///             },
    ///             IsEnabled = @var.Log_is_enabled,
    ///             RetentionDuration = @var.Log_retention_duration,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// Logs can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:logging/log:Log test_log "logGroupId/{logGroupId}/logId/{logId}"
    /// ```
    /// </summary>
    [OciResourceType("oci:logging/log:Log")]
    public partial class Log : Pulumi.CustomResource
    {
        /// <summary>
        /// The OCID of the compartment that the resource belongs to.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// Log object configuration.
        /// </summary>
        [Output("configuration")]
        public Output<Outputs.LogConfiguration> Configuration { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Whether or not this resource is currently enabled.
        /// </summary>
        [Output("isEnabled")]
        public Output<bool> IsEnabled { get; private set; } = null!;

        /// <summary>
        /// (Updatable) OCID of a log group to work with.
        /// </summary>
        [Output("logGroupId")]
        public Output<string> LogGroupId { get; private set; } = null!;

        /// <summary>
        /// The logType that the log object is for, whether custom or service.
        /// </summary>
        [Output("logType")]
        public Output<string> LogType { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Log retention duration in 30-day increments (30, 60, 90 and so on).
        /// </summary>
        [Output("retentionDuration")]
        public Output<int> RetentionDuration { get; private set; } = null!;

        /// <summary>
        /// The pipeline state.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The OCID of the tenancy.
        /// </summary>
        [Output("tenancyId")]
        public Output<string> TenancyId { get; private set; } = null!;

        /// <summary>
        /// Time the resource was created.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// Time the resource was last modified.
        /// </summary>
        [Output("timeLastModified")]
        public Output<string> TimeLastModified { get; private set; } = null!;


        /// <summary>
        /// Create a Log resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Log(string name, LogArgs args, CustomResourceOptions? options = null)
            : base("oci:logging/log:Log", name, args ?? new LogArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Log(string name, Input<string> id, LogState? state = null, CustomResourceOptions? options = null)
            : base("oci:logging/log:Log", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing Log resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Log Get(string name, Input<string> id, LogState? state = null, CustomResourceOptions? options = null)
        {
            return new Log(name, id, state, options);
        }
    }

    public sealed class LogArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Log object configuration.
        /// </summary>
        [Input("configuration")]
        public Input<Inputs.LogConfigurationArgs>? Configuration { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) Whether or not this resource is currently enabled.
        /// </summary>
        [Input("isEnabled")]
        public Input<bool>? IsEnabled { get; set; }

        /// <summary>
        /// (Updatable) OCID of a log group to work with.
        /// </summary>
        [Input("logGroupId", required: true)]
        public Input<string> LogGroupId { get; set; } = null!;

        /// <summary>
        /// The logType that the log object is for, whether custom or service.
        /// </summary>
        [Input("logType", required: true)]
        public Input<string> LogType { get; set; } = null!;

        /// <summary>
        /// (Updatable) Log retention duration in 30-day increments (30, 60, 90 and so on).
        /// </summary>
        [Input("retentionDuration")]
        public Input<int>? RetentionDuration { get; set; }

        public LogArgs()
        {
        }
    }

    public sealed class LogState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the compartment that the resource belongs to.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// Log object configuration.
        /// </summary>
        [Input("configuration")]
        public Input<Inputs.LogConfigurationGetArgs>? Configuration { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) Whether or not this resource is currently enabled.
        /// </summary>
        [Input("isEnabled")]
        public Input<bool>? IsEnabled { get; set; }

        /// <summary>
        /// (Updatable) OCID of a log group to work with.
        /// </summary>
        [Input("logGroupId")]
        public Input<string>? LogGroupId { get; set; }

        /// <summary>
        /// The logType that the log object is for, whether custom or service.
        /// </summary>
        [Input("logType")]
        public Input<string>? LogType { get; set; }

        /// <summary>
        /// (Updatable) Log retention duration in 30-day increments (30, 60, 90 and so on).
        /// </summary>
        [Input("retentionDuration")]
        public Input<int>? RetentionDuration { get; set; }

        /// <summary>
        /// The pipeline state.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The OCID of the tenancy.
        /// </summary>
        [Input("tenancyId")]
        public Input<string>? TenancyId { get; set; }

        /// <summary>
        /// Time the resource was created.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// Time the resource was last modified.
        /// </summary>
        [Input("timeLastModified")]
        public Input<string>? TimeLastModified { get; set; }

        public LogState()
        {
        }
    }
}
