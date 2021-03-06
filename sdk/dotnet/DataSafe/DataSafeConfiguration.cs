// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    /// <summary>
    /// This resource provides the Data Safe Configuration resource in Oracle Cloud Infrastructure Data Safe service.
    /// 
    /// Enables Data Safe in the tenancy and region.
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
    ///         var testDataSafeConfiguration = new Oci.DataSafe.DataSafeConfiguration("testDataSafeConfiguration", new Oci.DataSafe.DataSafeConfigurationArgs
    ///         {
    ///             IsEnabled = @var.Data_safe_configuration_is_enabled,
    ///             CompartmentId = @var.Compartment_id,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// Import is not supported for this resource.
    /// </summary>
    [OciResourceType("oci:datasafe/dataSafeConfiguration:DataSafeConfiguration")]
    public partial class DataSafeConfiguration : Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) A filter to return only resources that match the specified compartment OCID.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Indicates if Data Safe is enabled.
        /// </summary>
        [Output("isEnabled")]
        public Output<bool> IsEnabled { get; private set; } = null!;

        /// <summary>
        /// The current state of Data Safe.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The date and time Data Safe was enabled, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Output("timeEnabled")]
        public Output<string> TimeEnabled { get; private set; } = null!;

        /// <summary>
        /// The URL of the Data Safe service.
        /// </summary>
        [Output("url")]
        public Output<string> Url { get; private set; } = null!;


        /// <summary>
        /// Create a DataSafeConfiguration resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public DataSafeConfiguration(string name, DataSafeConfigurationArgs args, CustomResourceOptions? options = null)
            : base("oci:datasafe/dataSafeConfiguration:DataSafeConfiguration", name, args ?? new DataSafeConfigurationArgs(), MakeResourceOptions(options, ""))
        {
        }

        private DataSafeConfiguration(string name, Input<string> id, DataSafeConfigurationState? state = null, CustomResourceOptions? options = null)
            : base("oci:datasafe/dataSafeConfiguration:DataSafeConfiguration", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing DataSafeConfiguration resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static DataSafeConfiguration Get(string name, Input<string> id, DataSafeConfigurationState? state = null, CustomResourceOptions? options = null)
        {
            return new DataSafeConfiguration(name, id, state, options);
        }
    }

    public sealed class DataSafeConfigurationArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) A filter to return only resources that match the specified compartment OCID.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// (Updatable) Indicates if Data Safe is enabled.
        /// </summary>
        [Input("isEnabled", required: true)]
        public Input<bool> IsEnabled { get; set; } = null!;

        public DataSafeConfigurationArgs()
        {
        }
    }

    public sealed class DataSafeConfigurationState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) A filter to return only resources that match the specified compartment OCID.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// (Updatable) Indicates if Data Safe is enabled.
        /// </summary>
        [Input("isEnabled")]
        public Input<bool>? IsEnabled { get; set; }

        /// <summary>
        /// The current state of Data Safe.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The date and time Data Safe was enabled, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Input("timeEnabled")]
        public Input<string>? TimeEnabled { get; set; }

        /// <summary>
        /// The URL of the Data Safe service.
        /// </summary>
        [Input("url")]
        public Input<string>? Url { get; set; }

        public DataSafeConfigurationState()
        {
        }
    }
}
