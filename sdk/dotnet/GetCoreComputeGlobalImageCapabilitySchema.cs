// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci
{
    public static class GetCoreComputeGlobalImageCapabilitySchema
    {
        /// <summary>
        /// This data source provides details about a specific Compute Global Image Capability Schema resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Gets the specified Compute Global Image Capability Schema
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testComputeGlobalImageCapabilitySchema = Output.Create(Oci.GetCoreComputeGlobalImageCapabilitySchema.InvokeAsync(new Oci.GetCoreComputeGlobalImageCapabilitySchemaArgs
        ///         {
        ///             ComputeGlobalImageCapabilitySchemaId = oci_core_compute_global_image_capability_schema.Test_compute_global_image_capability_schema.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetCoreComputeGlobalImageCapabilitySchemaResult> InvokeAsync(GetCoreComputeGlobalImageCapabilitySchemaArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetCoreComputeGlobalImageCapabilitySchemaResult>("oci:index/getCoreComputeGlobalImageCapabilitySchema:GetCoreComputeGlobalImageCapabilitySchema", args ?? new GetCoreComputeGlobalImageCapabilitySchemaArgs(), options.WithVersion());
    }


    public sealed class GetCoreComputeGlobalImageCapabilitySchemaArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute global image capability schema
        /// </summary>
        [Input("computeGlobalImageCapabilitySchemaId", required: true)]
        public string ComputeGlobalImageCapabilitySchemaId { get; set; } = null!;

        public GetCoreComputeGlobalImageCapabilitySchemaArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetCoreComputeGlobalImageCapabilitySchemaResult
    {
        /// <summary>
        /// The OCID of the compartment containing the compute global image capability schema
        /// </summary>
        public readonly string CompartmentId;
        public readonly string ComputeGlobalImageCapabilitySchemaId;
        /// <summary>
        /// The name of the global capabilities version resource that is considered the current version.
        /// </summary>
        public readonly string CurrentVersionName;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// A user-friendly name for the compute global image capability schema.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The date and time the compute global image capability schema was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetCoreComputeGlobalImageCapabilitySchemaResult(
            string compartmentId,

            string computeGlobalImageCapabilitySchemaId,

            string currentVersionName,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string timeCreated)
        {
            CompartmentId = compartmentId;
            ComputeGlobalImageCapabilitySchemaId = computeGlobalImageCapabilitySchemaId;
            CurrentVersionName = currentVersionName;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            TimeCreated = timeCreated;
        }
    }
}