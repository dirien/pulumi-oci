// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetComputeImageCapabilitySchemas
    {
        /// <summary>
        /// This data source provides the list of Compute Image Capability Schemas in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists Compute Image Capability Schema in the specified compartment. You can also query by a specific imageId.
        /// 
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
        ///         var testComputeImageCapabilitySchemas = Output.Create(Oci.Core.GetComputeImageCapabilitySchemas.InvokeAsync(new Oci.Core.GetComputeImageCapabilitySchemasArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             DisplayName = @var.Compute_image_capability_schema_display_name,
        ///             ImageId = oci_core_image.Test_image.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetComputeImageCapabilitySchemasResult> InvokeAsync(GetComputeImageCapabilitySchemasArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetComputeImageCapabilitySchemasResult>("oci:core/getComputeImageCapabilitySchemas:getComputeImageCapabilitySchemas", args ?? new GetComputeImageCapabilitySchemasArgs(), options.WithVersion());
    }


    public sealed class GetComputeImageCapabilitySchemasArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return only resources that match the given compartment OCID exactly.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetComputeImageCapabilitySchemasFilterArgs>? _filters;
        public List<Inputs.GetComputeImageCapabilitySchemasFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetComputeImageCapabilitySchemasFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of an image.
        /// </summary>
        [Input("imageId")]
        public string? ImageId { get; set; }

        public GetComputeImageCapabilitySchemasArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetComputeImageCapabilitySchemasResult
    {
        /// <summary>
        /// The OCID of the compartment containing the compute global image capability schema
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// The list of compute_image_capability_schemas.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetComputeImageCapabilitySchemasComputeImageCapabilitySchemaResult> ComputeImageCapabilitySchemas;
        /// <summary>
        /// A user-friendly name for the compute global image capability schema
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetComputeImageCapabilitySchemasFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The OCID of the image associated with this compute image capability schema
        /// </summary>
        public readonly string? ImageId;

        [OutputConstructor]
        private GetComputeImageCapabilitySchemasResult(
            string? compartmentId,

            ImmutableArray<Outputs.GetComputeImageCapabilitySchemasComputeImageCapabilitySchemaResult> computeImageCapabilitySchemas,

            string? displayName,

            ImmutableArray<Outputs.GetComputeImageCapabilitySchemasFilterResult> filters,

            string id,

            string? imageId)
        {
            CompartmentId = compartmentId;
            ComputeImageCapabilitySchemas = computeImageCapabilitySchemas;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            ImageId = imageId;
        }
    }
}
