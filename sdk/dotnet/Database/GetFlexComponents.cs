// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetFlexComponents
    {
        /// <summary>
        /// This data source provides the list of Flex Components in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets a list of the flex components that can be used to launch a new DB system. The flex component determines resources to allocate to the DB system - Database Servers and Storage Servers.
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
        ///         var testFlexComponents = Output.Create(Oci.Database.GetFlexComponents.InvokeAsync(new Oci.Database.GetFlexComponentsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             Name = @var.Flex_component_name,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetFlexComponentsResult> InvokeAsync(GetFlexComponentsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetFlexComponentsResult>("oci:database/getFlexComponents:getFlexComponents", args ?? new GetFlexComponentsArgs(), options.WithVersion());
    }


    public sealed class GetFlexComponentsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetFlexComponentsFilterArgs>? _filters;
        public List<Inputs.GetFlexComponentsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetFlexComponentsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the entire name given. The match is not case sensitive.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        public GetFlexComponentsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetFlexComponentsResult
    {
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetFlexComponentsFilterResult> Filters;
        /// <summary>
        /// The list of flex_component_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFlexComponentsFlexComponentCollectionResult> FlexComponentCollections;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The name of the Flex Component used for the DB system.
        /// </summary>
        public readonly string? Name;

        [OutputConstructor]
        private GetFlexComponentsResult(
            string compartmentId,

            ImmutableArray<Outputs.GetFlexComponentsFilterResult> filters,

            ImmutableArray<Outputs.GetFlexComponentsFlexComponentCollectionResult> flexComponentCollections,

            string id,

            string? name)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            FlexComponentCollections = flexComponentCollections;
            Id = id;
            Name = name;
        }
    }
}
