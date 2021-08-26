// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.MeteringComputation
{
    public static class GetCustomTables
    {
        /// <summary>
        /// This data source provides the list of Custom Tables in Oracle Cloud Infrastructure Metering Computation service.
        /// 
        /// Returns the saved custom table list.
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
        ///         var testCustomTables = Output.Create(Oci.MeteringComputation.GetCustomTables.InvokeAsync(new Oci.MeteringComputation.GetCustomTablesArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             SavedReportId = oci_metering_computation_saved_report.Test_saved_report.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetCustomTablesResult> InvokeAsync(GetCustomTablesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetCustomTablesResult>("oci:meteringcomputation/getCustomTables:getCustomTables", args ?? new GetCustomTablesArgs(), options.WithVersion());
    }


    public sealed class GetCustomTablesArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The compartment ID in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetCustomTablesFilterArgs>? _filters;
        public List<Inputs.GetCustomTablesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetCustomTablesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The saved report ID in which to list resources.
        /// </summary>
        [Input("savedReportId", required: true)]
        public string SavedReportId { get; set; } = null!;

        public GetCustomTablesArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetCustomTablesResult
    {
        /// <summary>
        /// The custom table compartment OCID.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The list of custom_table_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetCustomTablesCustomTableCollectionResult> CustomTableCollections;
        public readonly ImmutableArray<Outputs.GetCustomTablesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The custom table associated saved report OCID.
        /// </summary>
        public readonly string SavedReportId;

        [OutputConstructor]
        private GetCustomTablesResult(
            string compartmentId,

            ImmutableArray<Outputs.GetCustomTablesCustomTableCollectionResult> customTableCollections,

            ImmutableArray<Outputs.GetCustomTablesFilterResult> filters,

            string id,

            string savedReportId)
        {
            CompartmentId = compartmentId;
            CustomTableCollections = customTableCollections;
            Filters = filters;
            Id = id;
            SavedReportId = savedReportId;
        }
    }
}
