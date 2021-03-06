// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetDataGuardAssociations
    {
        /// <summary>
        /// This data source provides the list of Data Guard Associations in Oracle Cloud Infrastructure Database service.
        /// 
        /// Lists all Data Guard associations for the specified database.
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
        ///         var testDataGuardAssociations = Output.Create(Oci.Database.GetDataGuardAssociations.InvokeAsync(new Oci.Database.GetDataGuardAssociationsArgs
        ///         {
        ///             DatabaseId = oci_database_database.Test_database.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDataGuardAssociationsResult> InvokeAsync(GetDataGuardAssociationsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDataGuardAssociationsResult>("oci:database/getDataGuardAssociations:getDataGuardAssociations", args ?? new GetDataGuardAssociationsArgs(), options.WithVersion());
    }


    public sealed class GetDataGuardAssociationsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("databaseId", required: true)]
        public string DatabaseId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetDataGuardAssociationsFilterArgs>? _filters;
        public List<Inputs.GetDataGuardAssociationsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDataGuardAssociationsFilterArgs>());
            set => _filters = value;
        }

        public GetDataGuardAssociationsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetDataGuardAssociationsResult
    {
        /// <summary>
        /// The list of data_guard_associations.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDataGuardAssociationsDataGuardAssociationResult> DataGuardAssociations;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the reporting database.
        /// </summary>
        public readonly string DatabaseId;
        public readonly ImmutableArray<Outputs.GetDataGuardAssociationsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetDataGuardAssociationsResult(
            ImmutableArray<Outputs.GetDataGuardAssociationsDataGuardAssociationResult> dataGuardAssociations,

            string databaseId,

            ImmutableArray<Outputs.GetDataGuardAssociationsFilterResult> filters,

            string id)
        {
            DataGuardAssociations = dataGuardAssociations;
            DatabaseId = databaseId;
            Filters = filters;
            Id = id;
        }
    }
}
