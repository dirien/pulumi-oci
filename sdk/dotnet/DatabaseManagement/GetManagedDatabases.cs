// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    public static class GetManagedDatabases
    {
        /// <summary>
        /// This data source provides the list of Managed Databases in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the Managed Database for a specific ID or the list of Managed Databases in a specific compartment.
        /// Managed Databases can also be filtered based on the name parameter. Only one of the parameters, ID or name
        /// should be provided. If none of these parameters is provided, all the Managed Databases in the compartment are listed.
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
        ///         var testManagedDatabases = Output.Create(Oci.DatabaseManagement.GetManagedDatabases.InvokeAsync(new Oci.DatabaseManagement.GetManagedDatabasesArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             Id = @var.Managed_database_id,
        ///             Name = @var.Managed_database_name,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetManagedDatabasesResult> InvokeAsync(GetManagedDatabasesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetManagedDatabasesResult>("oci:databasemanagement/getManagedDatabases:getManagedDatabases", args ?? new GetManagedDatabasesArgs(), options.WithVersion());
    }


    public sealed class GetManagedDatabasesArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetManagedDatabasesFilterArgs>? _filters;
        public List<Inputs.GetManagedDatabasesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetManagedDatabasesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The identifier of the resource.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire name.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        public GetManagedDatabasesArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetManagedDatabasesResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database Group resides.
        /// </summary>
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetManagedDatabasesFilterResult> Filters;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database Group.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The list of managed_database_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedDatabasesManagedDatabaseCollectionResult> ManagedDatabaseCollections;
        /// <summary>
        /// The name of the Managed Database.
        /// </summary>
        public readonly string? Name;

        [OutputConstructor]
        private GetManagedDatabasesResult(
            string compartmentId,

            ImmutableArray<Outputs.GetManagedDatabasesFilterResult> filters,

            string? id,

            ImmutableArray<Outputs.GetManagedDatabasesManagedDatabaseCollectionResult> managedDatabaseCollections,

            string? name)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            ManagedDatabaseCollections = managedDatabaseCollections;
            Name = name;
        }
    }
}
