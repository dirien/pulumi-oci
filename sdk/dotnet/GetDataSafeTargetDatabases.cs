// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci
{
    public static class GetDataSafeTargetDatabases
    {
        /// <summary>
        /// This data source provides the list of Target Databases in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Returns the list of registered target databases in Data Safe.
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
        ///         var testTargetDatabases = Output.Create(Oci.GetDataSafeTargetDatabases.InvokeAsync(new Oci.GetDataSafeTargetDatabasesArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             AccessLevel = @var.Target_database_access_level,
        ///             CompartmentIdInSubtree = @var.Target_database_compartment_id_in_subtree,
        ///             DatabaseType = @var.Target_database_database_type,
        ///             DisplayName = @var.Target_database_display_name,
        ///             InfrastructureType = @var.Target_database_infrastructure_type,
        ///             State = @var.Target_database_state,
        ///             TargetDatabaseId = oci_data_safe_target_database.Test_target_database.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDataSafeTargetDatabasesResult> InvokeAsync(GetDataSafeTargetDatabasesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDataSafeTargetDatabasesResult>("oci:index/getDataSafeTargetDatabases:GetDataSafeTargetDatabases", args ?? new GetDataSafeTargetDatabasesArgs(), options.WithVersion());
    }


    public sealed class GetDataSafeTargetDatabasesArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
        /// </summary>
        [Input("accessLevel")]
        public string? AccessLevel { get; set; }

        /// <summary>
        /// A filter to return only resources that match the specified compartment OCID.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
        /// </summary>
        [Input("compartmentIdInSubtree")]
        public bool? CompartmentIdInSubtree { get; set; }

        /// <summary>
        /// A filter to return target databases that match the database type of the target database.
        /// </summary>
        [Input("databaseType")]
        public string? DatabaseType { get; set; }

        /// <summary>
        /// A filter to return only resources that match the specified display name.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetDataSafeTargetDatabasesFilterArgs>? _filters;
        public List<Inputs.GetDataSafeTargetDatabasesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDataSafeTargetDatabasesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return target databases that match the infrastructure type of the target database.
        /// </summary>
        [Input("infrastructureType")]
        public string? InfrastructureType { get; set; }

        /// <summary>
        /// A filter to return the target databases that matches the current state of the target database.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        /// <summary>
        /// A filter to return the target database that matches the specified OCID.
        /// </summary>
        [Input("targetDatabaseId")]
        public string? TargetDatabaseId { get; set; }

        public GetDataSafeTargetDatabasesArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetDataSafeTargetDatabasesResult
    {
        public readonly string? AccessLevel;
        /// <summary>
        /// The OCID of the compartment which contains the Data Safe target database.
        /// </summary>
        public readonly string CompartmentId;
        public readonly bool? CompartmentIdInSubtree;
        /// <summary>
        /// The database type.
        /// </summary>
        public readonly string? DatabaseType;
        /// <summary>
        /// The display name of the target database in Data Safe.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetDataSafeTargetDatabasesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The infrastructure type the database is running on.
        /// </summary>
        public readonly string? InfrastructureType;
        /// <summary>
        /// The current state of the target database in Data Safe.
        /// </summary>
        public readonly string? State;
        public readonly string? TargetDatabaseId;
        /// <summary>
        /// The list of target_databases.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDataSafeTargetDatabasesTargetDatabaseResult> TargetDatabases;

        [OutputConstructor]
        private GetDataSafeTargetDatabasesResult(
            string? accessLevel,

            string compartmentId,

            bool? compartmentIdInSubtree,

            string? databaseType,

            string? displayName,

            ImmutableArray<Outputs.GetDataSafeTargetDatabasesFilterResult> filters,

            string id,

            string? infrastructureType,

            string? state,

            string? targetDatabaseId,

            ImmutableArray<Outputs.GetDataSafeTargetDatabasesTargetDatabaseResult> targetDatabases)
        {
            AccessLevel = accessLevel;
            CompartmentId = compartmentId;
            CompartmentIdInSubtree = compartmentIdInSubtree;
            DatabaseType = databaseType;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            InfrastructureType = infrastructureType;
            State = state;
            TargetDatabaseId = targetDatabaseId;
            TargetDatabases = targetDatabases;
        }
    }
}