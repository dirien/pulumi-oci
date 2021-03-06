// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetAutonomousContainerDatabases
    {
        /// <summary>
        /// This data source provides the list of Autonomous Container Databases in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets a list of the Autonomous Container Databases in the specified compartment.
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
        ///         var testAutonomousContainerDatabases = Output.Create(Oci.Database.GetAutonomousContainerDatabases.InvokeAsync(new Oci.Database.GetAutonomousContainerDatabasesArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             AutonomousExadataInfrastructureId = oci_database_autonomous_exadata_infrastructure.Test_autonomous_exadata_infrastructure.Id,
        ///             AutonomousVmClusterId = oci_database_autonomous_vm_cluster.Test_autonomous_vm_cluster.Id,
        ///             AvailabilityDomain = @var.Autonomous_container_database_availability_domain,
        ///             DisplayName = @var.Autonomous_container_database_display_name,
        ///             InfrastructureType = @var.Autonomous_container_database_infrastructure_type,
        ///             ServiceLevelAgreementType = @var.Autonomous_container_database_service_level_agreement_type,
        ///             State = @var.Autonomous_container_database_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetAutonomousContainerDatabasesResult> InvokeAsync(GetAutonomousContainerDatabasesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetAutonomousContainerDatabasesResult>("oci:database/getAutonomousContainerDatabases:getAutonomousContainerDatabases", args ?? new GetAutonomousContainerDatabasesArgs(), options.WithVersion());
    }


    public sealed class GetAutonomousContainerDatabasesArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The Autonomous Exadata Infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("autonomousExadataInfrastructureId")]
        public string? AutonomousExadataInfrastructureId { get; set; }

        /// <summary>
        /// The Autonomous VM Cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("autonomousVmClusterId")]
        public string? AutonomousVmClusterId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given availability domain exactly.
        /// </summary>
        [Input("availabilityDomain")]
        public string? AvailabilityDomain { get; set; }

        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given. The match is not case sensitive.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetAutonomousContainerDatabasesFilterArgs>? _filters;
        public List<Inputs.GetAutonomousContainerDatabasesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetAutonomousContainerDatabasesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given Infrastructure Type.
        /// </summary>
        [Input("infrastructureType")]
        public string? InfrastructureType { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given service level agreement type exactly.
        /// </summary>
        [Input("serviceLevelAgreementType")]
        public string? ServiceLevelAgreementType { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetAutonomousContainerDatabasesArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetAutonomousContainerDatabasesResult
    {
        /// <summary>
        /// The list of autonomous_container_databases.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAutonomousContainerDatabasesAutonomousContainerDatabaseResult> AutonomousContainerDatabases;
        /// <summary>
        /// The OCID of the Autonomous Exadata Infrastructure.
        /// </summary>
        public readonly string? AutonomousExadataInfrastructureId;
        /// <summary>
        /// The OCID of the Autonomous VM Cluster.
        /// </summary>
        public readonly string? AutonomousVmClusterId;
        /// <summary>
        /// The availability domain of the Autonomous Container Database.
        /// </summary>
        public readonly string? AvailabilityDomain;
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The user-provided name for the Autonomous Container Database.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetAutonomousContainerDatabasesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The infrastructure type this resource belongs to.
        /// </summary>
        public readonly string? InfrastructureType;
        /// <summary>
        /// The service level agreement type of the container database. The default is STANDARD.
        /// </summary>
        public readonly string? ServiceLevelAgreementType;
        /// <summary>
        /// The current state of the Autonomous Container Database.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetAutonomousContainerDatabasesResult(
            ImmutableArray<Outputs.GetAutonomousContainerDatabasesAutonomousContainerDatabaseResult> autonomousContainerDatabases,

            string? autonomousExadataInfrastructureId,

            string? autonomousVmClusterId,

            string? availabilityDomain,

            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetAutonomousContainerDatabasesFilterResult> filters,

            string id,

            string? infrastructureType,

            string? serviceLevelAgreementType,

            string? state)
        {
            AutonomousContainerDatabases = autonomousContainerDatabases;
            AutonomousExadataInfrastructureId = autonomousExadataInfrastructureId;
            AutonomousVmClusterId = autonomousVmClusterId;
            AvailabilityDomain = availabilityDomain;
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            InfrastructureType = infrastructureType;
            ServiceLevelAgreementType = serviceLevelAgreementType;
            State = state;
        }
    }
}
