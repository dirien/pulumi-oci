// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci
{
    public static class GetDatabaseAutonomousExadataInfrastructureOcpu
    {
        /// <summary>
        /// This data source provides details about a specific Autonomous Exadata Infrastructure Ocpu resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets details of the available and consumed OCPUs for the specified Autonomous Exadata Infrastructure resource.
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
        ///         var testAutonomousExadataInfrastructureOcpu = Output.Create(Oci.GetDatabaseAutonomousExadataInfrastructureOcpu.InvokeAsync(new Oci.GetDatabaseAutonomousExadataInfrastructureOcpuArgs
        ///         {
        ///             AutonomousExadataInfrastructureId = oci_database_autonomous_exadata_infrastructure.Test_autonomous_exadata_infrastructure.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDatabaseAutonomousExadataInfrastructureOcpuResult> InvokeAsync(GetDatabaseAutonomousExadataInfrastructureOcpuArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDatabaseAutonomousExadataInfrastructureOcpuResult>("oci:index/getDatabaseAutonomousExadataInfrastructureOcpu:GetDatabaseAutonomousExadataInfrastructureOcpu", args ?? new GetDatabaseAutonomousExadataInfrastructureOcpuArgs(), options.WithVersion());
    }


    public sealed class GetDatabaseAutonomousExadataInfrastructureOcpuArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The Autonomous Exadata Infrastructure  [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("autonomousExadataInfrastructureId", required: true)]
        public string AutonomousExadataInfrastructureId { get; set; } = null!;

        public GetDatabaseAutonomousExadataInfrastructureOcpuArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetDatabaseAutonomousExadataInfrastructureOcpuResult
    {
        public readonly string AutonomousExadataInfrastructureId;
        /// <summary>
        /// The number of consumed OCPUs, by database workload type.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDatabaseAutonomousExadataInfrastructureOcpuByWorkloadTypeResult> ByWorkloadTypes;
        /// <summary>
        /// The total number of consumed OCPUs in the Autonomous Exadata Infrastructure instance.
        /// </summary>
        public readonly double ConsumedCpu;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The total number of OCPUs in the Autonomous Exadata Infrastructure instance.
        /// </summary>
        public readonly double TotalCpu;

        [OutputConstructor]
        private GetDatabaseAutonomousExadataInfrastructureOcpuResult(
            string autonomousExadataInfrastructureId,

            ImmutableArray<Outputs.GetDatabaseAutonomousExadataInfrastructureOcpuByWorkloadTypeResult> byWorkloadTypes,

            double consumedCpu,

            string id,

            double totalCpu)
        {
            AutonomousExadataInfrastructureId = autonomousExadataInfrastructureId;
            ByWorkloadTypes = byWorkloadTypes;
            ConsumedCpu = consumedCpu;
            Id = id;
            TotalCpu = totalCpu;
        }
    }
}