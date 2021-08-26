// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetAutonomousExadataInfrastructureOcpu
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
        ///         var testAutonomousExadataInfrastructureOcpu = Output.Create(Oci.Database.GetAutonomousExadataInfrastructureOcpu.InvokeAsync(new Oci.Database.GetAutonomousExadataInfrastructureOcpuArgs
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
        public static Task<GetAutonomousExadataInfrastructureOcpuResult> InvokeAsync(GetAutonomousExadataInfrastructureOcpuArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetAutonomousExadataInfrastructureOcpuResult>("oci:database/getAutonomousExadataInfrastructureOcpu:getAutonomousExadataInfrastructureOcpu", args ?? new GetAutonomousExadataInfrastructureOcpuArgs(), options.WithVersion());
    }


    public sealed class GetAutonomousExadataInfrastructureOcpuArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The Autonomous Exadata Infrastructure  [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("autonomousExadataInfrastructureId", required: true)]
        public string AutonomousExadataInfrastructureId { get; set; } = null!;

        public GetAutonomousExadataInfrastructureOcpuArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetAutonomousExadataInfrastructureOcpuResult
    {
        public readonly string AutonomousExadataInfrastructureId;
        /// <summary>
        /// The number of consumed OCPUs, by database workload type.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAutonomousExadataInfrastructureOcpuByWorkloadTypeResult> ByWorkloadTypes;
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
        private GetAutonomousExadataInfrastructureOcpuResult(
            string autonomousExadataInfrastructureId,

            ImmutableArray<Outputs.GetAutonomousExadataInfrastructureOcpuByWorkloadTypeResult> byWorkloadTypes,

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
