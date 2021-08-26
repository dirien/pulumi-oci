// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetVmClusterUpdate
    {
        /// <summary>
        /// This data source provides details about a specific Vm Cluster Update resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets information about a specified maintenance update package for a VM cluster. Applies to Exadata Cloud@Customer instances only.
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
        ///         var testVmClusterUpdate = Output.Create(Oci.Database.GetVmClusterUpdate.InvokeAsync(new Oci.Database.GetVmClusterUpdateArgs
        ///         {
        ///             UpdateId = oci_database_update.Test_update.Id,
        ///             VmClusterId = oci_database_vm_cluster.Test_vm_cluster.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetVmClusterUpdateResult> InvokeAsync(GetVmClusterUpdateArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetVmClusterUpdateResult>("oci:database/getVmClusterUpdate:getVmClusterUpdate", args ?? new GetVmClusterUpdateArgs(), options.WithVersion());
    }


    public sealed class GetVmClusterUpdateArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the maintenance update.
        /// </summary>
        [Input("updateId", required: true)]
        public string UpdateId { get; set; } = null!;

        /// <summary>
        /// The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("vmClusterId", required: true)]
        public string VmClusterId { get; set; } = null!;

        public GetVmClusterUpdateArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetVmClusterUpdateResult
    {
        /// <summary>
        /// The possible actions that can be performed using this maintenance update.
        /// </summary>
        public readonly ImmutableArray<string> AvailableActions;
        /// <summary>
        /// Details of the maintenance update package.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The update action performed most recently using this maintenance update.
        /// </summary>
        public readonly string LastAction;
        /// <summary>
        /// Descriptive text providing additional details about the lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The current state of the maintenance update. Dependent on value of `lastAction`.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the maintenance update was released.
        /// </summary>
        public readonly string TimeReleased;
        public readonly string UpdateId;
        /// <summary>
        /// The type of VM cluster maintenance update.
        /// </summary>
        public readonly string UpdateType;
        /// <summary>
        /// The version of the maintenance update package.
        /// </summary>
        public readonly string Version;
        public readonly string VmClusterId;

        [OutputConstructor]
        private GetVmClusterUpdateResult(
            ImmutableArray<string> availableActions,

            string description,

            string id,

            string lastAction,

            string lifecycleDetails,

            string state,

            string timeReleased,

            string updateId,

            string updateType,

            string version,

            string vmClusterId)
        {
            AvailableActions = availableActions;
            Description = description;
            Id = id;
            LastAction = lastAction;
            LifecycleDetails = lifecycleDetails;
            State = state;
            TimeReleased = timeReleased;
            UpdateId = updateId;
            UpdateType = updateType;
            Version = version;
            VmClusterId = vmClusterId;
        }
    }
}
