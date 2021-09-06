// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GoldenGate
{
    public static class GetDeploymentBackups
    {
        /// <summary>
        /// This data source provides the list of Deployment Backups in Oracle Cloud Infrastructure Golden Gate service.
        /// 
        /// Lists the Backups in a compartment.
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
        ///         var testDeploymentBackups = Output.Create(Oci.GoldenGate.GetDeploymentBackups.InvokeAsync(new Oci.GoldenGate.GetDeploymentBackupsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             DeploymentId = oci_golden_gate_deployment.Test_deployment.Id,
        ///             DisplayName = @var.Deployment_backup_display_name,
        ///             State = @var.Deployment_backup_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDeploymentBackupsResult> InvokeAsync(GetDeploymentBackupsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDeploymentBackupsResult>("oci:goldengate/getDeploymentBackups:getDeploymentBackups", args ?? new GetDeploymentBackupsArgs(), options.WithVersion());
    }


    public sealed class GetDeploymentBackupsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// The ID of the deployment in which to list resources.
        /// </summary>
        [Input("deploymentId")]
        public string? DeploymentId { get; set; }

        /// <summary>
        /// A filter to return only the resources that match the entire 'displayName' given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetDeploymentBackupsFilterArgs>? _filters;
        public List<Inputs.GetDeploymentBackupsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDeploymentBackupsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only the resources that match the 'lifecycleState' given.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetDeploymentBackupsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetDeploymentBackupsResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The list of deployment_backup_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentBackupsDeploymentBackupCollectionResult> DeploymentBackupCollections;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment being referenced.
        /// </summary>
        public readonly string? DeploymentId;
        /// <summary>
        /// An object's Display Name.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetDeploymentBackupsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Possible lifecycle states.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetDeploymentBackupsResult(
            string compartmentId,

            ImmutableArray<Outputs.GetDeploymentBackupsDeploymentBackupCollectionResult> deploymentBackupCollections,

            string? deploymentId,

            string? displayName,

            ImmutableArray<Outputs.GetDeploymentBackupsFilterResult> filters,

            string id,

            string? state)
        {
            CompartmentId = compartmentId;
            DeploymentBackupCollections = deploymentBackupCollections;
            DeploymentId = deploymentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
        }
    }
}
