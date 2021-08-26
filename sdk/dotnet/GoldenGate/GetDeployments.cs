// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GoldenGate
{
    public static class GetDeployments
    {
        /// <summary>
        /// This data source provides the list of Deployments in Oracle Cloud Infrastructure Golden Gate service.
        /// 
        /// Lists the Deployments in a compartment.
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
        ///         var testDeployments = Output.Create(Oci.GoldenGate.GetDeployments.InvokeAsync(new Oci.GoldenGate.GetDeploymentsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             DisplayName = @var.Deployment_display_name,
        ///             State = @var.Deployment_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDeploymentsResult> InvokeAsync(GetDeploymentsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDeploymentsResult>("oci:goldengate/getDeployments:getDeployments", args ?? new GetDeploymentsArgs(), options.WithVersion());
    }


    public sealed class GetDeploymentsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only the resources that match the entire 'displayName' given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetDeploymentsFilterArgs>? _filters;
        public List<Inputs.GetDeploymentsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDeploymentsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only the resources that match the 'lifecycleState' given.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetDeploymentsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetDeploymentsResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The list of deployment_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionResult> DeploymentCollections;
        /// <summary>
        /// An object's Display Name.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetDeploymentsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Possible lifecycle states.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetDeploymentsResult(
            string compartmentId,

            ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionResult> deploymentCollections,

            string? displayName,

            ImmutableArray<Outputs.GetDeploymentsFilterResult> filters,

            string id,

            string? state)
        {
            CompartmentId = compartmentId;
            DeploymentCollections = deploymentCollections;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
        }
    }
}
