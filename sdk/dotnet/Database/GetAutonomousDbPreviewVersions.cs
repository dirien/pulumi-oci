// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetAutonomousDbPreviewVersions
    {
        /// <summary>
        /// This data source provides the list of Autonomous Db Preview Versions in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets a list of supported Autonomous Database versions. Note that preview version software is only available for
        /// databases with [shared Exadata infrastructure](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/adboverview.htm#AEI).
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
        ///         var testAutonomousDbPreviewVersions = Output.Create(Oci.Database.GetAutonomousDbPreviewVersions.InvokeAsync(new Oci.Database.GetAutonomousDbPreviewVersionsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetAutonomousDbPreviewVersionsResult> InvokeAsync(GetAutonomousDbPreviewVersionsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetAutonomousDbPreviewVersionsResult>("oci:database/getAutonomousDbPreviewVersions:getAutonomousDbPreviewVersions", args ?? new GetAutonomousDbPreviewVersionsArgs(), options.WithVersion());
    }


    public sealed class GetAutonomousDbPreviewVersionsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetAutonomousDbPreviewVersionsFilterArgs>? _filters;
        public List<Inputs.GetAutonomousDbPreviewVersionsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetAutonomousDbPreviewVersionsFilterArgs>());
            set => _filters = value;
        }

        public GetAutonomousDbPreviewVersionsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetAutonomousDbPreviewVersionsResult
    {
        /// <summary>
        /// The list of autonomous_db_preview_versions.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAutonomousDbPreviewVersionsAutonomousDbPreviewVersionResult> AutonomousDbPreviewVersions;
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetAutonomousDbPreviewVersionsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetAutonomousDbPreviewVersionsResult(
            ImmutableArray<Outputs.GetAutonomousDbPreviewVersionsAutonomousDbPreviewVersionResult> autonomousDbPreviewVersions,

            string compartmentId,

            ImmutableArray<Outputs.GetAutonomousDbPreviewVersionsFilterResult> filters,

            string id)
        {
            AutonomousDbPreviewVersions = autonomousDbPreviewVersions;
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
        }
    }
}
