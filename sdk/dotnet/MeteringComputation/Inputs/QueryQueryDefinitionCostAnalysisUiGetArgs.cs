// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.MeteringComputation.Inputs
{

    public sealed class QueryQueryDefinitionCostAnalysisUiGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The graph type.
        /// </summary>
        [Input("graph")]
        public Input<string>? Graph { get; set; }

        /// <summary>
        /// (Updatable) A cumulative graph.
        /// </summary>
        [Input("isCumulativeGraph")]
        public Input<bool>? IsCumulativeGraph { get; set; }

        public QueryQueryDefinitionCostAnalysisUiGetArgs()
        {
        }
    }
}
