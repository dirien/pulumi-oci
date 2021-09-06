// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Logging.Outputs
{

    [OutputType]
    public sealed class UnifiedAgentConfigurationServiceConfigurationSource
    {
        /// <summary>
        /// (Updatable)
        /// </summary>
        public readonly ImmutableArray<string> Channels;
        /// <summary>
        /// (Updatable) The name key to tag this grok pattern.
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// (Updatable) source parser object.
        /// </summary>
        public readonly Outputs.UnifiedAgentConfigurationServiceConfigurationSourceParser? Parser;
        /// <summary>
        /// (Updatable)
        /// </summary>
        public readonly ImmutableArray<string> Paths;
        /// <summary>
        /// (Updatable) Unified schema logging source type.
        /// </summary>
        public readonly string SourceType;

        [OutputConstructor]
        private UnifiedAgentConfigurationServiceConfigurationSource(
            ImmutableArray<string> channels,

            string? name,

            Outputs.UnifiedAgentConfigurationServiceConfigurationSourceParser? parser,

            ImmutableArray<string> paths,

            string sourceType)
        {
            Channels = channels;
            Name = name;
            Parser = parser;
            Paths = paths;
            SourceType = sourceType;
        }
    }
}
