// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Artifacts.Outputs
{

    [OutputType]
    public sealed class GetContainerImagesFilterResult
    {
        public readonly string Name;
        public readonly bool? Regex;
        public readonly ImmutableArray<string> Values;

        [OutputConstructor]
        private GetContainerImagesFilterResult(
            string name,

            bool? regex,

            ImmutableArray<string> values)
        {
            Name = name;
            Regex = regex;
            Values = values;
        }
    }
}
