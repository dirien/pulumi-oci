// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class DbHomeDatabaseConnectionStringArgs : Pulumi.ResourceArgs
    {
        [Input("allConnectionStrings")]
        private InputMap<object>? _allConnectionStrings;
        public InputMap<object> AllConnectionStrings
        {
            get => _allConnectionStrings ?? (_allConnectionStrings = new InputMap<object>());
            set => _allConnectionStrings = value;
        }

        [Input("cdbDefault")]
        public Input<string>? CdbDefault { get; set; }

        [Input("cdbIpDefault")]
        public Input<string>? CdbIpDefault { get; set; }

        public DbHomeDatabaseConnectionStringArgs()
        {
        }
    }
}
