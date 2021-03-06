// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer.Inputs
{

    public sealed class BackendSetLbCookieSessionPersistenceConfigurationArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The name of the cookie used to detect a session initiated by the backend server. Use '*' to specify that any cookie set by the backend causes the session to persist.  Example: `example_cookie`
        /// </summary>
        [Input("cookieName")]
        public Input<string>? CookieName { get; set; }

        /// <summary>
        /// (Updatable) Whether the load balancer is prevented from directing traffic from a persistent session client to a different backend server if the original server is unavailable. Defaults to false.  Example: `false`
        /// </summary>
        [Input("disableFallback")]
        public Input<bool>? DisableFallback { get; set; }

        /// <summary>
        /// (Updatable) The domain in which the cookie is valid. The `Set-cookie` header inserted by the load balancer contains a domain attribute with the specified value.
        /// </summary>
        [Input("domain")]
        public Input<string>? Domain { get; set; }

        /// <summary>
        /// (Updatable) Whether the `Set-cookie` header should contain the `HttpOnly` attribute. If `true`, the `Set-cookie` header inserted by the load balancer contains the `HttpOnly` attribute, which limits the scope of the cookie to HTTP requests. This attribute directs the client or browser to omit the cookie when providing access to cookies through non-HTTP APIs. For example, it restricts the cookie from JavaScript channels.  Example: `true`
        /// </summary>
        [Input("isHttpOnly")]
        public Input<bool>? IsHttpOnly { get; set; }

        /// <summary>
        /// (Updatable) Whether the `Set-cookie` header should contain the `Secure` attribute. If `true`, the `Set-cookie` header inserted by the load balancer contains the `Secure` attribute, which directs the client or browser to send the cookie only using a secure protocol.
        /// </summary>
        [Input("isSecure")]
        public Input<bool>? IsSecure { get; set; }

        /// <summary>
        /// (Updatable) The amount of time the cookie remains valid. The `Set-cookie` header inserted by the load balancer contains a `Max-Age` attribute with the specified value.
        /// </summary>
        [Input("maxAgeInSeconds")]
        public Input<int>? MaxAgeInSeconds { get; set; }

        /// <summary>
        /// (Updatable) The path in which the cookie is valid. The `Set-cookie header` inserted by the load balancer contains a `Path` attribute with the specified value.
        /// </summary>
        [Input("path")]
        public Input<string>? Path { get; set; }

        public BackendSetLbCookieSessionPersistenceConfigurationArgs()
        {
        }
    }
}
