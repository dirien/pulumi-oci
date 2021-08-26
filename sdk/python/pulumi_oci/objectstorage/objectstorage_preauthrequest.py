# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = ['ObjectstoragePreauthrequestArgs', 'ObjectstoragePreauthrequest']

@pulumi.input_type
class ObjectstoragePreauthrequestArgs:
    def __init__(__self__, *,
                 access_type: pulumi.Input[str],
                 bucket: pulumi.Input[str],
                 namespace: pulumi.Input[str],
                 time_expires: pulumi.Input[str],
                 bucket_listing_action: Optional[pulumi.Input[str]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 object: Optional[pulumi.Input[str]] = None,
                 object_name: Optional[pulumi.Input[str]] = None):
        """
        The set of arguments for constructing a ObjectstoragePreauthrequest resource.
        :param pulumi.Input[str] access_type: The operation that can be performed on this resource. Allowed Values: `ObjectRead`, `ObjectWrite`, `ObjectReadWrite`, `AnyObjectReadWrite` or `AnyObjectRead`
        :param pulumi.Input[str] bucket: The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        :param pulumi.Input[str] namespace: The Object Storage namespace used for the request.
        :param pulumi.Input[str] time_expires: The expiration date for the pre-authenticated request as per [RFC 3339](https://tools.ietf.org/html/rfc3339). After this date the pre-authenticated request will no longer be valid.
        :param pulumi.Input[str] bucket_listing_action: Specifies whether a list operation is allowed on a PAR with accessType "AnyObjectRead" or "AnyObjectReadWrite". Deny: Prevents the user from performing a list operation. ListObjects: Authorizes the user to perform a list operation.
        :param pulumi.Input[str] name: A user-specified name for the pre-authenticated request. Names can be helpful in managing pre-authenticated requests. Avoid entering confidential information.
        :param pulumi.Input[str] object: Deprecated. Instead use `object_name`. Requests that include both `object` and `object_name` will be rejected. (Optional) The name of the object that is being granted access to by the pre-authenticated request. Avoid entering confidential information. The object name can be null and if so, the pre-authenticated request grants access to the entire bucket if the access type allows that. The object name can be a prefix as well, in that case pre-authenticated request grants access to all the objects within the bucket starting with that prefix provided that we have the correct access type.
        :param pulumi.Input[str] object_name: The name of the object that is being granted access to by the pre-authenticated request. Avoid entering confidential information. The object name can be null and if so, the pre-authenticated request grants access to the entire bucket if the access type allows that. The object name can be a prefix as well, in that case pre-authenticated request grants access to all the objects within the bucket starting with that prefix provided that we have the correct access type.
        """
        pulumi.set(__self__, "access_type", access_type)
        pulumi.set(__self__, "bucket", bucket)
        pulumi.set(__self__, "namespace", namespace)
        pulumi.set(__self__, "time_expires", time_expires)
        if bucket_listing_action is not None:
            pulumi.set(__self__, "bucket_listing_action", bucket_listing_action)
        if name is not None:
            pulumi.set(__self__, "name", name)
        if object is not None:
            warnings.warn("""The 'object' field has been deprecated. Please use 'object_name' instead.""", DeprecationWarning)
            pulumi.log.warn("""object is deprecated: The 'object' field has been deprecated. Please use 'object_name' instead.""")
        if object is not None:
            pulumi.set(__self__, "object", object)
        if object_name is not None:
            pulumi.set(__self__, "object_name", object_name)

    @property
    @pulumi.getter(name="accessType")
    def access_type(self) -> pulumi.Input[str]:
        """
        The operation that can be performed on this resource. Allowed Values: `ObjectRead`, `ObjectWrite`, `ObjectReadWrite`, `AnyObjectReadWrite` or `AnyObjectRead`
        """
        return pulumi.get(self, "access_type")

    @access_type.setter
    def access_type(self, value: pulumi.Input[str]):
        pulumi.set(self, "access_type", value)

    @property
    @pulumi.getter
    def bucket(self) -> pulumi.Input[str]:
        """
        The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        """
        return pulumi.get(self, "bucket")

    @bucket.setter
    def bucket(self, value: pulumi.Input[str]):
        pulumi.set(self, "bucket", value)

    @property
    @pulumi.getter
    def namespace(self) -> pulumi.Input[str]:
        """
        The Object Storage namespace used for the request.
        """
        return pulumi.get(self, "namespace")

    @namespace.setter
    def namespace(self, value: pulumi.Input[str]):
        pulumi.set(self, "namespace", value)

    @property
    @pulumi.getter(name="timeExpires")
    def time_expires(self) -> pulumi.Input[str]:
        """
        The expiration date for the pre-authenticated request as per [RFC 3339](https://tools.ietf.org/html/rfc3339). After this date the pre-authenticated request will no longer be valid.
        """
        return pulumi.get(self, "time_expires")

    @time_expires.setter
    def time_expires(self, value: pulumi.Input[str]):
        pulumi.set(self, "time_expires", value)

    @property
    @pulumi.getter(name="bucketListingAction")
    def bucket_listing_action(self) -> Optional[pulumi.Input[str]]:
        """
        Specifies whether a list operation is allowed on a PAR with accessType "AnyObjectRead" or "AnyObjectReadWrite". Deny: Prevents the user from performing a list operation. ListObjects: Authorizes the user to perform a list operation.
        """
        return pulumi.get(self, "bucket_listing_action")

    @bucket_listing_action.setter
    def bucket_listing_action(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "bucket_listing_action", value)

    @property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[str]]:
        """
        A user-specified name for the pre-authenticated request. Names can be helpful in managing pre-authenticated requests. Avoid entering confidential information.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def object(self) -> Optional[pulumi.Input[str]]:
        """
        Deprecated. Instead use `object_name`. Requests that include both `object` and `object_name` will be rejected. (Optional) The name of the object that is being granted access to by the pre-authenticated request. Avoid entering confidential information. The object name can be null and if so, the pre-authenticated request grants access to the entire bucket if the access type allows that. The object name can be a prefix as well, in that case pre-authenticated request grants access to all the objects within the bucket starting with that prefix provided that we have the correct access type.
        """
        return pulumi.get(self, "object")

    @object.setter
    def object(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "object", value)

    @property
    @pulumi.getter(name="objectName")
    def object_name(self) -> Optional[pulumi.Input[str]]:
        """
        The name of the object that is being granted access to by the pre-authenticated request. Avoid entering confidential information. The object name can be null and if so, the pre-authenticated request grants access to the entire bucket if the access type allows that. The object name can be a prefix as well, in that case pre-authenticated request grants access to all the objects within the bucket starting with that prefix provided that we have the correct access type.
        """
        return pulumi.get(self, "object_name")

    @object_name.setter
    def object_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "object_name", value)


@pulumi.input_type
class _ObjectstoragePreauthrequestState:
    def __init__(__self__, *,
                 access_type: Optional[pulumi.Input[str]] = None,
                 access_uri: Optional[pulumi.Input[str]] = None,
                 bucket: Optional[pulumi.Input[str]] = None,
                 bucket_listing_action: Optional[pulumi.Input[str]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 namespace: Optional[pulumi.Input[str]] = None,
                 object: Optional[pulumi.Input[str]] = None,
                 object_name: Optional[pulumi.Input[str]] = None,
                 par_id: Optional[pulumi.Input[str]] = None,
                 time_created: Optional[pulumi.Input[str]] = None,
                 time_expires: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering ObjectstoragePreauthrequest resources.
        :param pulumi.Input[str] access_type: The operation that can be performed on this resource. Allowed Values: `ObjectRead`, `ObjectWrite`, `ObjectReadWrite`, `AnyObjectReadWrite` or `AnyObjectRead`
        :param pulumi.Input[str] access_uri: The URI to embed in the URL `https://objectstorage.${var.region}.oraclecloud.com{var.access_uri}` when using the pre-authenticated request.
        :param pulumi.Input[str] bucket: The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        :param pulumi.Input[str] bucket_listing_action: Specifies whether a list operation is allowed on a PAR with accessType "AnyObjectRead" or "AnyObjectReadWrite". Deny: Prevents the user from performing a list operation. ListObjects: Authorizes the user to perform a list operation.
        :param pulumi.Input[str] name: A user-specified name for the pre-authenticated request. Names can be helpful in managing pre-authenticated requests. Avoid entering confidential information.
        :param pulumi.Input[str] namespace: The Object Storage namespace used for the request.
        :param pulumi.Input[str] object: Deprecated. Instead use `object_name`. Requests that include both `object` and `object_name` will be rejected. (Optional) The name of the object that is being granted access to by the pre-authenticated request. Avoid entering confidential information. The object name can be null and if so, the pre-authenticated request grants access to the entire bucket if the access type allows that. The object name can be a prefix as well, in that case pre-authenticated request grants access to all the objects within the bucket starting with that prefix provided that we have the correct access type.
        :param pulumi.Input[str] object_name: The name of the object that is being granted access to by the pre-authenticated request. Avoid entering confidential information. The object name can be null and if so, the pre-authenticated request grants access to the entire bucket if the access type allows that. The object name can be a prefix as well, in that case pre-authenticated request grants access to all the objects within the bucket starting with that prefix provided that we have the correct access type.
        :param pulumi.Input[str] par_id: The unique identifier for the pre-authenticated request. This can be used to manage operations against the pre-authenticated request, such as GET or DELETE.
        :param pulumi.Input[str] time_created: The date when the pre-authenticated request was created as per specification [RFC 3339](https://tools.ietf.org/html/rfc3339).
        :param pulumi.Input[str] time_expires: The expiration date for the pre-authenticated request as per [RFC 3339](https://tools.ietf.org/html/rfc3339). After this date the pre-authenticated request will no longer be valid.
        """
        if access_type is not None:
            pulumi.set(__self__, "access_type", access_type)
        if access_uri is not None:
            pulumi.set(__self__, "access_uri", access_uri)
        if bucket is not None:
            pulumi.set(__self__, "bucket", bucket)
        if bucket_listing_action is not None:
            pulumi.set(__self__, "bucket_listing_action", bucket_listing_action)
        if name is not None:
            pulumi.set(__self__, "name", name)
        if namespace is not None:
            pulumi.set(__self__, "namespace", namespace)
        if object is not None:
            warnings.warn("""The 'object' field has been deprecated. Please use 'object_name' instead.""", DeprecationWarning)
            pulumi.log.warn("""object is deprecated: The 'object' field has been deprecated. Please use 'object_name' instead.""")
        if object is not None:
            pulumi.set(__self__, "object", object)
        if object_name is not None:
            pulumi.set(__self__, "object_name", object_name)
        if par_id is not None:
            pulumi.set(__self__, "par_id", par_id)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if time_expires is not None:
            pulumi.set(__self__, "time_expires", time_expires)

    @property
    @pulumi.getter(name="accessType")
    def access_type(self) -> Optional[pulumi.Input[str]]:
        """
        The operation that can be performed on this resource. Allowed Values: `ObjectRead`, `ObjectWrite`, `ObjectReadWrite`, `AnyObjectReadWrite` or `AnyObjectRead`
        """
        return pulumi.get(self, "access_type")

    @access_type.setter
    def access_type(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "access_type", value)

    @property
    @pulumi.getter(name="accessUri")
    def access_uri(self) -> Optional[pulumi.Input[str]]:
        """
        The URI to embed in the URL `https://objectstorage.${var.region}.oraclecloud.com{var.access_uri}` when using the pre-authenticated request.
        """
        return pulumi.get(self, "access_uri")

    @access_uri.setter
    def access_uri(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "access_uri", value)

    @property
    @pulumi.getter
    def bucket(self) -> Optional[pulumi.Input[str]]:
        """
        The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        """
        return pulumi.get(self, "bucket")

    @bucket.setter
    def bucket(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "bucket", value)

    @property
    @pulumi.getter(name="bucketListingAction")
    def bucket_listing_action(self) -> Optional[pulumi.Input[str]]:
        """
        Specifies whether a list operation is allowed on a PAR with accessType "AnyObjectRead" or "AnyObjectReadWrite". Deny: Prevents the user from performing a list operation. ListObjects: Authorizes the user to perform a list operation.
        """
        return pulumi.get(self, "bucket_listing_action")

    @bucket_listing_action.setter
    def bucket_listing_action(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "bucket_listing_action", value)

    @property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[str]]:
        """
        A user-specified name for the pre-authenticated request. Names can be helpful in managing pre-authenticated requests. Avoid entering confidential information.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def namespace(self) -> Optional[pulumi.Input[str]]:
        """
        The Object Storage namespace used for the request.
        """
        return pulumi.get(self, "namespace")

    @namespace.setter
    def namespace(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "namespace", value)

    @property
    @pulumi.getter
    def object(self) -> Optional[pulumi.Input[str]]:
        """
        Deprecated. Instead use `object_name`. Requests that include both `object` and `object_name` will be rejected. (Optional) The name of the object that is being granted access to by the pre-authenticated request. Avoid entering confidential information. The object name can be null and if so, the pre-authenticated request grants access to the entire bucket if the access type allows that. The object name can be a prefix as well, in that case pre-authenticated request grants access to all the objects within the bucket starting with that prefix provided that we have the correct access type.
        """
        return pulumi.get(self, "object")

    @object.setter
    def object(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "object", value)

    @property
    @pulumi.getter(name="objectName")
    def object_name(self) -> Optional[pulumi.Input[str]]:
        """
        The name of the object that is being granted access to by the pre-authenticated request. Avoid entering confidential information. The object name can be null and if so, the pre-authenticated request grants access to the entire bucket if the access type allows that. The object name can be a prefix as well, in that case pre-authenticated request grants access to all the objects within the bucket starting with that prefix provided that we have the correct access type.
        """
        return pulumi.get(self, "object_name")

    @object_name.setter
    def object_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "object_name", value)

    @property
    @pulumi.getter(name="parId")
    def par_id(self) -> Optional[pulumi.Input[str]]:
        """
        The unique identifier for the pre-authenticated request. This can be used to manage operations against the pre-authenticated request, such as GET or DELETE.
        """
        return pulumi.get(self, "par_id")

    @par_id.setter
    def par_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "par_id", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        The date when the pre-authenticated request was created as per specification [RFC 3339](https://tools.ietf.org/html/rfc3339).
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)

    @property
    @pulumi.getter(name="timeExpires")
    def time_expires(self) -> Optional[pulumi.Input[str]]:
        """
        The expiration date for the pre-authenticated request as per [RFC 3339](https://tools.ietf.org/html/rfc3339). After this date the pre-authenticated request will no longer be valid.
        """
        return pulumi.get(self, "time_expires")

    @time_expires.setter
    def time_expires(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_expires", value)


class ObjectstoragePreauthrequest(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 access_type: Optional[pulumi.Input[str]] = None,
                 bucket: Optional[pulumi.Input[str]] = None,
                 bucket_listing_action: Optional[pulumi.Input[str]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 namespace: Optional[pulumi.Input[str]] = None,
                 object: Optional[pulumi.Input[str]] = None,
                 object_name: Optional[pulumi.Input[str]] = None,
                 time_expires: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Preauthenticated Request resource in Oracle Cloud Infrastructure Object Storage service.

        Creates a pre-authenticated request specific to the bucket.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_preauthenticated_request = oci.objectstorage.ObjectstoragePreauthrequest("testPreauthenticatedRequest",
            access_type=var["preauthenticated_request_access_type"],
            bucket=var["preauthenticated_request_bucket"],
            namespace=var["preauthenticated_request_namespace"],
            time_expires=var["preauthenticated_request_time_expires"],
            bucket_listing_action=var["preauthenticated_request_bucket_listing_action"],
            object=var["preauthenticated_request_object"])
        ```

        ## Import

        PreauthenticatedRequests can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:objectstorage/objectstoragePreauthrequest:ObjectstoragePreauthrequest test_preauthenticated_request "n/{namespaceName}/b/{bucketName}/p/{parId}"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] access_type: The operation that can be performed on this resource. Allowed Values: `ObjectRead`, `ObjectWrite`, `ObjectReadWrite`, `AnyObjectReadWrite` or `AnyObjectRead`
        :param pulumi.Input[str] bucket: The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        :param pulumi.Input[str] bucket_listing_action: Specifies whether a list operation is allowed on a PAR with accessType "AnyObjectRead" or "AnyObjectReadWrite". Deny: Prevents the user from performing a list operation. ListObjects: Authorizes the user to perform a list operation.
        :param pulumi.Input[str] name: A user-specified name for the pre-authenticated request. Names can be helpful in managing pre-authenticated requests. Avoid entering confidential information.
        :param pulumi.Input[str] namespace: The Object Storage namespace used for the request.
        :param pulumi.Input[str] object: Deprecated. Instead use `object_name`. Requests that include both `object` and `object_name` will be rejected. (Optional) The name of the object that is being granted access to by the pre-authenticated request. Avoid entering confidential information. The object name can be null and if so, the pre-authenticated request grants access to the entire bucket if the access type allows that. The object name can be a prefix as well, in that case pre-authenticated request grants access to all the objects within the bucket starting with that prefix provided that we have the correct access type.
        :param pulumi.Input[str] object_name: The name of the object that is being granted access to by the pre-authenticated request. Avoid entering confidential information. The object name can be null and if so, the pre-authenticated request grants access to the entire bucket if the access type allows that. The object name can be a prefix as well, in that case pre-authenticated request grants access to all the objects within the bucket starting with that prefix provided that we have the correct access type.
        :param pulumi.Input[str] time_expires: The expiration date for the pre-authenticated request as per [RFC 3339](https://tools.ietf.org/html/rfc3339). After this date the pre-authenticated request will no longer be valid.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: ObjectstoragePreauthrequestArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Preauthenticated Request resource in Oracle Cloud Infrastructure Object Storage service.

        Creates a pre-authenticated request specific to the bucket.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_preauthenticated_request = oci.objectstorage.ObjectstoragePreauthrequest("testPreauthenticatedRequest",
            access_type=var["preauthenticated_request_access_type"],
            bucket=var["preauthenticated_request_bucket"],
            namespace=var["preauthenticated_request_namespace"],
            time_expires=var["preauthenticated_request_time_expires"],
            bucket_listing_action=var["preauthenticated_request_bucket_listing_action"],
            object=var["preauthenticated_request_object"])
        ```

        ## Import

        PreauthenticatedRequests can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:objectstorage/objectstoragePreauthrequest:ObjectstoragePreauthrequest test_preauthenticated_request "n/{namespaceName}/b/{bucketName}/p/{parId}"
        ```

        :param str resource_name: The name of the resource.
        :param ObjectstoragePreauthrequestArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(ObjectstoragePreauthrequestArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 access_type: Optional[pulumi.Input[str]] = None,
                 bucket: Optional[pulumi.Input[str]] = None,
                 bucket_listing_action: Optional[pulumi.Input[str]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 namespace: Optional[pulumi.Input[str]] = None,
                 object: Optional[pulumi.Input[str]] = None,
                 object_name: Optional[pulumi.Input[str]] = None,
                 time_expires: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        if opts is None:
            opts = pulumi.ResourceOptions()
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.version is None:
            opts.version = _utilities.get_version()
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = ObjectstoragePreauthrequestArgs.__new__(ObjectstoragePreauthrequestArgs)

            if access_type is None and not opts.urn:
                raise TypeError("Missing required property 'access_type'")
            __props__.__dict__["access_type"] = access_type
            if bucket is None and not opts.urn:
                raise TypeError("Missing required property 'bucket'")
            __props__.__dict__["bucket"] = bucket
            __props__.__dict__["bucket_listing_action"] = bucket_listing_action
            __props__.__dict__["name"] = name
            if namespace is None and not opts.urn:
                raise TypeError("Missing required property 'namespace'")
            __props__.__dict__["namespace"] = namespace
            if object is not None and not opts.urn:
                warnings.warn("""The 'object' field has been deprecated. Please use 'object_name' instead.""", DeprecationWarning)
                pulumi.log.warn("""object is deprecated: The 'object' field has been deprecated. Please use 'object_name' instead.""")
            __props__.__dict__["object"] = object
            __props__.__dict__["object_name"] = object_name
            if time_expires is None and not opts.urn:
                raise TypeError("Missing required property 'time_expires'")
            __props__.__dict__["time_expires"] = time_expires
            __props__.__dict__["access_uri"] = None
            __props__.__dict__["par_id"] = None
            __props__.__dict__["time_created"] = None
        super(ObjectstoragePreauthrequest, __self__).__init__(
            'oci:objectstorage/objectstoragePreauthrequest:ObjectstoragePreauthrequest',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            access_type: Optional[pulumi.Input[str]] = None,
            access_uri: Optional[pulumi.Input[str]] = None,
            bucket: Optional[pulumi.Input[str]] = None,
            bucket_listing_action: Optional[pulumi.Input[str]] = None,
            name: Optional[pulumi.Input[str]] = None,
            namespace: Optional[pulumi.Input[str]] = None,
            object: Optional[pulumi.Input[str]] = None,
            object_name: Optional[pulumi.Input[str]] = None,
            par_id: Optional[pulumi.Input[str]] = None,
            time_created: Optional[pulumi.Input[str]] = None,
            time_expires: Optional[pulumi.Input[str]] = None) -> 'ObjectstoragePreauthrequest':
        """
        Get an existing ObjectstoragePreauthrequest resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] access_type: The operation that can be performed on this resource. Allowed Values: `ObjectRead`, `ObjectWrite`, `ObjectReadWrite`, `AnyObjectReadWrite` or `AnyObjectRead`
        :param pulumi.Input[str] access_uri: The URI to embed in the URL `https://objectstorage.${var.region}.oraclecloud.com{var.access_uri}` when using the pre-authenticated request.
        :param pulumi.Input[str] bucket: The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        :param pulumi.Input[str] bucket_listing_action: Specifies whether a list operation is allowed on a PAR with accessType "AnyObjectRead" or "AnyObjectReadWrite". Deny: Prevents the user from performing a list operation. ListObjects: Authorizes the user to perform a list operation.
        :param pulumi.Input[str] name: A user-specified name for the pre-authenticated request. Names can be helpful in managing pre-authenticated requests. Avoid entering confidential information.
        :param pulumi.Input[str] namespace: The Object Storage namespace used for the request.
        :param pulumi.Input[str] object: Deprecated. Instead use `object_name`. Requests that include both `object` and `object_name` will be rejected. (Optional) The name of the object that is being granted access to by the pre-authenticated request. Avoid entering confidential information. The object name can be null and if so, the pre-authenticated request grants access to the entire bucket if the access type allows that. The object name can be a prefix as well, in that case pre-authenticated request grants access to all the objects within the bucket starting with that prefix provided that we have the correct access type.
        :param pulumi.Input[str] object_name: The name of the object that is being granted access to by the pre-authenticated request. Avoid entering confidential information. The object name can be null and if so, the pre-authenticated request grants access to the entire bucket if the access type allows that. The object name can be a prefix as well, in that case pre-authenticated request grants access to all the objects within the bucket starting with that prefix provided that we have the correct access type.
        :param pulumi.Input[str] par_id: The unique identifier for the pre-authenticated request. This can be used to manage operations against the pre-authenticated request, such as GET or DELETE.
        :param pulumi.Input[str] time_created: The date when the pre-authenticated request was created as per specification [RFC 3339](https://tools.ietf.org/html/rfc3339).
        :param pulumi.Input[str] time_expires: The expiration date for the pre-authenticated request as per [RFC 3339](https://tools.ietf.org/html/rfc3339). After this date the pre-authenticated request will no longer be valid.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _ObjectstoragePreauthrequestState.__new__(_ObjectstoragePreauthrequestState)

        __props__.__dict__["access_type"] = access_type
        __props__.__dict__["access_uri"] = access_uri
        __props__.__dict__["bucket"] = bucket
        __props__.__dict__["bucket_listing_action"] = bucket_listing_action
        __props__.__dict__["name"] = name
        __props__.__dict__["namespace"] = namespace
        __props__.__dict__["object"] = object
        __props__.__dict__["object_name"] = object_name
        __props__.__dict__["par_id"] = par_id
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["time_expires"] = time_expires
        return ObjectstoragePreauthrequest(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="accessType")
    def access_type(self) -> pulumi.Output[str]:
        """
        The operation that can be performed on this resource. Allowed Values: `ObjectRead`, `ObjectWrite`, `ObjectReadWrite`, `AnyObjectReadWrite` or `AnyObjectRead`
        """
        return pulumi.get(self, "access_type")

    @property
    @pulumi.getter(name="accessUri")
    def access_uri(self) -> pulumi.Output[str]:
        """
        The URI to embed in the URL `https://objectstorage.${var.region}.oraclecloud.com{var.access_uri}` when using the pre-authenticated request.
        """
        return pulumi.get(self, "access_uri")

    @property
    @pulumi.getter
    def bucket(self) -> pulumi.Output[str]:
        """
        The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        """
        return pulumi.get(self, "bucket")

    @property
    @pulumi.getter(name="bucketListingAction")
    def bucket_listing_action(self) -> pulumi.Output[str]:
        """
        Specifies whether a list operation is allowed on a PAR with accessType "AnyObjectRead" or "AnyObjectReadWrite". Deny: Prevents the user from performing a list operation. ListObjects: Authorizes the user to perform a list operation.
        """
        return pulumi.get(self, "bucket_listing_action")

    @property
    @pulumi.getter
    def name(self) -> pulumi.Output[str]:
        """
        A user-specified name for the pre-authenticated request. Names can be helpful in managing pre-authenticated requests. Avoid entering confidential information.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def namespace(self) -> pulumi.Output[str]:
        """
        The Object Storage namespace used for the request.
        """
        return pulumi.get(self, "namespace")

    @property
    @pulumi.getter
    def object(self) -> pulumi.Output[str]:
        """
        Deprecated. Instead use `object_name`. Requests that include both `object` and `object_name` will be rejected. (Optional) The name of the object that is being granted access to by the pre-authenticated request. Avoid entering confidential information. The object name can be null and if so, the pre-authenticated request grants access to the entire bucket if the access type allows that. The object name can be a prefix as well, in that case pre-authenticated request grants access to all the objects within the bucket starting with that prefix provided that we have the correct access type.
        """
        return pulumi.get(self, "object")

    @property
    @pulumi.getter(name="objectName")
    def object_name(self) -> pulumi.Output[str]:
        """
        The name of the object that is being granted access to by the pre-authenticated request. Avoid entering confidential information. The object name can be null and if so, the pre-authenticated request grants access to the entire bucket if the access type allows that. The object name can be a prefix as well, in that case pre-authenticated request grants access to all the objects within the bucket starting with that prefix provided that we have the correct access type.
        """
        return pulumi.get(self, "object_name")

    @property
    @pulumi.getter(name="parId")
    def par_id(self) -> pulumi.Output[str]:
        """
        The unique identifier for the pre-authenticated request. This can be used to manage operations against the pre-authenticated request, such as GET or DELETE.
        """
        return pulumi.get(self, "par_id")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        The date when the pre-authenticated request was created as per specification [RFC 3339](https://tools.ietf.org/html/rfc3339).
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeExpires")
    def time_expires(self) -> pulumi.Output[str]:
        """
        The expiration date for the pre-authenticated request as per [RFC 3339](https://tools.ietf.org/html/rfc3339). After this date the pre-authenticated request will no longer be valid.
        """
        return pulumi.get(self, "time_expires")
