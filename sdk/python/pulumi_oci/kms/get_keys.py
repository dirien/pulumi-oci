# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs
from ._inputs import *

__all__ = [
    'GetKeysResult',
    'AwaitableGetKeysResult',
    'get_keys',
]

@pulumi.output_type
class GetKeysResult:
    """
    A collection of values returned by getKeys.
    """
    def __init__(__self__, algorithm=None, compartment_id=None, curve_id=None, filters=None, id=None, keys=None, length=None, management_endpoint=None, protection_mode=None):
        if algorithm and not isinstance(algorithm, str):
            raise TypeError("Expected argument 'algorithm' to be a str")
        pulumi.set(__self__, "algorithm", algorithm)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if curve_id and not isinstance(curve_id, str):
            raise TypeError("Expected argument 'curve_id' to be a str")
        pulumi.set(__self__, "curve_id", curve_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if keys and not isinstance(keys, list):
            raise TypeError("Expected argument 'keys' to be a list")
        pulumi.set(__self__, "keys", keys)
        if length and not isinstance(length, int):
            raise TypeError("Expected argument 'length' to be a int")
        pulumi.set(__self__, "length", length)
        if management_endpoint and not isinstance(management_endpoint, str):
            raise TypeError("Expected argument 'management_endpoint' to be a str")
        pulumi.set(__self__, "management_endpoint", management_endpoint)
        if protection_mode and not isinstance(protection_mode, str):
            raise TypeError("Expected argument 'protection_mode' to be a str")
        pulumi.set(__self__, "protection_mode", protection_mode)

    @property
    @pulumi.getter
    def algorithm(self) -> Optional[str]:
        """
        The algorithm used by a key's key versions to encrypt or decrypt.
        """
        return pulumi.get(self, "algorithm")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment that contains this master encryption key.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="curveId")
    def curve_id(self) -> Optional[str]:
        """
        Supported curve IDs for ECDSA keys.
        """
        return pulumi.get(self, "curve_id")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetKeysFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def keys(self) -> Sequence['outputs.GetKeysKeyResult']:
        """
        The list of keys.
        """
        return pulumi.get(self, "keys")

    @property
    @pulumi.getter
    def length(self) -> Optional[int]:
        """
        The length of the key in bytes, expressed as an integer. Supported values include the following:
        * AES: 16, 24, or 32
        * RSA: 256, 384, or 512
        * ECDSA: 32, 48, or 66
        """
        return pulumi.get(self, "length")

    @property
    @pulumi.getter(name="managementEndpoint")
    def management_endpoint(self) -> str:
        return pulumi.get(self, "management_endpoint")

    @property
    @pulumi.getter(name="protectionMode")
    def protection_mode(self) -> Optional[str]:
        """
        The key's protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of `HSM` means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of `SOFTWARE` means that the key persists on the server, protected by the vault's RSA wrapping key which persists  on the HSM. All cryptographic operations that use a key with a protection mode of `SOFTWARE` are performed on the server. By default,  a key's protection mode is set to `HSM`. You can't change a key's protection mode after the key is created or imported.
        """
        return pulumi.get(self, "protection_mode")


class AwaitableGetKeysResult(GetKeysResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetKeysResult(
            algorithm=self.algorithm,
            compartment_id=self.compartment_id,
            curve_id=self.curve_id,
            filters=self.filters,
            id=self.id,
            keys=self.keys,
            length=self.length,
            management_endpoint=self.management_endpoint,
            protection_mode=self.protection_mode)


def get_keys(algorithm: Optional[str] = None,
             compartment_id: Optional[str] = None,
             curve_id: Optional[str] = None,
             filters: Optional[Sequence[pulumi.InputType['GetKeysFilterArgs']]] = None,
             length: Optional[int] = None,
             management_endpoint: Optional[str] = None,
             protection_mode: Optional[str] = None,
             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetKeysResult:
    """
    This data source provides the list of Keys in Oracle Cloud Infrastructure Kms service.

    Lists the master encryption keys in the specified vault and compartment.

    As a management operation, this call is subject to a Key Management limit that applies to the total number
    of requests across all management read operations. Key Management might throttle this call to reject an
    otherwise valid request when the total rate of management read operations exceeds 10 requests per second
    for a given tenancy.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_keys = oci.kms.get_keys(compartment_id=var["compartment_id"],
        management_endpoint=var["key_management_endpoint"],
        algorithm=var["key_algorithm"],
        length=var["key_length"],
        curve_id=oci_kms_curve["test_curve"]["id"],
        protection_mode=var["key_protection_mode"])
    ```


    :param str algorithm: The algorithm used by a key's key versions to encrypt or decrypt data. Currently, support includes AES, RSA, and ECDSA algorithms.
    :param str compartment_id: The OCID of the compartment.
    :param str curve_id: The curve ID of the keys. (This pertains only to ECDSA keys.)
    :param int length: The length of the key in bytes, expressed as an integer. Supported values include 16, 24, or 32.
    :param str management_endpoint: The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
    :param str protection_mode: A key's protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A  protection mode of `HSM` means that the key persists on a hardware security module (HSM) and all cryptographic operations are  performed inside the HSM. A protection mode of `SOFTWARE` means that the key persists on the server, protected by the vault's  RSA wrapping key which persists on the HSM. All cryptographic operations that use a key with a protection mode of  `SOFTWARE` are performed on the server.
    """
    __args__ = dict()
    __args__['algorithm'] = algorithm
    __args__['compartmentId'] = compartment_id
    __args__['curveId'] = curve_id
    __args__['filters'] = filters
    __args__['length'] = length
    __args__['managementEndpoint'] = management_endpoint
    __args__['protectionMode'] = protection_mode
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:kms/getKeys:getKeys', __args__, opts=opts, typ=GetKeysResult).value

    return AwaitableGetKeysResult(
        algorithm=__ret__.algorithm,
        compartment_id=__ret__.compartment_id,
        curve_id=__ret__.curve_id,
        filters=__ret__.filters,
        id=__ret__.id,
        keys=__ret__.keys,
        length=__ret__.length,
        management_endpoint=__ret__.management_endpoint,
        protection_mode=__ret__.protection_mode)
