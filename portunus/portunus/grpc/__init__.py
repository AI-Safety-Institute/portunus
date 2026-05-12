"""gRPC services for Envoy filters.

Currently hosts the Envoy ``ext_authz`` ``Check`` service in
:mod:`portunus.grpc.auth_servicer`. It wraps
:class:`portunus.services.auth_service.AuthService` and publishes per-request
metadata synchronously so every authenticated request has principal info
recorded in Kinesis before it proceeds upstream.

The ``ext_proc`` ``Process`` service (for HTTP body / WS frame observation)
is not yet implemented — it will be added when the Envoy filter chain
switches to gRPC observability.

See :mod:`portunus.grpc.server` for lifecycle management. The gRPC stack
is gated on :attr:`portunus.config.GrpcConfig.enabled`, default off.
"""

from portunus.grpc.auth_servicer import PortunusAuthServicer

__all__ = ["PortunusAuthServicer"]
