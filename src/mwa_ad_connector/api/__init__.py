"""FastAPI presentation layer: app factory, routes, schemas, middleware, dependencies."""

from mwa_ad_connector.api.app import create_app

__all__ = ["create_app"]
