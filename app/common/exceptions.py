from typing import Any

class RepositoryError(Exception):
    """Base class for repository-related errors."""
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message

class ResourceNotFoundError(RepositoryError):
    """Raised when a resource is not found in a repository."""
    def __init__(self, resource_name: str, identifier: Any):
        self.resource_name = resource_name
        self.identifier = identifier
        super().__init__(f"{resource_name} with identifier '{identifier}' not found.")

class DuplicateResourceError(RepositoryError):
    """Raised when attempting to create a resource that already exists (e.g., unique constraint)."""
    def __init__(self, resource_name: str, identifier: Any):
        self.resource_name = resource_name
        self.identifier = identifier
        super().__init__(f"{resource_name} with identifier '{identifier}' already exists.")
