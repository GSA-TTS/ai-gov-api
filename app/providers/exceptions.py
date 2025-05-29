class InvalidInput(Exception):
    """Exception raised for errors caused by invalid input data format or content."""
    def __init__(self, message: str, field_name: str | None = None, original_exception: Exception | None= None):
        super().__init__(message)
        self.field_name = field_name
        self.original_exception = original_exception

class InvalidBase64DataError(InvalidInput):
    """Error for failures during Base64 decoding."""
    pass

class InvalidImageURLError(InvalidInput):
    """Error for failures during data:url decoding."""
    pass


class ModelError(Exception):
    """Exception raised from models during invocation."""
    def __init__(self, message: str, field_name: str | None = None, original_exception: Exception | None= None):
        super().__init__(message)
        self.field_name = field_name
        self.original_exception = original_exception
