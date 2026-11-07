class XocError(ValueError):
    """An actionable, public error without source payloads or secrets."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
