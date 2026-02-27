class RetryManager:
    def __init__(self, max_attempts: int = 3) -> None:
        self.max_attempts = max_attempts
        self.sent: set[str] = set()

    def should_send(self, message_id: str) -> bool:
        if message_id in self.sent:
            return False
        self.sent.add(message_id)
        return True
