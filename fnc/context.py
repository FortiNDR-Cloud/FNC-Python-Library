
class Context:
    _checkpoint: str
    _history: dict

    def __init__(self):
        self._checkpoint = ''
        self._history = {}

    def update_history(self, _history: dict):
        self._history = _history or None

    def get_history(self):
        return self._history

    def update_checkpoint(self, checkpoint: str):
        self._checkpoint = checkpoint

    def get_checkpoint(self):
        return self._checkpoint
