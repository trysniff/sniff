from .intent_contracts import Store


class MemoryStore(Store):
    def metadata(self, key):
        return None
