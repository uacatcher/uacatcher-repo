class Component(object):
    """
    Base component that need to be used by all child components.
    """
    def setup(self) -> str:
        return None

    def perform(self) -> str:
        raise NotImplementedError("Perform needs to be implemented.")

    def cleanup(self) -> str:
        return None

    def get_name(self) -> str:
        return "Base"