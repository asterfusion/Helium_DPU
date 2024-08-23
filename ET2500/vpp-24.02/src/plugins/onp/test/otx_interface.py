from vpp_interface import VppInterface


class OtxInterface(VppInterface):
    """
    Otx Interface
    """

    def __init__(self, test):
        super(OtxInterface, self).__init__(test)

    def add_vpp_config(self):
        print(self.name)
        self.test.registry.register(self, self.test.logger)

    def remove_vpp_config(self):
        pass

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "octeon-%d" % self._sw_if_index
