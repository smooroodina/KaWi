import unittest
from temp import *

class TempTest(unittest.TestCase):
    def test_lookup_iface(self):
        result = lookup_iface()
        self.assertGreater(len(result), 0)