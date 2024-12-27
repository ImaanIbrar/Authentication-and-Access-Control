import unittest

from app_test import FlaskAppTests

from app import grant_access


class AccessTests(unittest.TestCase):
    def test_grant_access_function(self):
        # Test grant_access function with valid inputs
        self.assertTrue(grant_access('Task', 'mnaeem.bese21seecs@seecs.edu.pk'))

        # Test grant_access function with invalid inputs
        self.assertFalse(grant_access('InvalidResource', 'iibrar.bese21seecs@seecs.edu.pk'))

#since grant_access checks working hours too, returns True if resource and email matches AND working hours, location are valid
if __name__ == '__main__':
    unittest.main()
