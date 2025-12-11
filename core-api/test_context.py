from agent import _extract_entities, _get_user_context, _check_ip_reputation
import unittest

class TestContextAwareness(unittest.TestCase):
    
    def test_entity_extraction(self):
        log = "Failed login for user admin@corp.com from 192.168.1.50"
        ip, user = _extract_entities(log)
        self.assertEqual(ip, "192.168.1.50")
        self.assertEqual(user, "admin@corp.com")
        print("\n✅ Extraction Verified: Admin & IP found.")

    def test_user_context_admin(self):
        ctx = _get_user_context("admin@corp.com")
        self.assertTrue(ctx['is_admin'])
        self.assertEqual(ctx['jobTitle'], "Administrator")
        print("✅ Admin Context Verified.")

    def test_user_context_employee(self):
        ctx = _get_user_context("bob@corp.com")
        self.assertFalse(ctx['is_admin'])
        self.assertEqual(ctx['jobTitle'], "Employee")
        print("✅ Employee Context Verified.")

    def test_ip_reputation_malicious(self):
        ctx = _check_ip_reputation("51.15.20.10")
        self.assertEqual(ctx['status'], "Malicious")
        self.assertTrue(ctx['score'] > 50)
        print("✅ Malicious IP Detection Verified.")

if __name__ == '__main__':
    unittest.main()
