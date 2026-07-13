from django.test import TestCase
from django.contrib.auth import get_user_model
from core.models import UserKeys

User = get_user_model()

class ForgotPasswordTestCase(TestCase):
    def setUp(self):
        # Create a test user with a security question
        self.username = "testuser"
        self.password = "original_password"
        self.question = "What is your favorite color?"
        self.answer = "Blue"
        self.normalized_answer = "blue"
        
        # Salt and key stubs
        self.salt = "salt_stub"
        self.rsa_pub = "rsa_pub_stub"
        self.rsa_priv = "rsa_priv_stub"
        self.recovery_salt = "recovery_salt_stub"
        self.rsa_priv_rec = "rsa_priv_rec_stub"
        
        # Register user via the register endpoint
        payload = {
            "username": self.username,
            "password": self.password,
            "salt": self.salt,
            "rsa_public_key": self.rsa_pub,
            "encrypted_rsa_private_key": self.rsa_priv,
            "security_question": self.question,
            "security_answer": self.answer,
            "recovery_salt": self.recovery_salt,
            "encrypted_rsa_private_key_recovery": self.rsa_priv_rec
        }
        response = self.client.post("/api/auth/register/", payload, content_type="application/json")
        self.assertEqual(response.status_code, 201)

    def test_get_security_question(self):
        # Test fetching the security question
        response = self.client.post(
            "/api/auth/forgot-password/question/",
            {"username": self.username},
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["security_question"], self.question)

        # Test non-existent user
        response = self.client.post(
            "/api/auth/forgot-password/question/",
            {"username": "nonexistent"},
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 404)

    def test_verify_security_answer(self):
        # Test verify with correct answer (case/whitespace insensitive check)
        response = self.client.post(
            "/api/auth/forgot-password/verify/",
            {"username": self.username, "security_answer": "  blUE  "},
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["recovery_salt"], self.recovery_salt)
        self.assertEqual(data["encrypted_rsa_private_key_recovery"], self.rsa_priv_rec)

        # Test verify with incorrect answer
        response = self.client.post(
            "/api/auth/forgot-password/verify/",
            {"username": self.username, "security_answer": "Red"},
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.json())

    def test_reset_password_with_recovery(self):
        new_password = "new_super_secret_password"
        new_salt = "new_salt_stub"
        new_encrypted_rsa_private_key = "new_rsa_priv_stub"

        # Test reset with correct answer
        response = self.client.post(
            "/api/auth/forgot-password/reset/",
            {
                "username": self.username,
                "security_answer": "  bLuE ",
                "new_password": new_password,
                "new_salt": new_salt,
                "new_encrypted_rsa_private_key": new_encrypted_rsa_private_key
            },
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["success"], "Password reset successfully")

        # Verify password and keys are updated in database
        user = User.objects.get(username=self.username)
        self.assertTrue(user.check_password(new_password))
        
        keys = user.keys
        self.assertEqual(keys.salt, new_salt)
        self.assertEqual(keys.encrypted_rsa_private_key, new_encrypted_rsa_private_key)

    def test_reset_password_with_incorrect_answer(self):
        # Test reset with incorrect answer
        response = self.client.post(
            "/api/auth/forgot-password/reset/",
            {
                "username": self.username,
                "security_answer": "Red",
                "new_password": "some_new_password",
                "new_salt": "some_new_salt",
                "new_encrypted_rsa_private_key": "some_new_key"
            },
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)
        
        # Verify original password is still valid
        user = User.objects.get(username=self.username)
        self.assertTrue(user.check_password(self.password))
