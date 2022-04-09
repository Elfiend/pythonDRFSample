"""
Usage :
- Test all
python3 manage.py test
- Test all rapidly
python3 manage.py test --keepdb
- Test one class
python3 manage.py test login.tests.LoginUserTest
- Test only one method
python3 manage.py test login.tests.SignupUserTest.test_signup_with_only_symbol
"""

from django.core import mail
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from rest_framework import status
from rest_framework.reverse import reverse
from rest_framework.test import APITestCase

from .models import LocalUser
from .tokens import account_activation_token

# Empty the test outbox
mail.outbox = []


class BaseAPITestCase(APITestCase):

    def setUp(self):
        self.email = 'elfiend+test1@gmail.com'
        self.password = '!234Qwer'

        self.test_user = LocalUser.objects.create_user(self.email,
                                                       self.password)
        self.test_user.email_confirmed = False
        self.test_user.is_social_auth = False
        self.test_user.save()


class AuthAPITestCase(BaseAPITestCase):

    def setUp(self):
        super().setUp()

        self.client.login(email=self.email, password=self.password)


class SignupUserTest(BaseAPITestCase):

    def setUp(self):
        super().setUp()
        self.signup_url = reverse('auth-signup')
        self.new_email = 'elfiend+test11@gmail.com'
        self.password = '!234Qwer'

    def test_signup_success(self):
        """
        Ensure user is created for correct data.
        """
        data = {
            'email': self.new_email,
            'password': self.password,
            'password2': self.password,
        }
        response = self.client.post(self.signup_url, data, format='json')

        # We want to make sure we have two users in the database..
        self.assertEqual(LocalUser.objects.count(), 2)
        # And that we're returning a 201 created code.
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # Additionally, we want to return email upon successful creation.
        self.assertEqual(response.data['email'], data['email'])
        self.assertFalse('password' in response.data)

    def test_signup_with_exist_email(self):
        """
        Ensure user is not created for duplicate email.
        """
        data = {
            'email': self.email,
            'password': self.password,
            'password2': self.password,
        }
        response = self.client.post(self.signup_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(LocalUser.objects.count(), 1)
        self.assertEqual(len(response.data['email']), 1)

    def test_signup_with_short_password(self):
        """
        Ensure user is not created for password lengths less than 8.
        """
        data = {
            'email': self.new_email,
            'password': '!234Qwe',
            'password2': '!234Qwe',
        }
        response = self.client.post(self.signup_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(LocalUser.objects.count(), 1)
        self.assertEqual(len(response.data['password']), 1)

    def test_signup_with_no_number(self):
        """
        Ensure user is not created for password without number.
        """
        data = {
            'email': self.new_email,
            'password': '!xcvQwer',
            'password2': '!xcvQwer',
        }
        response = self.client.post(self.signup_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(LocalUser.objects.count(), 1)
        self.assertEqual(len(response.data['password']), 1)

    def test_signup_with_no_upper(self):
        """
        Ensure user is not created for password without uppercase letter.
        """
        data = {
            'email': self.new_email,
            'password': '!234qwer',
            'password2': '!234qwer',
        }
        response = self.client.post(self.signup_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(LocalUser.objects.count(), 1)
        self.assertEqual(len(response.data['password']), 1)

    def test_signup_with_no_lower(self):
        """
        Ensure user is not created for password without lowercase letter.
        """
        data = {
            'email': self.new_email,
            'password': '!234QWER',
            'password2': '!234QWER',
        }
        response = self.client.post(self.signup_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(LocalUser.objects.count(), 1)
        self.assertEqual(len(response.data['password']), 1)

    def test_signup_with_no_symbol(self):
        """
        Ensure user is not created for password without symbol.
        """
        data = {
            'email': self.new_email,
            'password': '1234Qwer',
            'password2': '1234Qwer',
        }
        response = self.client.post(self.signup_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(LocalUser.objects.count(), 1)
        self.assertEqual(len(response.data['password']), 1)

    def test_signup_with_only_symbol(self):
        """
        Ensure user is not created for password with only symbol.
        """
        data = {
            'email': self.new_email,
            'password': '[',
            'password2': '[',
        }
        response = self.client.post(self.signup_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(LocalUser.objects.count(), 1)
        self.assertEqual(len(response.data['password']), 4)


class LoginUserTest(BaseAPITestCase):

    def setUp(self):
        super().setUp()
        self.login_url = reverse('auth-login')

    def test_login_success(self):
        """
        Ensure user can log in for correct data.
        """
        data = {'email': self.email, 'password': self.password}
        response = self.client.post(self.login_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)


class ResetPasswordTest(AuthAPITestCase):

    def setUp(self):
        super().setUp()
        self.reset_password_url = reverse('auth-reset-password')

    def test_reset_password_success(self):
        """
        Ensure user can reset password for correct data.
        """
        data = {
            'old_password': '!234Qwer',
            'new_password': 'Qwer!234',
            'reenter_new_password': 'Qwer!234',
        }
        response = self.client.post(self.reset_password_url,
                                    data,
                                    format='json')

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)


class LogoutUserTest(AuthAPITestCase):

    def setUp(self):
        super().setUp()
        self.logout_url = reverse('auth-logout')

    def test_logout_success(self):
        """
        Ensure user can log out for correct data.
        """
        response = self.client.post(self.logout_url, '', format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # TODO: To check the token exist or not.


class EmailVerificationTest(AuthAPITestCase):

    def setUp(self):
        super().setUp()
        self.resend_verification_email_url = reverse(
            'auth-resend-verification-email')

    def test_resend_verification_email_success(self):
        """
        Ensure user can ask for resend email to verify.
        """
        response = self.client.post(self.resend_verification_email_url,
                                    '',
                                    format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Test that one message has been sent.
        self.assertEqual(len(mail.outbox), 1)
        # Verify that the subject of the first message is correct.
        self.assertEqual(mail.outbox[0].subject, 'Activate Your Account')

    def test_verification_email_success(self):
        """
        Ensure user can verify for correct data.
        """
        response = self.client.post(self.resend_verification_email_url,
                                    '',
                                    format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        uid = urlsafe_base64_encode(force_bytes(self.test_user.pk))
        token = account_activation_token.make_token(self.test_user)
        email_verification_url = reverse('auth-email-verification',
                                         args=(uid, token))

        response = self.client.get(email_verification_url, '', format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], self.email)
        self.assertEqual(response.data['email_confirmed'], True)
