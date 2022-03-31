"""
Usage : 
- Test all
python3 manage.py test
- Test one class
python3 manage.py test login.tests.LoginUserTest
- Test only one method
python3 manage.py test login.tests.RegisterUserTest.test_register_with_wrong
"""
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.reverse import reverse
from rest_framework.test import APITestCase

from .models import LocalUser


class BaseAPITestCase(APITestCase):

    def setUp(self):
        self.email = 'elfiend+test1@gmail.com'
        self.password = '!234Qwer'

        self.test_user = LocalUser.objects.create_user(self.email,
                                                       self.password)


class AuthAPITestCase(BaseAPITestCase):

    def setUp(self):
        super().setUp()

        self.login_url = reverse('auth-login')
        data = {'email': self.email, 'password': self.password}
        response = self.client.post(self.login_url, data, format='json')
        self.client.credentials(HTTP_AUTHORIZATION='Token ' +
                                response.data['auth_token'])


class RegisterUserTest(BaseAPITestCase):

    def setUp(self):
        super().setUp()
        self.register_url = reverse('auth-register')
        self.new_email = 'elfiend+test11@gmail.com'
        self.password = '!234Qwer'

    def test_register_success(self):
        """
        Ensure user is created for correct data.
        """
        data = {'email': self.new_email, 'password': self.password}
        response = self.client.post(self.register_url, data, format='json')

        # We want to make sure we have two users in the database..
        self.assertEqual(LocalUser.objects.count(), 2)
        # And that we're returning a 201 created code.
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # Additionally, we want to return email upon successful creation.
        self.assertEqual(response.data['email'], data['email'])
        self.assertFalse('password' in response.data)

        user = LocalUser.objects.latest('id')
        token = Token.objects.get(user=user)
        self.assertEqual(response.data['auth_token'], token.key)

    def test_register_with_exist_email(self):
        """
        Ensure user is not created for duplicate email.
        """
        data = {'email': self.email, 'password': self.password}
        response = self.client.post(self.register_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(LocalUser.objects.count(), 1)
        self.assertEqual(len(response.data['email']), 1)

    def test_register_with_short_password(self):
        """
        Ensure user is not created for password lengths less than 8.
        """
        data = {'email': self.new_email, 'password': '!234Qwe'}
        response = self.client.post(self.register_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(LocalUser.objects.count(), 1)
        self.assertEqual(len(response.data['password']), 1)

    def test_register_with_no_number(self):
        """
        Ensure user is not created for password without number.
        """
        data = {'email': self.new_email, 'password': '!xcvQwer'}
        response = self.client.post(self.register_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(LocalUser.objects.count(), 1)
        self.assertEqual(len(response.data['password']), 1)

    def test_register_with_no_upper(self):
        """
        Ensure user is not created for password without uppercase letter.
        """
        data = {'email': self.new_email, 'password': '!234qwer'}
        response = self.client.post(self.register_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(LocalUser.objects.count(), 1)
        self.assertEqual(len(response.data['password']), 1)

    def test_register_with_no_lower(self):
        """
        Ensure user is not created for password without lowercase letter.
        """
        data = {'email': self.new_email, 'password': '!234QWER'}
        response = self.client.post(self.register_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(LocalUser.objects.count(), 1)
        self.assertEqual(len(response.data['password']), 1)

    def test_register_with_no_symbol(self):
        """
        Ensure user is not created for password without symbol.
        """
        data = {'email': self.new_email, 'password': '1234Qwer'}
        response = self.client.post(self.register_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(LocalUser.objects.count(), 1)
        self.assertEqual(len(response.data['password']), 1)

    def test_register_with_only_symbol(self):
        """
        Ensure user is not created for password with only symbol.
        """
        data = {'email': self.new_email, 'password': '['}
        response = self.client.post(self.register_url, data, format='json')

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

        user = LocalUser.objects.latest('id')
        token = Token.objects.get(user=user)
        self.assertEqual(response.data['auth_token'], token.key)
        return token.key


class PasswordChangeTest(AuthAPITestCase):

    def setUp(self):
        super().setUp()
        self.password_change_url = reverse('auth-password-change')

    def test_change_password_success(self):
        """
        Ensure user can change password for correct data.
        """
        data = {
            'current_password': '!234Qwer',
            'new_password': 'Qwer!234',
        }
        response = self.client.post(self.password_change_url,
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
