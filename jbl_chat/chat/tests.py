import json
from urllib.parse import parse_qs, urlparse

from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.urls import reverse

from chat.models import Message


class ChatBaseTestCase(TestCase):

    def setUp(self):
        self.client = Client()
        self.create_user(1)

    def create_user(self, user_instance_number):
        user_identfier = f"user{user_instance_number}"
        user = User.objects.create_user(
            username=user_identfier, password="password"
        )
        setattr(self, user_identfier, user)

    def create_additional_users(self, user_count):
        # Considering a first user already exists, the first additional
        # user should be 2, therefore the range should start at 2.
        for user_instance_number in range(2, user_count + 2):
            self.create_user(user_instance_number)

    def create_messages(self):
        # Get all users that are not user1.
        users = [
            value for attribute, value in self.__dict__.items()
            if attribute.startswith("user") and attribute != "user1"
        ]
        for user in users:
            Message.objects.create(
                sender=self.user1,
                recipient=user,
                content=f"Hi, {user.username}!"
            )
            Message.objects.create(
                sender=user, recipient=self.user1, content="Hi, user1!"
            )

    def login(self):
        self.client.login(username="user1", password="password")


class IndexViewTests(ChatBaseTestCase):

    def setUp(self):
        super().setUp()

        self.create_additional_users(2)
        self.create_messages()

    def test_unauthenticated_user_response(self):
        """
        Test that unauthenticated users see the login page.
        """
        response = self.client.get(reverse("index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "login.html")
        self.assertFalse(response.context['is_error'])

    def test_successful_login_response(self):
        """
        Test that authenticated users see the index page with users and
        conversations.
        """
        self.login()
        response = self.client.get(reverse("index"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "index.html")

        # Check that other users are in the context
        users = response.context['users']
        self.assertEqual(users.count(), 2)
        user_ids = [user.id for user in users]
        self.assertIn(self.user2.id, user_ids)
        self.assertIn(self.user3.id, user_ids)

        # Check that conversations are in the context
        conversations = response.context['conversations']
        self.assertEqual(conversations.count(), 2)

    def test_failed_login_response(self):
        """
        Test that users see the login page following a failed login
        attempt.
        """
        self.client.login(username="user1", password="wrongpassword")
        response = self.client.get(reverse("index"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "login.html")


class LoginAPIViewTests(ChatBaseTestCase):

    def setUp(self):
        super().setUp()

        self.create_additional_users(1)

    def test_successful_login_api_response(self):
        """
        Test API response after successful login.
        """
        response = self.client.post(
            reverse("login-api"),
            {'username': 'user1', 'password': 'password'}
        )

        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content)
        self.assertEqual(response_data, {'success': 'Login successful'})

    def test_successful_login_htmx_response(self):
        """
        Test HTMX response after successful login.
        """
        response = self.client.post(
            reverse("login-api"),
            {'username': 'user1', 'password': 'password'},
            HTTP_HX_REQUEST='true'
        )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "index.html")

    def test_successful_login_htmx_redirect_response(self):
        """
        Test HTMX response after successful login.
        """
        response = self.client.post(
            reverse("login-api"),
            {
                'username': 'user1',
                'password': 'password',
                'next': '/conversation/user2'
            },
            HTTP_HX_REQUEST='true'
        )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "conversation.html")

    def test_failed_login_api_response(self):
        """
        Test API response after failed login.
        """
        response = self.client.post(
            reverse("login-api"),
            {'username': 'user1', 'password': 'wrongpassword'}
        )

        self.assertEqual(response.status_code, 401)
        response_data = json.loads(response.content)
        self.assertEqual(response_data, {'error': 'Invalid credentials'})

    def test_failed_login_htmx_response(self):
        """
        Test HTMX response after failed login.
        """
        response = self.client.post(
            reverse("login-api"),
            {'username': 'user1', 'password': 'wrongpassword'},
            HTTP_HX_REQUEST='true'
        )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "login.html")
        self.assertTrue(response.context['is_error'])


class LogoutAPIViewTests(ChatBaseTestCase):

    def setUp(self):
        super().setUp()

        self.login()

    def verify_logout(self):
        """
        Verify user is logged out.
        """
        return self.assertFalse('_auth_user_id' in self.client.session)

    def test_logout_api_response(self):
        """
        Test API response after logout.
        """
        response = self.client.post(reverse("logout-api"))

        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content)
        self.assertEqual(response_data, {'success': 'Logout successful'})

        self.verify_logout()

    def test_logout_htmx_response(self):
        """
        Test HTMX response after logout.
        """
        response = self.client.post(
            reverse("logout-api"),
            HTTP_HX_REQUEST='true'
        )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "login.html")

        self.verify_logout()


class UserDetailAPIViewTests(ChatBaseTestCase):

    def setUp(self):
        super().setUp()

        self.create_additional_users(1)

    def test_successful_user_details_api_response(self):
        """
        Test API response of successful user details request.
        """
        self.login()
        response = self.client.get(
            reverse("user-detail-api", kwargs={'user_id': self.user2.id})
        )

        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content)
        self.assertEqual(response_data['username'], 'user2')

    def test_successful_user_details_htmx_response(self):
        """
        Test HTMX response of successful user details request.
        """
        self.login()
        response = self.client.get(
            reverse("user-detail-api", kwargs={'user_id': self.user2.id}),
            HTTP_HX_REQUEST='true'
        )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "components/user_detail.html")

    def test_unauthenticated_user_details_api_response(self):
        """
        Test API response of unauthenticated user details request.
        """
        response = self.client.get(
            reverse("user-detail-api", kwargs={'user_id': self.user2.id})
        )

        self.assertEqual(response.status_code, 403)

    def test_nonexistant_user_details_api_response(self):
        """
        Test API response of user details request for non-existent
        user.
        """
        self.login()
        response = self.client.get(
            reverse("user-detail-api", kwargs={'user_id': 3})
        )

        self.assertEqual(response.status_code, 404)
        response_data = json.loads(response.content)
        self.assertEqual(response_data, {'error': 'User not found'})


class ConversationViewTests(ChatBaseTestCase):

    def setUp(self):
        super().setUp()

    def test_successful_conversation_response(self):
        """
        Test that authenticated users see the conversation page.
        """
        self.create_additional_users(1)
        self.login()
        response = self.client.get(
            reverse('conversation', kwargs={'username': 'user2'})
        )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'conversation.html')
        self.assertEqual(response.context['user_data'], self.user2)

    def test_nonexistant_conversation_response(self):
        """
        Test the response of a conversation with a non-existant user.
        """
        self.login()
        response = self.client.get(
            reverse('conversation', kwargs={'username': 'non_existent_user'})
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content.decode(), "User not found")

    def test_conversation_with_self_response(self):
        """
        Test the response of a user's conversation with itself.
        """
        self.login()
        response = self.client.get(
            reverse('conversation', kwargs={'username': self.user1.username})
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.content.decode(), "Messages cannot be sent to self"
        )

    def test_unauthenticated_conversation_response(self):
        """
        Test that unauthenticated users are redirected to login page.
        """
        response = self.client.get(
            reverse('conversation', kwargs={'username': 'user2'})
        )

        self.assertEqual(response.status_code, 302)

        parsed_response_url = urlparse(response.url)
        self.assertEqual("/", parsed_response_url.path)

        response_url_query_params = parse_qs(parsed_response_url.query)
        self.assertEqual(
            response_url_query_params.get('next')[0], "/conversation/user2"
        )


class MessageAPIViewTests(ChatBaseTestCase):

    def setUp(self):
        super().setUp()

        self.create_additional_users(1)
        self.create_messages()

    def test_successful_message_api_get_response(self):
        """
        Test API response after retrieving messages.
        """
        self.login()
        response = self.client.get(
            reverse("message-api", kwargs={'partner_user_id': 2})
        )

        self.assertEqual(response.status_code, 200)

        response_data = json.loads(response.content)
        self.assertEqual(response_data['partner_user_id'], 2)

        messages = response_data['messages']
        self.assertEqual(len(messages), 2)

    def test_successful_message_api_post_response(self):
        """
        Test API response after sent message.
        """
        self.login()
        response = self.client.post(
            reverse("message-api", kwargs={'partner_user_id': 2}),
            {'content': 'Test message'}
        )

        self.assertEqual(response.status_code, 201)

        response_data = json.loads(response.content)
        self.assertEqual(response_data['sender'], self.user1.username)
        self.assertEqual(response_data['recipient'], self.user2.username)
        self.assertEqual(response_data['content'], "Test message")

    def test_successful_message_htmx_get_response(self):
        """
        Test HTMX response after retrieving messages.
        """
        self.login()
        response = self.client.get(
            reverse("message-api", kwargs={'partner_user_id': 2}),
            HTTP_HX_REQUEST='true'
        )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(
            response, "components/conversation_detail.html"
        )

        messages = response.context['messages']
        self.assertEqual(messages.count(), 2)

    def test_successful_message_htmx_post_response(self):
        """
        Test HTMX response after sent message.
        """
        self.login()
        response = self.client.post(
            reverse("message-api", kwargs={'partner_user_id': 2}),
            {'content': 'Test message'},
            HTTP_HX_REQUEST='true'
        )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "components/message_detail.html")

    def test_unauthenticated_message_get_api_response(self):
        """
        Test API response of unauthenticated message GET request.
        """
        response = self.client.get(
            reverse("message-api", kwargs={'partner_user_id': 2})
        )

        self.assertEqual(response.status_code, 403)

    def test_unauthenticated_message_post_api_response(self):
        """
        Test API response of unauthenticated message POST request.
        """
        response = self.client.post(
            reverse("message-api", kwargs={'partner_user_id': 2}),
            {'content': 'Test message'}
        )

        self.assertEqual(response.status_code, 403)

    def test_self_messages_get_response(self):
        """
        Test the response of a user trying to retrieve messages sent to
        itself.
        """
        self.login()
        response = self.client.get(
            reverse("message-api", kwargs={'partner_user_id': self.user1.id})
        )

        self.assertEqual(response.status_code, 400)

        response_data = json.loads(response.content)
        self.assertEqual(
            response_data,
            {
                'error': (
                    'Messages cannot be retrieved as messages cannot be '
                    'sent to self'
                )
            }
        )

    def test_self_messages_post_response(self):
        """
        Test the response of a user trying to send a message to itself.
        """
        self.login()
        response = self.client.post(
            reverse("message-api", kwargs={'partner_user_id': self.user1.id}),
            {'content': 'Test message'}
        )

        self.assertEqual(response.status_code, 400)

        response_data = json.loads(response.content)
        self.assertEqual(
            response_data, {'error': 'Messages cannot be sent to self'}
        )
