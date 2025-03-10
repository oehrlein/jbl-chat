from typing import Union

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import User
from django.db.models import Case, When, F, Max, Subquery, Q, QuerySet
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.urls import resolve
from django.views import View
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from chat.models import Message
from chat.serializers import MessageSerializer, UserSerializer


class IndexView(View):
    """
    Main view for the application's index page.

    This view handles both authenticated and unauthenticated users:
        - For authenticated users: Displays a list of other users and
        recent conversations.
        - For unauthenticated users: Displays a login page.

    The view contains helper methods to retrieve users and conversation
    data, as well as handlers for the different authentication states.
    """

    def _get_users(self, request: HttpRequest) -> QuerySet:
        """
        Get all users except the current user.

        This method retrieves all users in the system excluding the
        currently authenticated user. The results are ordered by
        username alphabetically.

        Args:
            request: The HTTP request object from an authenticated
                user.

        Returns:
            QuerySet of User objects, excluding the current user,
            ordered by username.
        """
        return (
            User.objects
                .exclude(id=request.user.id)
                .annotate(user_id=F('id'))
                .order_by('username')
        )

    def _get_conversations(self, request: HttpRequest) -> QuerySet:
        """
        Get the most recent message from each conversation the current
        user is involved in.

        This method performs a two-step query:
            1. First finds the most recent message ID for each
            conversation partner.
            2. Then retrieves those messages with user details.

        The result is a list of the most recent messages from all
        conversations, in addition to the conversation partner's ID and
        username.

        Args:
            request: The HTTP request object from an authenticated
                user.

        Returns:
            QuerySet containing the most recent message from each
            conversation, ordered by creation date (newest first).
        """
        subquery = Message.objects.filter(
            Q(sender_id=request.user.id) | Q(recipient_id=request.user.id)
        ).values(
            partner_user_id=Case(
                When(sender_id=request.user.id, then=F('recipient_id')),
                When(recipient_id=request.user.id, then=F('sender_id')),
            )
        ).annotate(
            most_recent_message_id=Max('id')
        ).values('partner_user_id', 'most_recent_message_id')

        return Message.objects.filter(
            id__in=Subquery(subquery.values('most_recent_message_id'))
        ).select_related('sender', 'recipient').annotate(
            user_id=Case(
                When(sender_id=request.user.id, then=F('recipient__id')),
                When(recipient_id=request.user.id, then=F('sender__id')),
            ),
            username=Case(
                When(
                    sender_id=request.user.id, then=F('recipient__username')
                ),
                When(
                    recipient_id=request.user.id, then=F('sender__username')
                )
            )
        ).values(
            'id', 'created_at', 'content', 'user_id', 'username'
        ).order_by('-created_at')

    def _handle_authenticated_view(
        self, request: HttpRequest
    ) -> HttpResponse:
        """
        Handle requests from authenticated users.

        Renders the main index page with context containing:
            - A QuerySet of all other users.
            - A QuerySet of the most recent conversations.

        Args:
            request: The HTTP request object from an authenticated
                user.

        Returns:
            Rendered HTTP response with the index template and context
            data.
        """
        return render(
            request,
            "index.html",
            {
                'users': self._get_users(request),
                'conversations': self._get_conversations(request),
            }
        )

    def _handle_unauthenticated_user(
        self, request: HttpRequest, is_login_error: bool
    ) -> HttpResponse:
        """
        Handle requests from unauthenticated users.

        Renders the login page, optionally with an error message if
        login failed.

        Args:
            request: The HTTP request object from an unauthenticated
                user.
            is_login_error: Boolean indicating if there was a login
                error.

        Returns:
            Rendered HTTP response with the login template.
        """
        return render(request, "login.html", {'is_error': is_login_error})

    def get(
        self, request: HttpRequest, is_login_error: bool = False
    ) -> HttpResponse:
        """
        Handle GET requests to the index page.

        This is the main entry point for the view. It checks if the
        user is authenticated and routes the request to the appropriate
        handler.

        Args:
            request: The HTTP request object.
            is_login_error: Optional boolean indicating if there was a
                login error (default: False).

        Returns:
            HttpResponse: Either the authenticated view or the login
            page.
        """
        if request.user.is_authenticated:
            return self._handle_authenticated_view(request)
        else:
            return self._handle_unauthenticated_user(request, is_login_error)


class LoginAPIView(APIView):
    """
    API view for handling user authentication.

    This view processes login attempts and returns appropriate
    responses based on whether the authentication succeeds or fails. It
    supports both HTMX requests and regular API requests with different
    response formats for each.

    Authentication is permitted for all users (including anonymous)
    since this endpoint is specifically for logging in unauthenticated
    users.
    """
    permission_classes = [AllowAny]

    def post(self, request: Request) -> Union[Response, HttpResponse]:
        """
        Process a login attempt.

        Authenticates a user based on provided username and password.
        For successful authentications:
            - HTMX requests: Redirects to requested next URL or index
            page.
            - API requests: Returns success message with 200 status.

        For failed authentications:
            - HTMX requests: Returns index page with login error.
            - API requests: Returns error message with 401 status.

        Args:
            request: Request object containing login credentials in the
                data attribute (username and password).

        Returns:
            For HTMX requests: HttpResponse with appropriate content.
            For API requests: Response object with success/error
                message.
        """
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(request, username=username, password=password)

        index_view = IndexView()
        if user:
            login(request, user)

            if request.htmx:
                next_url = request.data.get("next")
                if next_url:
                    func, args, kwargs = resolve(next_url)
                    # Need to get class from resolved URL.
                    class_instance = func.view_class()
                    return class_instance.get(request, **kwargs)

                return index_view.get(request)

            return Response(
                {'success': 'Login successful'},
                status=status.HTTP_200_OK
            )
        else:
            # Handle failed login attempts
            if request.htmx:
                return index_view.get(request, True)

            return Response(
                {'error': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED
            )


class LogoutAPIView(APIView):
    """
    API view for handling user logout.

    This view processes logout requests and returns appropriate
    responses based on the request type. It supports both HTMX requests
    and regular API requests with different response formats for each.

    Authentication is required as only authenticated users can logout.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Union[Response, HttpResponse]:
        """
        Process a logout request.

        Logs out the current user by invalidating their session.
        Response format depends on request type:
            - HTMX requests: Returns rendered login page.
            - API requests: Returns success message with 200 status.

        Args:
            request: Request object from an authenticated user

        Returns:
            For HTMX requests: HttpResponse with rendered login
                template.
            For API requests: Response object with success message.
        """
        logout(request)

        if request.htmx:
            return render(request, "login.html")

        return Response(
            {'success': 'Logout successful'},
            status=status.HTTP_200_OK
        )


class UserDetailAPIView(APIView):
    """
    API endpoint to get user details.

    This view retrieves and returns information about a specific user
    by their ID. It supports both HTMX requests and regular API
    requests with different response formats for each.

    Authentication is required to access user details.
    """
    permission_classes = [IsAuthenticated]

    def get(
        self, request: Request, user_id: int
    ) -> Union[Response, HttpResponse]:
        """
        Retrieve details for a specific user.

        Fetches user information by ID and returns it in the
        appropriate format. If the user doesn't exist, returns a 404
        error.

        Response format depends on request type:
            - HTMX requests: Returns rendered user detail component.
            - API requests: Returns serialized user data.

        Args:
            request: Request object from an authenticated user.
            user_id: Integer ID of the requested user.

        Returns:
            For HTMX requests: HttpResponse with rendered user template
                or error message.
            For API requests: Response object with user data or error.
        """
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            if request.htmx:
                return HttpResponse("User not found", status=404)

            return Response(
                {'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND
            )

        if request.htmx:
            return render(
                request, "components/user_detail.html", {'user_data': user}
            )

        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ConversationView(LoginRequiredMixin, View):
    """
    View for displaying a conversation between the current user and
    another user.

    This view requires authentication. Unauthenticated users are
    redirected to the homepage. It retrieves the conversation partner
    by username and renders the conversation template.
    """
    login_url = "/"

    def get(self, request: HttpRequest, username: str) -> HttpResponse:
        """
        Handle GET requests for the conversation page.

        Retrieves the user corresponding to the provided username and
        renders the conversation template with the user data as
        context. If the provided username is the username of the
        authenticated user, returns a 400 error. If the user doesn't
        exist, returns a 404 error.

        Args:
            request: HTTP request from an authenticated user.
            username: Username of the conversation partner to display.

        Returns:
            HttpResponse with rendered conversation template if the
            user exists, a 400 error if the provided username is the
            username of the authenticated user, or a 404 error response
            if the user is not found.
        """
        if username == request.user.username:
            return HttpResponse("Messages cannot be sent to self", status=400)

        user_data = User.objects.filter(username=username).first()
        if not user_data:
            # Handle case where user doesn't exist.
            return HttpResponse("User not found", status=404)

        return render(
            request, "conversation.html", {'user_data': user_data}
        )


class MessageAPIView(APIView):
    """
    API view for handling message operations between users.

    This view provides endpoints for retrieving conversation history
    and sending new messages. It supports both HTMX requests and
    regular API requests with different response formats for each.

    Authentication is required for all operations.
    """
    permission_classes = [IsAuthenticated]

    def get(
        self, request: HttpRequest, partner_user_id: int
    ) -> Union[HttpResponse, Response]:
        """
        Retrieve conversation history with a specific user.

        Fetches all messages exchanged between the current user and the
        specified user, ordered chronologically by creation time. If
        the provided user ID is the user ID of the authenticated user,
        returns a 400 error.

        Response format depends on request type:
            - HTMX requests: Returns rendered conversation component.
            - API requests: Returns serialized message data.

        Args:
            request: HTTP request from an authenticated user.
            partner_user_id: User ID of the conversation partner.

        Returns:
            For HTMX requests: HttpResponse with rendered conversation
                template.
            For API requests: Response object with serialized message
                data.
        """
        if request.user.id == partner_user_id:
            return Response(
                {
                    'error': (
                        'Messages cannot be retrieved as messages cannot be '
                        'sent to self'
                    )
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        messages = (
            Message.objects.select_related('sender', 'recipient').filter(
                (
                    Q(sender__id=request.user.id)
                    & Q(recipient__id=partner_user_id))
                | (
                    Q(sender__id=partner_user_id)
                    & Q(recipient__id=request.user.id)
                )
            ).order_by('created_at')
        )

        if request.htmx:
            return render(
                request,
                "components/conversation_detail.html",
                {'partner_user_id': partner_user_id, 'messages': messages}
            )

        serializer = MessageSerializer(messages, many=True)
        return Response(
            {'partner_user_id': partner_user_id, 'messages': serializer.data},
            status=status.HTTP_200_OK
        )

    def post(
        self, request: HttpRequest, partner_user_id: int
    ) -> Union[HttpResponse, Response]:
        """
        Send a new message to a specific user.

        Creates a new message with the current user as sender and the
        specified user as recipient, using the content from the
        request. If the provided user ID is the user ID of the
        authenticated user, returns a 400 error.

        Response format depends on request type:
            - HTMX requests: Returns rendered message component.
            - API requests: Returns serialized new message data.

        Args:
            request: HTTP request containing message content.
            partner_user_id: User ID of the message recipient.

        Returns:
            For HTMX requests: HttpResponse with rendered message
                template.
            For API requests: Response object with serialized message
                data and 201 Created status.
        """
        if request.user.id == partner_user_id:
            return Response(
                {'error': 'Messages cannot be sent to self'},
                status=status.HTTP_400_BAD_REQUEST
            )

        sender_id = request.user.id
        content = request.data.get("content")
        new_message = Message.objects.create(
            sender_id=sender_id, recipient_id=partner_user_id, content=content
        )
        new_message.save()

        if request.htmx:
            return render(
                request,
                "components/message_detail.html",
                {'force_sender_format': True, 'message': new_message}
            )

        serializer = MessageSerializer(new_message)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
