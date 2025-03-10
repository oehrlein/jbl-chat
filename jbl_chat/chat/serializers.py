from django.contrib.auth.models import User
from rest_framework import serializers

from chat.models import Message


class MessageSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField()
    sender = serializers.CharField()
    recipient = serializers.CharField()
    content = serializers.CharField()

    class Meta:
        model = Message
        fields = ['created_at', 'sender', 'recipient', 'content']


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = [
            'username',
            'first_name',
            'last_name',
            'email',
            'last_login',
            'date_joined'
        ]
