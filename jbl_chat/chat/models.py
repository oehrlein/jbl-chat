from django.contrib.auth.models import User
from django.db import models
from django.db.models import F, Q


class Message(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    sender = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='sender'
    )
    recipient = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='recipient'
    )
    content = models.TextField()

    class Meta:
        db_table = "message"
        constraints = [
            models.CheckConstraint(
                check=~Q(sender=F('recipient')),
                name='sender_not_recipient'
            )
        ]
