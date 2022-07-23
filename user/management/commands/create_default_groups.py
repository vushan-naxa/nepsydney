from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    """
    Create default Project groups
    """
    help = "Create default Project Groups"
    PROJECT_GROUPS = ['Admin', 'Manager']

    def handle(self, **options):
        for group_name in self.PROJECT_GROUPS:
            group, created = Group.objects.get_or_create(name=group_name)
            if created:
                self.stdout.write(self.style.WARNING(
                    "Created group {}".format(group.name)))
