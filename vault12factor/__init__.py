import django

from .apps import *


if django.VERSION < (3, 2):
    default_app_config = 'vault12factor.DjangoIntegration'

