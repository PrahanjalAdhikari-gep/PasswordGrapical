# Generated by Django 4.0.5 on 2022-07-03 14:05

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0009_logininfo_type'),
    ]

    operations = [
        migrations.RenameField(
            model_name='logininfo',
            old_name='type',
            new_name='passtype',
        ),
    ]