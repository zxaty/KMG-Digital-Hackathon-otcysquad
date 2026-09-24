from django.apps import AppConfig
class AppConfig(AppConfig):
    name = 'app'
    def ready(self):
        from django.db.models.signals import post_save, post_delete, m2m_changed
        from django.db.backends.signals import connection_created
        from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
        from . import audit
        post_save.connect(audit.mutation, dispatch_uid='app_mutation')
        post_delete.connect(audit.deletion, dispatch_uid='app_deletion')
        m2m_changed.connect(audit.relations, dispatch_uid='app_relations')
        connection_created.connect(audit.db_connected, dispatch_uid='app_db_connected')
        user_logged_in.connect(audit.signed_in)
        user_logged_out.connect(audit.signed_out)
        user_login_failed.connect(audit.login_failed)
