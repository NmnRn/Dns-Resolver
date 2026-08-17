from django.urls import path

from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.logs, name='logs'),
    path('gecmis/', views.queries, name='queries'),
    path('gecmis/disa-aktar/', views.queries_export, name='queries_export'),
    path('sunucular/', views.servers, name='servers'),
    path('filtreler/', views.filters, name='filters'),
    path('filtreler/link-kontrol/', views.check_sources_ajax, name='check_sources'),
    path('analiz/', views.analytics, name='analytics'),
    path('sertifika/', views.certificate, name='certificate'),
    path('domain/', views.guide, name='guide'),
    path('ayarlar/', views.settings_page, name='settings'),
    path('sorgu-ayarlari/', views.query_settings, name='query_settings'),
    path('ayarlar/sunucu-test/', views.test_upstreams_ajax, name='test_upstreams'),
    path('ayarlar/yedek/', views.backup_export, name='backup_export'),
    path('kullanicilar/', views.users, name='users'),
    path('giris/', views.login_view, name='login'),
    path('kurulum/', views.setup, name='setup'),
    path('cikis/', views.logout_view, name='logout'),
]
