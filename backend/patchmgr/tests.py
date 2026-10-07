from datetime import datetime, timedelta, timezone
from io import StringIO
from types import SimpleNamespace
from unittest import mock
from urllib.error import HTTPError

from django.conf import settings
from django.core.management import call_command
from packaging.version import Version
from rest_framework.test import APITestCase

from config.celery import app as celery_app

from . import nvd, services, tasks, versions
from .models import (
    CVE,
    AffectedSoftware,
    SoftwareCpe,
    Endpoint,
    EndpointGroup,
    InstalledSoftware,
    Patch,
    PatchStatus,
    Software,
)


class ApiTestBase(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.test_group = EndpointGroup.objects.create(name='테스트')
        cls.general_group = EndpointGroup.objects.create(name='일반')
        cls.pc1 = Endpoint.objects.create(
            hostname='pc-001', os_name='Windows 10 22H2', os_build='10.0.19045.5011', group=cls.test_group,
        )
        cls.pc2 = Endpoint.objects.create(
            hostname='pc-002', os_name='Windows 11 23H2', os_build='10.0.22631.4317', group=cls.general_group,
        )
        cls.software = Software.objects.create(name='Apache Log4j', vendor='Apache')
        InstalledSoftware.objects.create(endpoint=cls.pc1, software=cls.software, version='2.14.0')
        cls.cve = CVE.objects.create(cve_id='CVE-2024-43572', cvss_score='7.8', severity='high')
        cls.patch = Patch.objects.create(kb_number='KB5044273', target_os='Windows 10 22H2')
        cls.patch.cves.add(cls.cve)
        PatchStatus.objects.create(endpoint=cls.pc1, patch=cls.patch, status='applied')
        PatchStatus.objects.create(endpoint=cls.pc2, patch=cls.patch, status='error')


class EndpointApiTests(ApiTestBase):
    def test_list_filters_by_group(self):
        response = self.client.get('/api/endpoints/', {'group': self.test_group.id})
        self.assertEqual(response.status_code, 200)
        self.assertEqual([row['hostname'] for row in response.json()['results']], ['pc-001'])

    def test_list_filters_by_patch_status(self):
        response = self.client.get('/api/endpoints/', {'status': 'error'})
        self.assertEqual([row['hostname'] for row in response.json()['results']], ['pc-002'])

    def test_detail_includes_software_and_patch_status(self):
        response = self.client.get(f'/api/endpoints/{self.pc1.id}/')
        body = response.json()
        self.assertEqual(body['installed_software'][0]['name'], 'Apache Log4j')
        self.assertEqual(body['patch_statuses'][0]['kb_number'], 'KB5044273')


class EndpointListTests(ApiTestBase):
    def _hostnames(self, **params):
        body = self.client.get('/api/endpoints/', params).json()
        return [row['hostname'] for row in body['results']]

    def test_search_by_hostname_ignores_case_and_matches_part(self):
        self.assertEqual(self._hostnames(search='PC-00'), ['pc-001', 'pc-002'])
        self.assertEqual(self._hostnames(search='002'), ['pc-002'])
        self.assertEqual(self._hostnames(search='  PC-002 '), ['pc-002'])  # 앞뒤 공백은 무시
        self.assertEqual(self._hostnames(search='nothing'), [])

    def test_search_combines_with_group_and_status_filters(self):
        self.assertEqual(self._hostnames(search='pc', group=self.general_group.id), ['pc-002'])
        self.assertEqual(self._hostnames(search='pc-001', status='error'), [])
        self.assertEqual(self._hostnames(search='pc', status='error'), ['pc-002'])

    def test_each_row_has_unapplied_error_and_vulnerable_counts(self):
        cve = CVE.objects.create(cve_id='CVE-2021-44228', cvss_score='10.0', severity='critical')
        AffectedSoftware.objects.create(cve=cve, software=self.software, version_end_excluding='2.15.0')
        rows = {row['hostname']: row for row in self.client.get('/api/endpoints/').json()['results']}
        # pc-001: KB 적용됨, 설치된 Log4j 2.14.0이 범위(2.15.0 미만)에 들어감
        self.assertEqual(
            (rows['pc-001']['unapplied_patch_count'], rows['pc-001']['error_patch_count'], rows['pc-001']['vulnerable_cve_count']),
            (0, 0, 1),
        )
        # pc-002: KB가 오류 상태라 미적용으로도 세고, 설치된 소프트웨어는 없음
        self.assertEqual(
            (rows['pc-002']['unapplied_patch_count'], rows['pc-002']['error_patch_count'], rows['pc-002']['vulnerable_cve_count']),
            (1, 1, 0),
        )

    def test_counts_are_zero_when_nothing_is_reported(self):
        PatchStatus.objects.all().delete()
        rows = self.client.get('/api/endpoints/').json()['results']
        self.assertTrue(all(row['unapplied_patch_count'] == 0 and row['vulnerable_cve_count'] == 0 for row in rows))


class CveAndPatchApiTests(ApiTestBase):
    def test_cve_detail_lists_fixing_patches(self):
        response = self.client.get(f'/api/cves/{self.cve.id}/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['patches'][0]['kb_number'], 'KB5044273')

    def test_patch_detail_lists_cves(self):
        response = self.client.get(f'/api/patches/{self.patch.id}/')
        self.assertEqual(response.json()['cves'][0]['cve_id'], 'CVE-2024-43572')


class PolicyApiTests(ApiTestBase):
    def _payload(self, **extra):
        payload = {
            'name': '높음 이상 단계 배포',
            'min_severity': 'high',
            'stages': [
                {'order': 1, 'group': self.test_group.id, 'delay_minutes': 0, 'rollback_error_rate': 0.1},
                {'order': 2, 'group': self.general_group.id, 'delay_minutes': 60, 'rollback_error_rate': 0.05},
            ],
        }
        payload.update(extra)
        return payload

    def test_create_policy_with_stages(self):
        response = self.client.post('/api/policies/', self._payload(), format='json')
        self.assertEqual(response.status_code, 201)
        self.assertEqual([stage['order'] for stage in response.json()['stages']], [1, 2])

    def test_duplicate_stage_order_is_rejected(self):
        payload = self._payload()
        payload['stages'][1]['order'] = 1
        response = self.client.post('/api/policies/', payload, format='json')
        self.assertEqual(response.status_code, 400)

    def test_update_replaces_stages(self):
        created = self.client.post('/api/policies/', self._payload(), format='json').json()
        payload = self._payload(stages=[
            {'order': 1, 'group': self.general_group.id, 'delay_minutes': 0, 'rollback_error_rate': 0.2},
        ])
        response = self.client.put(f"/api/policies/{created['id']}/", payload, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()['stages']), 1)

    def test_delete_policy(self):
        created = self.client.post('/api/policies/', self._payload(), format='json').json()
        response = self.client.delete(f"/api/policies/{created['id']}/")
        self.assertEqual(response.status_code, 204)


class SeedDemoTests(APITestCase):
    def _counts(self):
        return (
            EndpointGroup.objects.count(),
            Software.objects.count(),
            Endpoint.objects.count(),
            InstalledSoftware.objects.count(),
        )

    def test_seed_creates_expected_counts(self):
        call_command('seed_demo', stdout=StringIO())
        groups, software, endpoints, _ = self._counts()
        self.assertEqual((groups, software, endpoints), (3, 20, 50))
        self.assertEqual(Endpoint.objects.filter(group__name='테스트').count(), 5)

    def test_seed_is_repeatable(self):
        call_command('seed_demo', stdout=StringIO())
        first = self._counts()
        call_command('seed_demo', stdout=StringIO())
        self.assertEqual(self._counts(), first)


class SeedSamplePatchesTests(APITestCase):
    def test_creates_cve_with_four_patches_and_is_repeatable(self):
        call_command('seed_sample_patches', stdout=StringIO())
        call_command('seed_sample_patches', stdout=StringIO())
        self.assertEqual(CVE.objects.count(), 1)
        self.assertEqual(Patch.objects.count(), 4)
        cve = CVE.objects.get(cve_id='CVE-2024-43572')
        self.assertEqual(cve.patches.count(), 4)
        self.assertEqual(str(cve.cvss_score), '7.8')


class AgentReportApiTests(ApiTestBase):
    """보고 API. 테스트에서는 Celery 작업을 큐를 거치지 않고 바로 실행한다(eager)."""

    def setUp(self):
        celery_app.conf.task_always_eager = True
        self.addCleanup(setattr, celery_app.conf, 'task_always_eager', False)

    def _report(self, **extra):
        payload = {
            'hostname': 'pc-001',
            'os_name': 'Windows 10 22H2',
            'os_build': '10.0.19045.5011',
            'installed_software': [{'name': 'Google Chrome', 'vendor': 'Google', 'version': '130.0'}],
            'installed_kbs': ['KB5044273'],
            'errors': [],
        }
        payload.update(extra)
        return self.client.post('/api/agents/report/', payload, format='json')

    def test_report_is_accepted_and_applied(self):
        PatchStatus.objects.filter(endpoint=self.pc1).update(status='pending')
        response = self._report()
        self.assertEqual(response.status_code, 202)
        self.assertEqual(PatchStatus.objects.get(endpoint=self.pc1, patch=self.patch).status, 'applied')
        self.pc1.refresh_from_db()
        self.assertEqual(self.pc1.os_build, '10.0.19045.5011')
        self.assertIsNotNone(self.pc1.last_reported_at)

    def test_installed_software_is_replaced_by_the_report(self):
        self._report()
        names = list(self.pc1.installed_software.values_list('software__name', flat=True))
        self.assertEqual(names, ['Google Chrome'])  # 기존 Apache Log4j는 보고에 없으므로 지워진다

    def test_error_report_marks_patch_and_clears_when_resolved(self):
        PatchStatus.objects.filter(endpoint=self.pc2).delete()  # 기본 데이터의 다른 PC 오류를 치운다
        self._report(installed_kbs=[], errors=[{'kb_number': 'KB5044273', 'error_code': '0x80070643'}])
        status = PatchStatus.objects.get(endpoint=self.pc1, patch=self.patch)
        self.assertEqual((status.status, status.error_code), ('error', '0x80070643'))
        self.patch.refresh_from_db()
        self.assertTrue(self.patch.is_error_reported)

        self._report()  # 다음 보고에서 설치에 성공
        self.patch.refresh_from_db()
        self.assertFalse(self.patch.is_error_reported)

    def test_rolled_back_status_is_kept_when_not_installed(self):
        PatchStatus.objects.filter(endpoint=self.pc1).update(status='rolled_back')
        self._report(installed_kbs=[])
        self.assertEqual(PatchStatus.objects.get(endpoint=self.pc1, patch=self.patch).status, 'rolled_back')

    def test_patches_for_other_os_are_ignored(self):
        before = PatchStatus.objects.filter(endpoint=self.pc2).count()
        self._report(hostname='pc-002', os_name='Windows 11 23H2', installed_kbs=['KB5044273'])
        self.assertEqual(PatchStatus.objects.filter(endpoint=self.pc2, patch=self.patch).count(), before)

    def test_unknown_hostname_is_rejected(self):
        self.assertEqual(self._report(hostname='no-such-pc').status_code, 404)

    def test_invalid_payload_is_rejected(self):
        response = self.client.post('/api/agents/report/', {'os_name': 'Windows 10 22H2'}, format='json')
        self.assertEqual(response.status_code, 400)


class DashboardSummaryTests(ApiTestBase):
    def test_summary_counts_and_rate(self):
        body = self.client.get('/api/dashboard/summary/').json()
        self.assertEqual(body['total'], 2)
        self.assertEqual(body['status_counts']['applied'], 1)
        self.assertEqual(body['status_counts']['error'], 1)
        self.assertEqual(body['patch_rate'], 0.5)

    def test_rate_is_null_without_data(self):
        PatchStatus.objects.all().delete()
        self.assertIsNone(self.client.get('/api/dashboard/summary/').json()['patch_rate'])


def nvd_item(cve_id='CVE-2024-43572', metrics=None, published='2024-10-08T00:00:00.000', description='desc'):
    """NVD 응답의 vulnerabilities 항목 하나와 같은 모양의 시험용 데이터"""
    cve = {
        'id': cve_id,
        'published': published,
        'descriptions': [{'lang': 'es', 'value': 'descripcion'}, {'lang': 'en', 'value': description}],
        'metrics': metrics or {},
    }
    return {'cve': cve}


def metric(score, severity, source='nvd@nist.gov', kind='Primary'):
    return {'source': source, 'type': kind, 'cvssData': {'baseScore': score, 'baseSeverity': severity}}


class NvdParseTests(APITestCase):
    def test_uses_english_description_and_primary_v31_score(self):
        item = nvd_item(metrics={'cvssMetricV31': [
            metric(5.0, 'MEDIUM', source='vendor@example.com', kind='Secondary'),
            metric(7.8, 'HIGH'),
        ]})
        parsed = nvd.parse_cve(item)
        self.assertEqual(parsed['description'], 'desc')
        self.assertEqual((parsed['cvss_score'], parsed['severity']), (7.8, 'high'))
        self.assertEqual(parsed['published_at'].isoformat(), '2024-10-08T00:00:00+00:00')

    def test_falls_back_to_v40_when_there_is_no_v31(self):
        parsed = nvd.parse_cve(nvd_item(metrics={'cvssMetricV40': [metric(9.3, 'CRITICAL')]}))
        self.assertEqual((parsed['cvss_score'], parsed['severity']), (9.3, 'critical'))

    def test_cve_without_score_is_kept_with_blank_severity(self):
        parsed = nvd.parse_cve(nvd_item())
        self.assertEqual((parsed['cvss_score'], parsed['severity']), (None, ''))

    def test_unknown_severity_name_becomes_blank(self):
        parsed = nvd.parse_cve(nvd_item(metrics={'cvssMetricV31': [metric(0.0, 'NONE')]}))
        self.assertEqual(parsed['severity'], '')


class NvdSaveAndCollectTests(APITestCase):
    def test_save_creates_then_updates(self):
        first = nvd.save_cves([nvd.parse_cve(nvd_item(description='old'))])
        second = nvd.save_cves([nvd.parse_cve(nvd_item(description='new'))])
        self.assertEqual((first, second), ((1, 0), (0, 1)))
        self.assertEqual(CVE.objects.get(cve_id='CVE-2024-43572').description, 'new')

    def test_collect_recent_saves_and_skips_broken_items(self):
        items = [nvd_item('CVE-2026-0001'), {'cve': {'published': 'x'}}, nvd_item('CVE-2026-0002')]
        with mock.patch('patchmgr.nvd.fetch_modified_since', return_value=iter(items)):
            result = nvd.collect_recent(hours=12)
        self.assertEqual(result, {'created': 2, 'updated': 0, 'skipped': 1, 'affected': 0})

    def test_fetch_follows_pages_until_total_is_reached(self):
        pages = [
            {'totalResults': 3, 'resultsPerPage': 2, 'vulnerabilities': [nvd_item('CVE-2026-0001'), nvd_item('CVE-2026-0002')]},
            {'totalResults': 3, 'resultsPerPage': 1, 'vulnerabilities': [nvd_item('CVE-2026-0003')]},
        ]
        urls = []

        def fake_get(url, api_key):
            urls.append(url)
            return pages[len(urls) - 1]

        now = datetime(2026, 10, 2, tzinfo=timezone.utc)
        with mock.patch('patchmgr.nvd._get', side_effect=fake_get), mock.patch('patchmgr.nvd.time.sleep'):
            got = list(nvd.fetch_modified_since(now - timedelta(hours=1), now, api_key=None))
        self.assertEqual(len(got), 3)
        self.assertIn('startIndex=0', urls[0])
        self.assertIn('startIndex=2', urls[1])

    def test_error_message_never_contains_the_api_key(self):
        failure = HTTPError('http://x', 403, 'forbidden', {}, None)
        with mock.patch('patchmgr.nvd.request.urlopen', side_effect=failure), \
                mock.patch('patchmgr.nvd.time.sleep'):
            with self.assertRaises(nvd.NvdError) as caught:
                nvd._get('http://x', 'SECRET-KEY-VALUE')
        self.assertNotIn('SECRET-KEY-VALUE', str(caught.exception))
        self.assertIn('403', str(caught.exception))

    def test_beat_schedule_runs_the_fetch_task(self):
        entry = settings.CELERY_BEAT_SCHEDULE['fetch-recent-cves']
        self.assertEqual(entry['task'], 'patchmgr.tasks.fetch_recent_cves')
        self.assertEqual(entry['task'], tasks.fetch_recent_cves.name)

    def test_task_returns_counts(self):
        with mock.patch('patchmgr.nvd.fetch_modified_since', return_value=iter([nvd_item('CVE-2026-0009')])):
            result = tasks.fetch_recent_cves(hours=12)
        self.assertEqual(result, {'created': 1, 'updated': 0, 'skipped': 0, 'affected': 0})


def with_config(item, *matches):
    """nvd_item에 영향 소프트웨어(CPE) 조건을 붙인다."""
    item['cve']['configurations'] = [{'nodes': [{'operator': 'OR', 'negate': False, 'cpeMatch': list(matches)}]}]
    return item


def cpe(criteria, vulnerable=True, **bounds):
    return {'vulnerable': vulnerable, 'criteria': criteria, 'matchCriteriaId': 'X', **bounds}


class NvdAffectedTests(APITestCase):
    def test_parse_affected_reads_ranges_and_unescapes_names(self):
        item = with_config(
            nvd_item(),
            cpe('cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:*:*:*:*:*:*:*:*', versionEndExcluding='8.6.5'),
            cpe('cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*', versionStartIncluding='100.0', versionEndIncluding='120.0'),
            cpe('cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*'),
            cpe('cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*', vulnerable=False),  # 조건일 뿐이라 제외
            cpe('cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*'),  # 운영체제라 제외
        )
        found = nvd.parse_affected(item)
        self.assertEqual(len(found), 3)
        notepad, chrome, log4j = found
        self.assertEqual((notepad['vendor'], notepad['product'], notepad['version_end_excluding']),
                         ('notepad-plus-plus', 'notepad++', '8.6.5'))
        self.assertEqual((chrome['version_start_including'], chrome['version_end_including']), ('100.0', '120.0'))
        self.assertEqual((log4j['version_exact'], log4j['version_end_excluding']), ('2.0', ''))

    def test_parse_affected_removes_duplicates_and_handles_missing_configuration(self):
        same = cpe('cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*', versionEndExcluding='1.0')
        self.assertEqual(len(nvd.parse_affected(with_config(nvd_item(), same, dict(same)))), 1)
        self.assertEqual(nvd.parse_affected(nvd_item()), [])

    def _software(self):
        adobe = Software.objects.create(name='Adobe Acrobat Reader', vendor='Adobe')
        SoftwareCpe.objects.create(software=adobe, vendor='adobe', product='acrobat_reader')
        SoftwareCpe.objects.create(software=adobe, vendor='adobe', product='acrobat_reader_dc')
        return adobe

    def test_only_mapped_software_is_saved_and_duplicates_are_merged(self):
        adobe = self._software()
        item = with_config(
            nvd_item('CVE-2024-41869'),
            cpe('cpe:2.3:a:adobe:acrobat_reader:*:*:*:*:*:*:*:*', versionEndExcluding='24.001'),
            cpe('cpe:2.3:a:adobe:acrobat_reader_dc:*:*:*:*:*:*:*:*', versionEndExcluding='24.001'),
            cpe('cpe:2.3:a:unknown_vendor:unknown_product:*:*:*:*:*:*:*:*'),  # 우리 소프트웨어에 없음
        )
        with mock.patch('patchmgr.nvd.fetch_by_ids', return_value=iter([item])):
            result = nvd.collect_ids(['CVE-2024-41869'])
        self.assertEqual(result['affected'], 1)
        row = AffectedSoftware.objects.get()
        self.assertEqual((row.software, row.version_end_excluding), (adobe, '24.001'))

    def test_rerun_replaces_the_previous_rows_of_the_cve(self):
        self._software()
        first = with_config(nvd_item('CVE-2024-41869'),
                            cpe('cpe:2.3:a:adobe:acrobat_reader:*:*:*:*:*:*:*:*', versionEndExcluding='24.001'))
        second = with_config(nvd_item('CVE-2024-41869'),
                             cpe('cpe:2.3:a:adobe:acrobat_reader:*:*:*:*:*:*:*:*', versionEndExcluding='24.002'))
        for item in (first, second):
            with mock.patch('patchmgr.nvd.fetch_by_ids', return_value=iter([item])):
                nvd.collect_ids(['CVE-2024-41869'])
        self.assertEqual(list(AffectedSoftware.objects.values_list('version_end_excluding', flat=True)), ['24.002'])

    def test_cve_detail_api_shows_affected_software_with_ranges(self):
        self._software()
        item = with_config(nvd_item('CVE-2024-41869'),
                           cpe('cpe:2.3:a:adobe:acrobat_reader:*:*:*:*:*:*:*:*', versionEndExcluding='24.001'))
        with mock.patch('patchmgr.nvd.fetch_by_ids', return_value=iter([item])):
            nvd.collect_ids(['CVE-2024-41869'])
        cve = CVE.objects.get(cve_id='CVE-2024-41869')
        body = self.client.get(f'/api/cves/{cve.id}/').json()
        self.assertEqual(body['affected_software'][0]['name'], 'Adobe Acrobat Reader')
        self.assertEqual(body['affected_software'][0]['version_end_excluding'], '24.001')


class SeedCpeMappingsTests(APITestCase):
    def test_maps_multiple_names_skips_missing_and_is_repeatable(self):
        adobe = Software.objects.create(name='Adobe Acrobat Reader', vendor='Adobe')
        notepad = Software.objects.create(name='Notepad++', vendor='Notepad++ Team')
        Software.objects.create(name='Slack', vendor='Slack')
        for _ in range(2):
            call_command('seed_cpe_mappings', stdout=StringIO())
        self.assertEqual(adobe.cpes.count(), 2)
        self.assertEqual(sorted(notepad.cpes.values_list('vendor', flat=True)),
                         ['don_ho', 'notepad-plus-plus', 'notepad_plus_plus'])
        self.assertEqual(SoftwareCpe.objects.filter(software__name='Slack').count(), 0)  # 매핑 없음으로 둔다

    def test_seed_demo_also_creates_mappings(self):
        call_command('seed_demo', stdout=StringIO())
        self.assertEqual(Software.objects.get(name='Google Chrome').cpes.get().product, 'chrome')


def bounds(**kwargs):
    """AffectedSoftware 한 줄과 같은 칸을 가진 시험용 값 (안 준 칸은 빈 문자열)"""
    fields = ['version_start_including', 'version_start_excluding', 'version_end_including',
              'version_end_excluding', 'version_exact']
    return SimpleNamespace(**{name: kwargs.get(name, '') for name in fields})


class VersionCompareTests(APITestCase):
    def test_parse_version_formats(self):
        self.assertEqual(versions.parse_version('8u421'), Version('8.0.421'))  # Java식
        self.assertEqual(versions.parse_version('v1.2'), Version('1.2'))
        self.assertEqual(versions.parse_version(' 128.0.6613.84 '), Version('128.0.6613.84'))
        for unreadable in ('', None, 'abc', '1.x.y z'):
            self.assertIsNone(versions.parse_version(unreadable))

    def test_versions_are_compared_as_numbers_not_text(self):
        self.assertTrue(versions.parse_version('9.0') < versions.parse_version('10.0'))
        self.assertTrue(versions.parse_version('2.0-beta9') < versions.parse_version('2.0'))  # 시험판이 먼저
        self.assertTrue(versions.parse_version('24.003.0') < versions.parse_version('24.003.20112'))

    def test_end_excluding(self):
        row = bounds(version_end_excluding='128.0.6613.84')
        self.assertIs(versions.is_affected('124.0', row), True)
        self.assertIs(versions.is_affected('128.0.6613.84', row), False)  # 미만이라 같은 버전은 제외
        self.assertIs(versions.is_affected('130.0', row), False)

    def test_end_including_and_start_bounds(self):
        row = bounds(version_start_including='2.13.0', version_end_including='2.15.0')
        self.assertIs(versions.is_affected('2.13.0', row), True)
        self.assertIs(versions.is_affected('2.15.0', row), True)  # 이하라 같은 버전도 포함
        self.assertIs(versions.is_affected('2.12.9', row), False)
        self.assertIs(versions.is_affected('2.15.1', row), False)
        excluding = bounds(version_start_excluding='2.13.0')
        self.assertIs(versions.is_affected('2.13.0', excluding), False)  # 초과라 같은 버전은 제외
        self.assertIs(versions.is_affected('2.13.1', excluding), True)

    def test_exact_version(self):
        row = bounds(version_exact='2.0')
        self.assertIs(versions.is_affected('2.0', row), True)
        self.assertIs(versions.is_affected('2.0.1', row), False)

    def test_no_bounds_means_every_version(self):
        self.assertIs(versions.is_affected('1.0', bounds()), True)
        self.assertIs(versions.is_affected('whatever', bounds()), True)  # 범위가 없으면 버전을 읽을 필요도 없다

    def test_unreadable_versions_are_unknown(self):
        self.assertIsNone(versions.is_affected('abc', bounds(version_end_excluding='1.0')))
        self.assertIsNone(versions.is_affected('1.0', bounds(version_end_excluding='abc')))

    def test_a_failed_readable_condition_wins_over_an_unreadable_one(self):
        row = bounds(version_start_including='5.0', version_end_excluding='abc')
        self.assertIs(versions.is_affected('1.0', row), False)  # 시작 조건에서 이미 어긋남


class SearchApiTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.log4j = CVE.objects.create(cve_id='CVE-2021-44228', cvss_score='10.0', severity='critical',
                                       description='Apache Log4j2 JNDI features do not protect against attacker controlled LDAP')
        cls.mmc = CVE.objects.create(cve_id='CVE-2024-43572', cvss_score='7.8', severity='high',
                                     description='Microsoft Management Console Remote Code Execution Vulnerability')
        cls.unscored = CVE.objects.create(cve_id='CVE-2026-0001', description='A new WordPress plugin issue')
        cls.win10 = Patch.objects.create(kb_number='KB5044273', target_os='Windows 10 22H2', fixed_build='10.0.19045.5011')
        cls.win11 = Patch.objects.create(kb_number='KB5044285', target_os='Windows 11 23H2')
        cls.win10.cves.add(cls.mmc)
        cls.win11.cves.add(cls.mmc)

    def _search(self, q):
        response = self.client.get('/api/search/', {'q': q})
        return response, response.json()

    def test_finds_cve_by_number_ignoring_case(self):
        _, body = self._search('cve-2021-44228')
        self.assertEqual([c['cve_id'] for c in body['cves']], ['CVE-2021-44228'])
        self.assertEqual(body['patches'], [])

    def test_finds_cve_by_description_and_orders_by_score(self):
        _, body = self._search('vulnerability')
        self.assertEqual([c['cve_id'] for c in body['cves']], ['CVE-2024-43572'])
        _, body = self._search('CVE-202')
        self.assertEqual([c['cve_id'] for c in body['cves']],
                         ['CVE-2021-44228', 'CVE-2024-43572', 'CVE-2026-0001'])  # 점수 높은 순, 점수 없는 CVE는 마지막

    def test_finds_patch_by_kb_with_or_without_prefix(self):
        for q in ('KB5044273', 'kb5044273', '5044273'):
            _, body = self._search(q)
            self.assertEqual([p['kb_number'] for p in body['patches']], ['KB5044273'], q)
        _, body = self._search('KB50442')
        self.assertEqual(sorted(p['kb_number'] for p in body['patches']), ['KB5044273', 'KB5044285'])

    def test_cve_number_also_returns_the_patches_that_fix_it(self):
        _, body = self._search('CVE-2024-43572')
        self.assertEqual(sorted(p['kb_number'] for p in body['patches']), ['KB5044273', 'KB5044285'])
        self.assertEqual(body['patches'][0]['cve_count'], 1)

    def test_description_is_cut_to_200_characters(self):
        CVE.objects.create(cve_id='CVE-2026-0002', description='x' * 500)
        _, body = self._search('CVE-2026-0002')
        self.assertEqual(len(body['cves'][0]['description']), 200)

    def test_missing_or_too_short_query_is_rejected(self):
        for params in ({}, {'q': ''}, {'q': ' a '}):
            self.assertEqual(self.client.get('/api/search/', params).status_code, 400, params)

    def test_no_match_returns_empty_lists(self):
        response, body = self._search('no-such-thing')
        self.assertEqual((response.status_code, body), (200, {'cves': [], 'patches': []}))


class VulnerabilityAssessmentTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        group = EndpointGroup.objects.create(name='일반')
        cls.chrome = Software.objects.create(name='Google Chrome', vendor='Google')
        cls.log4j = Software.objects.create(name='Apache Log4j', vendor='Apache')

        def pc(name, chrome=None, log4j=None):
            endpoint = Endpoint.objects.create(hostname=name, os_name='Windows 10 22H2', os_build='1', group=group)
            if chrome:
                InstalledSoftware.objects.create(endpoint=endpoint, software=cls.chrome, version=chrome)
            if log4j:
                InstalledSoftware.objects.create(endpoint=endpoint, software=cls.log4j, version=log4j)
            return endpoint

        cls.old = pc('pc-old', chrome='124.0', log4j='2.14.0')
        cls.new = pc('pc-new', chrome='130.0', log4j='2.17.1')
        cls.broken = pc('pc-broken', chrome='unknown-build')

        chrome_cve = CVE.objects.create(cve_id='CVE-2024-7971', cvss_score='8.8', severity='high')
        AffectedSoftware.objects.create(cve=chrome_cve, software=cls.chrome, version_end_excluding='128.0.6613.84')
        log4j_cve = CVE.objects.create(cve_id='CVE-2021-44228', cvss_score='10.0', severity='critical')
        # 같은 CVE에 범위가 두 줄
        AffectedSoftware.objects.create(cve=log4j_cve, software=cls.log4j,
                                        version_start_including='2.4.0', version_end_excluding='2.12.2')
        AffectedSoftware.objects.create(cve=log4j_cve, software=cls.log4j,
                                        version_start_including='2.13.0', version_end_excluding='2.15.0')
        cls.unscored_cve = CVE.objects.create(cve_id='CVE-2026-0001')
        AffectedSoftware.objects.create(cve=cls.unscored_cve, software=cls.log4j)  # 모든 버전

    def _findings(self, endpoint):
        return {(f['cve_id'], f['status']) for f in services.assess_vulnerabilities(endpoint=endpoint)}

    def test_old_pc_is_vulnerable_new_pc_is_not(self):
        self.assertEqual(self._findings(self.old), {
            ('CVE-2024-7971', 'vulnerable'), ('CVE-2021-44228', 'vulnerable'), ('CVE-2026-0001', 'vulnerable'),
        })
        # 새 PC: Chrome 130과 Log4j 2.17.1은 범위 밖이라 CVE 둘은 없고, 모든 버전 해당인 CVE만 남는다
        self.assertEqual(self._findings(self.new), {('CVE-2026-0001', 'vulnerable')})

    def test_unreadable_version_is_unknown_not_vulnerable(self):
        self.assertEqual(self._findings(self.broken), {('CVE-2024-7971', 'unknown')})

    def test_endpoint_detail_lists_vulnerable_first(self):
        body = self.client.get(f'/api/endpoints/{self.old.id}/').json()
        self.assertEqual(len(body['vulnerabilities']), 3)
        self.assertTrue(all(v['status'] == 'vulnerable' for v in body['vulnerabilities']))
        chrome = next(v for v in body['vulnerabilities'] if v['cve_id'] == 'CVE-2024-7971')
        self.assertEqual((chrome['software'], chrome['installed_version'], chrome['severity']),
                         ('Google Chrome', '124.0', 'high'))
        broken = self.client.get(f'/api/endpoints/{self.broken.id}/').json()
        self.assertEqual(broken['vulnerabilities'][0]['status'], 'unknown')

    def test_dashboard_counts_endpoints_by_severity_and_unknown_separately(self):
        body = self.client.get('/api/dashboard/summary/').json()
        counts = body['software_vulnerable_endpoints_by_severity']
        self.assertEqual(counts, {'critical': 1, 'high': 1, 'medium': 0, 'low': 0, 'unscored': 2})
        self.assertEqual(body['unknown_assessments'], 1)
