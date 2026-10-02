from rest_framework.test import APITestCase

from .models import (
    CVE,
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
