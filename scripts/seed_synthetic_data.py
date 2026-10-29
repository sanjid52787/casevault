"""
CaseVault Synthetic Data Seeding Script
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)

HARD RULE COMPLIANCE:
Only synthetic, fictitious data and inert evidence files.
No real client information, no malware, no dangerous payloads.
"""

import os
import sys
from pathlib import Path

import django

# Setup Django standalone environment
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'casevault_core.settings')
django.setup()

import uuid

from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile

from accounts.models import CustomUser, UserRole
from audit.models import AuditAction
from audit.service import log_security_event
from cases.models import Case, CaseClassification, CaseMembership, CaseNote, CaseStatus
from vault.crypto import encrypt_and_store_evidence
from vault.models import EvidenceItem
from vault.validators import validate_inert_evidence_file


def create_sample_png() -> bytes:
    """Generates a harmless 1x1 inert PNG directly using standard binary headers."""
    # Standard valid 1x1 RGBA PNG
    return (
        b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06'
        b'\x00\x00\x00\x1f\x15c4\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff?\x03\x05\x01\x02'
        b'\xfe\xa7\xbf\x16\x00\x00\x00\x00IEND\xaeB`\x82'
    )


def create_sample_pdf() -> bytes:
    """Generates a harmless inert PDF with valid %PDF- header."""
    return (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n"
        b"3 0 obj<</Type/Page/MediaBox[0 0 300 144]/Parent 2 0 R/Resources<<>>>>endobj\n"
        b"xref\n0 4\n0000000000 65535 f\n0000000010 00000 n\n0000000053 00000 n\n0000000102 00000 n\n"
        b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF\n"
    )


def seed():
    print("Seeding CaseVault synthetic environment...")

    # 1. Create synthetic users (Passwords comply with min 12 chars: 'SecurePassw0rd!')
    DEFAULT_PASS = 'SecurePassw0rd!'

    admin_user, _ = CustomUser.objects.get_or_create(
        username='admin',
        defaults={
            'email': 'admin@northbridge-cyber.local',
            'role': UserRole.ADMIN,
            'organization': 'Northbridge Cyber Response',
            'is_staff': True,
            'is_superuser': True,
        }
    )
    admin_user.set_password(DEFAULT_PASS)
    admin_user.is_mfa_enabled = False
    admin_user.save()

    alice, _ = CustomUser.objects.get_or_create(
        username='alice_lead',
        defaults={
            'email': 'alice@northbridge-cyber.local',
            'role': UserRole.LEAD_INVESTIGATOR,
            'organization': 'Northbridge Cyber Response',
            'is_staff': True,
        }
    )
    alice.set_password(DEFAULT_PASS)
    alice.is_mfa_enabled = False
    alice.save()

    bob, _ = CustomUser.objects.get_or_create(
        username='bob_investigator',
        defaults={
            'email': 'bob@northbridge-cyber.local',
            'role': UserRole.INVESTIGATOR,
            'organization': 'Northbridge Cyber Response',
        }
    )
    bob.set_password(DEFAULT_PASS)
    bob.is_mfa_enabled = False
    bob.save()

    carol, _ = CustomUser.objects.get_or_create(
        username='carol_auditor',
        defaults={
            'email': 'carol@apexfinancial.local',
            'role': UserRole.CLIENT_AUDITOR,
            'organization': 'Apex Financial Corp',
        }
    )
    carol.set_password(DEFAULT_PASS)
    carol.is_mfa_enabled = False
    carol.save()

    dave, _ = CustomUser.objects.get_or_create(
        username='dave_auditor',
        defaults={
            'email': 'dave@medshield.local',
            'role': UserRole.CLIENT_AUDITOR,
            'organization': 'MedShield Health',
        }
    )
    dave.set_password(DEFAULT_PASS)
    dave.is_mfa_enabled = False
    dave.save()

    print("Users created: admin, alice_lead, bob_investigator, carol_auditor (Apex), dave_auditor (MedShield)")

    # 2. Create Cases
    case1, _ = Case.objects.get_or_create(
        case_number='NCR-2026-001',
        defaults={
            'title': 'Ransomware Perimeter Breach Assessment',
            'description': (
                'Synthetic scenario: Perimeter firewall anomaly detected on external bastion host. '
                'Lead investigator Alice and investigator Bob deployed for forensic triage.'
            ),
            'client_organization': 'Apex Financial Corp',
            'classification': CaseClassification.RESTRICTED,
            'status': CaseStatus.ACTIVE,
            'lead_investigator': alice,
        }
    )

    CaseMembership.objects.get_or_create(case=case1, user=bob, defaults={'role_in_case': 'INVESTIGATOR'})

    case2, _ = Case.objects.get_or_create(
        case_number='NCR-2026-002',
        defaults={
            'title': 'EHR Database Query Anomaly Investigation',
            'description': (
                'Synthetic scenario: Database query volume spike detected out-of-hours. '
                'Investigating simulated SQL logs for data exfiltration indicators.'
            ),
            'client_organization': 'MedShield Health',
            'classification': CaseClassification.CRITICAL_INFRASTRUCTURE,
            'status': CaseStatus.CONTAINED,
            'lead_investigator': alice,
        }
    )

    print("Cases created: NCR-2026-001 (Apex Financial), NCR-2026-002 (MedShield Health)")

    # 3. Add Investigative Notes
    CaseNote.objects.get_or_create(
        case=case1,
        author=alice,
        note='Initial ingress vector identified via compromised VPN gateway token. Endpoint isolated at 03:15 UTC.',
        defaults={'is_client_visible': True}
    )

    CaseNote.objects.get_or_create(
        case=case1,
        author=bob,
        note='Extracted memory dump from host BASTION-01. Reviewing process injection artifacts.',
        defaults={'is_client_visible': False}
    )

    CaseNote.objects.get_or_create(
        case=case2,
        author=alice,
        note='Synthetic database query audit verified: 12 internal records queried; no bulk export detected.',
        defaults={'is_client_visible': True}
    )

    # 4. Ingest Harmless Synthetic Evidence
    def ingest_synthetic_evidence(case, user, filename, content_bytes, description):
        upload = SimpleUploadedFile(filename, content_bytes)
        sanitized_name, mime_type = validate_inert_evidence_file(upload)
        storage_filename = f"{uuid.uuid4().hex}.enc"
        dest_path = settings.EVIDENCE_STORAGE_PATH / storage_filename
        sha256, sha512, byte_size = encrypt_and_store_evidence(upload, dest_path)

        item = EvidenceItem.objects.create(
            case=case,
            uploaded_by=user,
            original_filename=sanitized_name,
            storage_filename=storage_filename,
            file_size_bytes=byte_size,
            mime_type=mime_type,
            sha256_hash=sha256,
            sha512_hash=sha512,
            description=description,
        )
        log_security_event(
            action=AuditAction.EVIDENCE_UPLOADED,
            actor=user,
            target_model='EvidenceItem',
            target_id=str(item.id),
            details={'case_number': case.case_number, 'filename': item.original_filename, 'sha256': sha256}
        )
        return item

    # Evidence for Case 1
    log_sample = (
        b"2026-10-30T01:00:12Z BASTION-01 sshd[4912]: Accepted publickey for ir_analyst from 192.168.1.50\n"
        b"2026-10-30T01:02:44Z BASTION-01 sudo: pam_unix(sudo:session): session opened for user root\n"
        b"2026-10-30T01:05:10Z BASTION-01 kernel: [ 4102.12] nftables: SYN scan drop from 10.0.0.99\n"
    )
    ingest_synthetic_evidence(case1, bob, 'firewall_bastion.log', log_sample, 'Simulated firewall and syslog journal')

    png_sample = create_sample_png()
    ingest_synthetic_evidence(case1, bob, 'network_topology.png', png_sample, 'Synthetic network segmentation diagram')

    # Evidence for Case 2
    pdf_sample = create_sample_pdf()
    ingest_synthetic_evidence(case2, alice, 'interim_status_report.pdf', pdf_sample, 'Synthetic preliminary audit briefing')

    print("Synthetic evidence artifacts encrypted and stored.")
    print("Seed complete. All users have password: 'SecurePassw0rd!'")


if __name__ == '__main__':
    seed()
