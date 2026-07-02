"""Tests for the default roles seeded by initdb."""

import pytest
from sqlalchemy import text

from faraday.server.models import PermissionsUnitAction, User
from faraday.server.utils.permissions import (
    UNIT_ADMIN,
    UNIT_BASE,
    UNIT_PREFERENCES,
    UNIT_ROLES,
    UNIT_SETTINGS,
    UNIT_TOKENS,
    UNIT_USERS,
    UNIT_VULNERABILITIES,
    UNIT_WORKSPACES,
)
from faraday.utils.initdb import _exec_initdb

CREATE = PermissionsUnitAction.CREATE_ACTION
READ = PermissionsUnitAction.READ_ACTION
UPDATE = PermissionsUnitAction.UPDATE_ACTION
DELETE = PermissionsUnitAction.DELETE_ACTION
TAG = PermissionsUnitAction.TAG_ACTION

CRUD = [CREATE, READ, UPDATE, DELETE]


def _allowed(session, role_name, unit_name, action):
    return session.execute(
        text(
            "SELECT rp.allowed FROM role_permission rp "
            "JOIN faraday_role r ON rp.role_id = r.id "
            "JOIN permissions_unit_action pua ON rp.unit_action_id = pua.id "
            "JOIN permissions_unit pu ON pua.permissions_unit_id = pu.id "
            "WHERE r.name = :role AND pu.name = :unit AND pua.action_type = :action"
        ),
        {'role': role_name, 'unit': unit_name, 'action': action},
    ).scalar()


def test_workspace_admin_role_constant():
    assert User.WORKSPACE_ADMIN_ROLE == 'workspace_admin'
    assert User.WORKSPACE_ADMIN_ROLE in User.ROLES


class TestInitdbWorkspaceAdmin:

    @pytest.fixture(autouse=True)
    def seeded(self, session):
        session.execute(text('DELETE FROM role_permission'))
        session.execute(text('DELETE FROM notification_allowed_roles'))
        session.execute(text('DELETE FROM roles_users'))
        session.execute(text('DELETE FROM faraday_role'))
        _exec_initdb(lambda stmt: session.execute(text(stmt)))

    def test_seeded_as_default_role(self, session):
        row = session.execute(
            text("SELECT weight, custom, description FROM faraday_role WHERE name = :role"),
            {'role': User.WORKSPACE_ADMIN_ROLE},
        ).one()
        assert row.custom is False
        assert row.weight == 15
        assert row.description

    def test_all_default_roles_seeded(self, session):
        names = session.execute(
            text("SELECT name FROM faraday_role WHERE custom = false")
        ).scalars().all()
        assert set(names) == set(User.ROLES)

    def test_full_workspace_permissions(self, session):
        for action in CRUD:
            assert _allowed(session, User.WORKSPACE_ADMIN_ROLE, UNIT_WORKSPACES, action) is True
        assert _allowed(session, User.WORKSPACE_ADMIN_ROLE, UNIT_WORKSPACES, TAG) is False

    def test_cannot_manage_users(self, session):
        assert _allowed(session, User.WORKSPACE_ADMIN_ROLE, UNIT_USERS, READ) is True
        assert _allowed(session, User.WORKSPACE_ADMIN_ROLE, UNIT_USERS, UPDATE) is True
        assert _allowed(session, User.WORKSPACE_ADMIN_ROLE, UNIT_USERS, CREATE) is False
        assert _allowed(session, User.WORKSPACE_ADMIN_ROLE, UNIT_USERS, DELETE) is False

    def test_no_settings_access(self, session):
        for action in CRUD:
            assert _allowed(session, User.WORKSPACE_ADMIN_ROLE, UNIT_SETTINGS, action) is False

    def test_default_admin_group_profile(self, session):
        assert _allowed(session, User.WORKSPACE_ADMIN_ROLE, UNIT_ADMIN, READ) is True
        assert _allowed(session, User.WORKSPACE_ADMIN_ROLE, UNIT_ADMIN, UPDATE) is True
        assert _allowed(session, User.WORKSPACE_ADMIN_ROLE, UNIT_ADMIN, CREATE) is False
        assert _allowed(session, User.WORKSPACE_ADMIN_ROLE, UNIT_ADMIN, DELETE) is False
        assert _allowed(session, User.WORKSPACE_ADMIN_ROLE, UNIT_BASE, READ) is True
        assert _allowed(session, User.WORKSPACE_ADMIN_ROLE, UNIT_BASE, CREATE) is False
        for action in CRUD:
            assert _allowed(session, User.WORKSPACE_ADMIN_ROLE, UNIT_ROLES, action) is False

    def test_group_all_allowed(self, session):
        assert _allowed(session, User.WORKSPACE_ADMIN_ROLE, UNIT_PREFERENCES, READ) is True
        assert _allowed(session, User.WORKSPACE_ADMIN_ROLE, UNIT_TOKENS, READ) is True

    def test_no_rows_outside_admin_and_all_groups(self, session):
        assert _allowed(session, User.WORKSPACE_ADMIN_ROLE, UNIT_VULNERABILITIES, READ) is None
