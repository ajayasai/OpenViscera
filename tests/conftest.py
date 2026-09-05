import shutil

import pytest

from openviscera.demo import Driver
from openviscera.store import Store

PASSWORD = "synthetic-test-password-123"


@pytest.fixture(scope="session")
def template(tmp_path_factory):
    path = tmp_path_factory.mktemp("template") / "data"
    store = Store.initialize(path)
    lab = store.add_lab("org-a", {"name": "Synthetic Laboratory"})
    users = {}
    for role in ["admin", "examiner", "coordinator", "courier", "lab", "reviewer", "auditor"]:
        users[role] = store.add_user("org-a", {"username": role, "display_name": "Synthetic " + role,
                                             "role": role, "lab_id": lab["id"] if role == "lab" else None,
                                             "password": PASSWORD})
    users["other_examiner"] = store.add_user("org-a", {"username": "other_examiner", "display_name": "Other examiner",
                                                     "role": "examiner", "password": PASSWORD})
    users["outsider"] = store.add_user("org-b", {"username": "outsider", "display_name": "Different department",
                                               "role": "examiner", "password": PASSWORD})
    return path, users, lab


@pytest.fixture
def env(template, tmp_path):
    path, users, lab = template
    target = tmp_path / "data"
    shutil.copytree(path, target)
    store = Store(target)
    return store, users, lab, Driver(store, users, lab)
