"""Explicit additive upgrade. Historical case rows, signatures and keys are not rewritten."""
from .domain import require
from .governance import AUDIT_SCHEMA


def migrate(data_dir):
    from .store import Store
    from .evidence import check_database
    store = Store(data_dir, allow_legacy=True)
    before = check_database(store)
    with store.transaction() as c:
        version = c.execute("SELECT value FROM meta WHERE name='schema'").fetchone()[0]
        require(version in {"1", "2"}, "Unsupported migration source")
        if version == "1":
            for statement in AUDIT_SCHEMA:
                c.execute(statement)
            c.execute("UPDATE meta SET value='2' WHERE name='schema'")
            store._admin_event(c, "local-migration", "schema_migrated", {"from": 1, "to": 2})
    result = Store(data_dir)
    after = check_database(result)
    require(before["heads"] == after["heads"], "Migration changed case ledger heads")
    return {"schema": 2, "changed": version == "1", "cases_verified": len(after["heads"]), "heads": after["heads"]}
